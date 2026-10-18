use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::Write,
    os::unix::fs::MetadataExt,
    process::Command,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use uuid::Uuid;

// Load configuration from environment variables
fn load_config() -> Config {
    // Prova a caricare .env dalla directory corrente o da /opt/haproxy-manager/
    let env_paths = [".env", "/opt/haproxy-manager/.env"];

    for path in env_paths {
        if std::path::Path::new(path).exists() {
            std::env::set_current_dir(std::path::Path::new(path).parent().unwrap()).ok();
            dotenv::dotenv().ok();
            break;
        }
    }

    Config {
        domains_map: std::env::var("DOMAINS_MAP").unwrap_or_else(|_| "/etc/haproxy/maps/domains.map".to_string()),
        backends_map: std::env::var("BACKENDS_MAP").unwrap_or_else(|_| "/etc/haproxy/maps/backends.map".to_string()),
        haproxy_cfg: std::env::var("HAPROXY_CFG").unwrap_or_else(|_| "/etc/haproxy/haproxy.cfg".to_string()),
        log_file: std::env::var("LOG_FILE").unwrap_or_else(|_| "/var/log/haproxy-manager.log".to_string()),
        history_file: std::env::var("HISTORY_FILE").unwrap_or_else(|_| "/var/lib/haproxy-manager/history.jsonl".to_string()),
        listen_addr: std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string()),
        admin_user: std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
        admin_pass_hash: std::env::var("ADMIN_PASS_HASH").ok().filter(|s| !s.is_empty()),
        admin_pass: std::env::var("ADMIN_PASS").ok().filter(|s| !s.is_empty() && s != "CHANGE_ME"),
        ui_dir: std::env::var("UI_DIR").unwrap_or_else(|_| "/opt/haproxy-manager/ui".to_string()),
        helper: std::env::var("HELPER").unwrap_or_else(|_| "/usr/local/sbin/haproxy-manager-helper".to_string()),
    }
}

#[derive(Clone)]
struct Config {
    domains_map: String,
    backends_map: String,
    haproxy_cfg: String,
    log_file: String,
    history_file: String,
    listen_addr: String,
    admin_user: String,
    // Hash bcrypt (haproxy-manager hash-password); ADMIN_PASS in chiaro solo come ripiego
    admin_pass_hash: Option<String>,
    admin_pass: Option<String>,
    ui_dir: String,
    // Unico comando eseguito come root (via sudo): check/reload HAProxy, ban Varnish, certificati
    helper: String,
}

// ── Strutture ─────────────────────────────────────────────────────
// Backend che passa da Varnish: il server di origine è in backends.map
const VARNISH_BACKEND: &str = "varnish_backend";
// Stesso lock di /usr/local/sbin/haproxy-domain (script degli eventi Plesk)
const MAPS_LOCK: &str = "/run/lock/haproxy-maps.lock";
// Sessione: scade dopo 2 ore di inattività e comunque dopo 12 ore
const SESSION_IDLE: Duration = Duration::from_secs(2 * 3600);
const SESSION_MAX: Duration = Duration::from_secs(12 * 3600);
// Login: dopo 5 errori in 15 minuti, bloccato per 15 minuti
const LOGIN_MAX_FAILS: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
const LOGIN_BLOCK: Duration = Duration::from_secs(15 * 60);
// Elenco dei nomi nei certificati: riletto al massimo ogni minuto
const CERT_CACHE_TTL: Duration = Duration::from_secs(60);
const HISTORY_KEEP: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
struct Domain {
    name:    String,
    backend: String,
    // Server di origine (backends.map): uguale a backend se diretto
    #[serde(default)]
    origin:  Option<String>,
}

// Dominio come lo vede la UI: con l'indicazione del certificato
#[derive(Serialize)]
struct DomainView {
    #[serde(flatten)]
    domain: Domain,
    // false: nessun certificato in /etc/haproxy/certs copre il dominio (Cloudflare 526)
    cert:   Option<bool>,
}

#[derive(Deserialize)]
struct DomainRequest {
    name:    String,
    backend: String,
    #[serde(default)]
    origin:  Option<String>,
}

#[derive(Deserialize)]
struct BulkRequest {
    domains: Vec<String>,
    backend: String,
}

#[derive(Deserialize)]
struct CachePurgeRequest {
    domain: String,
}

#[derive(Deserialize)]
struct BackendRequest {
    // Nome del server (es. server7): il backend sarà server7_backend
    name: String,
    ip:   String,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    message: String,
    data:    Option<T>,
}

// ── Storico (history.jsonl, scritto anche da haproxy-domain) ─────
#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct MapEntry {
    backend: String,
    origin:  Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Change {
    domain: String,
    before: Option<MapEntry>,
    after:  Option<MapEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct HistoryEntry {
    id:      String,
    time:    String,
    // "manager" o "plesk" (eventi dei Plesk via haproxy-domain)
    source:  String,
    action:  String,
    changes: Vec<Change>,
    #[serde(default)]
    undo_of: Option<String>,
}

#[derive(Serialize)]
struct HistoryView {
    #[serde(flatten)]
    entry:  HistoryEntry,
    undone: bool,
}

struct Session {
    created:   Instant,
    last_seen: Instant,
}

#[derive(Default)]
struct LoginGuard {
    fails:         u32,
    first_fail:    Option<Instant>,
    blocked_until: Option<Instant>,
}

#[derive(Clone)]
struct AppState {
    sessions:    Arc<RwLock<HashMap<String, Session>>>,
    login_guard: Arc<Mutex<LoginGuard>>,
    cert_cache:  Arc<Mutex<Option<(Instant, Vec<String>)>>>,
    config:      Config,
}

// ── File I/O ──────────────────────────────────────────────────────
fn read_map(path: &str) -> Vec<(String, String)> {
    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect()
}

// domains.map (backend del frontend) + backends.map (origine dietro Varnish)
fn read_domains(config: &Config) -> Vec<Domain> {
    let origins: HashMap<String, String> = read_map(&config.backends_map).into_iter().collect();
    read_map(&config.domains_map)
        .into_iter()
        .map(|(name, backend)| {
            let origin = origins.get(&name).cloned().or_else(|| {
                (backend != VARNISH_BACKEND).then(|| backend.clone())
            });
            Domain { name, backend, origin }
        })
        .collect()
}

// Scrive su file temporaneo e rinomina: HAProxy e il sync verso lo slave
// non leggono mai un file a metà
fn write_map(path: &str, entries: &[(&str, &str)]) -> Result<(), String> {
    let content: String = entries
        .iter()
        .map(|(k, v)| format!("{:<50} {}\n", k, v))
        .collect();
    let tmp = format!("{}.tmp", path);
    fs::write(&tmp, content).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn write_domains(config: &Config, domains: &[Domain]) -> Result<(), String> {
    let front: Vec<(&str, &str)> = domains.iter().map(|d| (d.name.as_str(), d.backend.as_str())).collect();
    let origins: Vec<(&str, &str)> = domains
        .iter()
        .filter_map(|d| d.origin.as_deref().map(|o| (d.name.as_str(), o)))
        .collect();
    // Prima backends.map: un dominio appena messo su Varnish trova già l'origine
    write_map(&config.backends_map, &origins)?;
    write_map(&config.domains_map, &front)
}

// Lock condiviso con lo script degli eventi Plesk per la lettura-modifica-scrittura.
// Se il file l'ha creato root senza permesso di scrittura basta aprirlo in lettura:
// flock non guarda la modalità di apertura
fn lock_maps() -> Result<fs::File, String> {
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(MAPS_LOCK)
        .or_else(|_| fs::File::open(MAPS_LOCK))
        .map_err(|e| format!("{}: {}", MAPS_LOCK, e))?;
    f.lock().map_err(|e| e.to_string())?;
    Ok(f)
}

// Nome esatto come lo cerca HAProxy: minuscolo, senza "www." (lo toglie HAProxy)
fn normalize_domain(name: &str) -> Result<String, String> {
    let n = name.trim().trim_end_matches('.').to_lowercase();
    if n.starts_with("www.") {
        return Err(format!("{}: inserire il dominio senza www. (www. segue sempre il dominio)", n));
    }
    let valid = n.len() <= 253
        && n.contains('.')
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if valid { Ok(n) } else { Err(format!("Nome di dominio non valido: {}", name)) }
}

fn list_backends(config: &Config) -> Vec<String> {
    let content = fs::read_to_string(&config.haproxy_cfg).unwrap_or_default();
    content
        .lines()
        .filter(|l| l.trim().starts_with("backend "))
        .map(|l| l.trim().replace("backend ", ""))
        .collect()
}

// Origine per un dominio: se diretto è il backend stesso; se passa da Varnish
// quella richiesta, altrimenti quella già nota o il backend diretto precedente
fn resolve_origin(
    config: &Config,
    backend: &str,
    requested: Option<&str>,
    previous: Option<&Domain>,
) -> Result<String, String> {
    let known = list_backends(config);
    if !known.iter().any(|b| b == backend) {
        return Err(format!("Backend sconosciuto: {}", backend));
    }
    if backend != VARNISH_BACKEND {
        return Ok(backend.to_string());
    }
    let origin = requested
        .filter(|o| !o.is_empty())
        .map(|o| o.to_string())
        .or_else(|| previous.and_then(|d| d.origin.clone()))
        .ok_or_else(|| "Con varnish_backend va indicato il server di origine".to_string())?;
    if origin == VARNISH_BACKEND || !known.iter().any(|b| *b == origin) {
        return Err(format!("Server di origine non valido: {}", origin));
    }
    Ok(origin)
}

// ── Comandi privilegiati (haproxy-manager-helper, via sudo se non root) ─
fn run_helper(config: &Config, args: &[&str]) -> Result<String, String> {
    let is_root = fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false);
    let mut cmd = if is_root {
        Command::new(&config.helper)
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", &config.helper]);
        c
    };
    let output = cmd.args(args).output().map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if err.is_empty() { format!("{} {} fallito", config.helper, args.join(" ")) } else { err })
    }
}

fn reload_haproxy(config: &Config) -> Result<String, String> {
    run_helper(config, &["reload"]).map(|_| "HAProxy ricaricato con successo".to_string())
}

fn log_action(config: &Config, action: &str, domain: &str, detail: &str) {
    let line = format!(
        "[{}] {} | {} → {}",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        action, domain, detail
    );
    let content = fs::read_to_string(&config.log_file).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    lines.push(line);
    if lines.len() > 1000 {
        lines = lines[lines.len() - 1000..].to_vec();
    }
    let _ = fs::write(&config.log_file, lines.join("\n") + "\n");
}

fn purge_varnish_cache(config: &Config, domain: &str) -> Result<String, String> {
    // L'helper vieta tutto tranne un dominio valido e costruisce lui il ban
    // (anche www.: Varnish tiene in cache l'Host così come arriva)
    let domain = normalize_domain(domain)?;
    run_helper(config, &["purge", &domain]).map(|_| format!("Cache Varnish purgata per {}", domain))
}

// ── Certificati ───────────────────────────────────────────────────
// Nomi (SAN) di tutti i certificati in /etc/haproxy/certs, letti dall'helper
fn cert_names(state: &AppState) -> Option<Vec<String>> {
    let mut cache = state.cert_cache.lock().unwrap();
    if let Some((at, names)) = cache.as_ref() {
        if at.elapsed() < CERT_CACHE_TTL {
            return Some(names.clone());
        }
    }
    let out = run_helper(&state.config, &["certs"]).ok()?;
    let names: Vec<String> = out
        .lines()
        .flat_map(|l| l.split_whitespace().skip(1))
        .map(|s| s.to_lowercase())
        .collect();
    *cache = Some((Instant::now(), names.clone()));
    Some(names)
}

// Coperto da un nome uguale o da *.genitore (un solo livello, come nei certificati)
fn cert_covers(names: &[String], domain: &str) -> bool {
    let parent = domain.split_once('.').map(|(_, p)| p).unwrap_or("");
    names.iter().any(|n| n == domain || n.strip_prefix("*.") == Some(parent))
}

fn cert_warning(state: &AppState, domain: &str) -> String {
    match cert_names(state) {
        Some(names) if !cert_covers(&names, domain) => format!(
            " — attenzione: nessun certificato copre {}, Cloudflare risponderà 526",
            domain
        ),
        _ => String::new(),
    }
}

// ── Storico ───────────────────────────────────────────────────────
fn read_history(config: &Config) -> Vec<HistoryEntry> {
    fs::read_to_string(&config.history_file)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn append_history(config: &Config, entry: &HistoryEntry) {
    let Ok(line) = serde_json::to_string(entry) else { return };
    let mut entries: Vec<String> = fs::read_to_string(&config.history_file)
        .unwrap_or_default()
        .lines()
        .map(|s| s.to_string())
        .collect();
    entries.push(line);
    if entries.len() > HISTORY_KEEP {
        entries = entries[entries.len() - HISTORY_KEEP..].to_vec();
    }
    let tmp = format!("{}.tmp", config.history_file);
    let ok = fs::File::create(&tmp)
        .and_then(|mut f| f.write_all((entries.join("\n") + "\n").as_bytes()))
        .and_then(|_| fs::rename(&tmp, &config.history_file));
    if let Err(e) = ok {
        tracing::warn!("storico non scritto ({}): {}", config.history_file, e);
    }
}

fn entry_of(d: &Domain) -> MapEntry {
    MapEntry { backend: d.backend.clone(), origin: d.origin.clone() }
}

fn diff_domains(old: &[Domain], new: &[Domain]) -> Vec<Change> {
    let o: HashMap<&str, &Domain> = old.iter().map(|d| (d.name.as_str(), d)).collect();
    let n: HashMap<&str, &Domain> = new.iter().map(|d| (d.name.as_str(), d)).collect();
    let names: BTreeSet<&str> = o.keys().chain(n.keys()).copied().collect();
    names
        .into_iter()
        .filter_map(|name| {
            let before = o.get(name).map(|d| entry_of(d));
            let after = n.get(name).map(|d| entry_of(d));
            (before != after).then(|| Change { domain: name.to_string(), before, after })
        })
        .collect()
}

// Scrive le mappe, controlla e ricarica HAProxy; se HAProxy rifiuta la
// configurazione rimette le mappe di prima. Va chiamata con il lock preso.
fn commit_change(
    config: &Config,
    old: &[Domain],
    new: &[Domain],
    action: &str,
    undo_of: Option<String>,
) -> Result<usize, String> {
    let changes = diff_domains(old, new);
    if changes.is_empty() {
        return Ok(0);
    }
    if let Err(e) = write_domains(config, new) {
        let _ = write_domains(config, old);
        return Err(e);
    }
    if let Err(e) = reload_haproxy(config) {
        let _ = write_domains(config, old);
        let _ = reload_haproxy(config);
        return Err(format!("HAProxy ha rifiutato la modifica, mappe ripristinate: {}", e));
    }
    let n = changes.len();
    append_history(config, &HistoryEntry {
        id: format!("{}-{}", Local::now().format("%Y%m%d%H%M%S"), &Uuid::new_v4().simple().to_string()[..6]),
        time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        source: "manager".to_string(),
        action: action.to_string(),
        changes,
        undo_of,
    });
    Ok(n)
}

// ── Middleware Auth ───────────────────────────────────────────────
async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Route pubbliche: solo la pagina, i suoi file e il login
    if path == "/auth/login" || path == "/" || path.starts_with("/static/") {
        return next.run(request).await;
    }

    // Controlla token
    let token = request
        .headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Il lock va rilasciato prima di qualsiasi .await
    let valid = token.is_some_and(|t| {
        let mut sessions = state.sessions.write().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| now - s.last_seen < SESSION_IDLE && now - s.created < SESSION_MAX);
        sessions.get_mut(&t).map(|s| s.last_seen = now).is_some()
    });
    if valid {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(ApiResponse::<()> {
            success: false,
            message: "Non autenticato".to_string(),
            data: None,
        }),
    )
        .into_response()
}

// ── Handler Auth ──────────────────────────────────────────────────
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// Confronto a tempo costante (non dipende da quanti caratteri coincidono)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn check_credentials(config: &Config, user: &str, pass: &str) -> bool {
    let user_ok = ct_eq(user.as_bytes(), config.admin_user.as_bytes());
    let pass_ok = if let Some(hash) = &config.admin_pass_hash {
        bcrypt::verify(pass, hash).unwrap_or(false)
    } else if let Some(plain) = &config.admin_pass {
        ct_eq(pass.as_bytes(), plain.as_bytes())
    } else {
        false
    };
    user_ok && pass_ok
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    if let Some(until) = state.login_guard.lock().unwrap().blocked_until {
        let now = Instant::now();
        if until > now {
            let min = (until - now).as_secs() / 60 + 1;
            return reply(
                StatusCode::TOO_MANY_REQUESTS,
                false,
                format!("Troppi tentativi sbagliati: riprova tra {} minuti", min),
            );
        }
    }

    // bcrypt è lento apposta: fuori dal thread che serve le richieste
    let config = state.config.clone();
    let (user, pass) = (req.username, req.password);
    let ok = tokio::task::spawn_blocking(move || check_credentials(&config, &user, &pass))
        .await
        .unwrap_or(false);

    if ok {
        *state.login_guard.lock().unwrap() = LoginGuard::default();
        let token = Uuid::new_v4().to_string();
        let now = Instant::now();
        state
            .sessions
            .write()
            .unwrap()
            .insert(token.clone(), Session { created: now, last_seen: now });
        return Json(ApiResponse {
            success: true,
            message: "Login effettuato".to_string(),
            data: Some(LoginResponse { token }),
        })
        .into_response();
    }

    {
        let mut g = state.login_guard.lock().unwrap();
        let now = Instant::now();
        if g.first_fail.map_or(true, |t| now - t > LOGIN_WINDOW) {
            g.fails = 0;
            g.first_fail = Some(now);
        }
        g.fails += 1;
        if g.fails >= LOGIN_MAX_FAILS {
            g.blocked_until = Some(now + LOGIN_BLOCK);
            g.fails = 0;
            g.first_fail = None;
            tracing::warn!("login bloccato per {} minuti dopo {} errori", LOGIN_BLOCK.as_secs() / 60, LOGIN_MAX_FAILS);
        }
    }
    log_action(&state.config, "LOGIN", "-", "credenziali non valide");
    tokio::time::sleep(Duration::from_secs(1)).await;
    reply(StatusCode::OK, false, "Credenziali non valide".to_string())
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(t) = headers.get("X-Session-Token").and_then(|v| v.to_str().ok()) {
        state.sessions.write().unwrap().remove(t);
    }
    Json(ApiResponse::<()> {
        success: true,
        message: "Logout effettuato".to_string(),
        data: None,
    })
}

// ── Handler Domini ────────────────────────────────────────────────
async fn get_domains(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let names = cert_names(&state);
    let domains: Vec<DomainView> = read_domains(&state.config)
        .into_iter()
        .map(|d| {
            let cert = names.as_ref().map(|n| cert_covers(n, &d.name));
            DomainView { domain: d, cert }
        })
        .collect();
    Json(ApiResponse {
        success: true,
        message: format!("{} domini trovati", domains.len()),
        data: Some(domains),
    })
}

fn reply(status: StatusCode, success: bool, message: String) -> Response {
    (status, Json(ApiResponse::<()> { success, message, data: None })).into_response()
}

async fn add_domain(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> impl IntoResponse {
    let name = match normalize_domain(&req.name) {
        Ok(n) => n,
        Err(e) => return reply(StatusCode::BAD_REQUEST, false, e),
    };
    let _lock = match lock_maps() {
        Ok(l) => l,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    };
    let old = read_domains(&state.config);
    if old.iter().any(|d| d.name == name) {
        return reply(StatusCode::CONFLICT, false, format!("Dominio {} già esistente", name));
    }
    let origin = match resolve_origin(&state.config, &req.backend, req.origin.as_deref(), None) {
        Ok(o) => o,
        Err(e) => return reply(StatusCode::BAD_REQUEST, false, e),
    };
    let mut new = old.clone();
    new.push(Domain {
        name:    name.clone(),
        backend: req.backend.clone(),
        origin:  Some(origin.clone()),
    });
    match commit_change(&state.config, &old, &new, &format!("Aggiunto {}", name), None) {
        Ok(_) => {
            log_action(&state.config, "ADD", &name, &format!("{} (origine {})", req.backend, origin));
            let warn = cert_warning(&state, &name);
            reply(StatusCode::OK, true, format!("Dominio {} aggiunto{}", name, warn))
        }
        Err(e) => reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    }
}

async fn update_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Json(req): Json<DomainRequest>,
) -> impl IntoResponse {
    let _lock = match lock_maps() {
        Ok(l) => l,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    };
    let old = read_domains(&state.config);
    let mut new = old.clone();
    let Some(d) = new.iter_mut().find(|d| d.name == domain) else {
        return reply(StatusCode::NOT_FOUND, false, format!("Dominio {} non trovato", domain));
    };
    let origin = match resolve_origin(&state.config, &req.backend, req.origin.as_deref(), Some(d)) {
        Ok(o) => o,
        Err(e) => return reply(StatusCode::BAD_REQUEST, false, e),
    };
    let before = format!("{} (origine {})", d.backend, d.origin.as_deref().unwrap_or("-"));
    let after = format!("{} (origine {})", req.backend, origin);
    d.backend = req.backend.clone();
    d.origin = Some(origin);
    match commit_change(&state.config, &old, &new, &format!("Modificato {}", domain), None) {
        Ok(0) => reply(StatusCode::OK, true, format!("{}: nessuna modifica", domain)),
        Ok(_) => {
            log_action(&state.config, "UPDATE", &domain, &format!("{} → {}", before, after));
            reply(StatusCode::OK, true, format!("Backend: {} → {}", before, after))
        }
        Err(e) => reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    }
}

async fn delete_domain(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let _lock = match lock_maps() {
        Ok(l) => l,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    };
    let old = read_domains(&state.config);
    let new: Vec<Domain> = old.iter().filter(|d| d.name != domain).cloned().collect();
    if new.len() == old.len() {
        return reply(StatusCode::NOT_FOUND, false, format!("Dominio {} non trovato", domain));
    }
    match commit_change(&state.config, &old, &new, &format!("Rimosso {}", domain), None) {
        Ok(_) => {
            log_action(&state.config, "DELETE", &domain, "-");
            reply(StatusCode::OK, true, format!("Dominio {} rimosso", domain))
        }
        Err(e) => reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    }
}

async fn bulk_update(
    State(state): State<AppState>,
    Json(req): Json<BulkRequest>,
) -> impl IntoResponse {
    let _lock = match lock_maps() {
        Ok(l) => l,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    };
    let old = read_domains(&state.config);
    let mut new = old.clone();
    let mut skipped = Vec::new();
    for name in &req.domains {
        if let Some(d) = new.iter_mut().find(|d| &d.name == name) {
            // Verso Varnish ogni dominio tiene la sua origine
            match resolve_origin(&state.config, &req.backend, None, Some(d)) {
                Ok(o) => {
                    d.backend = req.backend.clone();
                    d.origin = Some(o);
                }
                Err(_) => skipped.push(name.clone()),
            }
        }
    }
    let action = format!("{} domini → {}", req.domains.len() - skipped.len(), req.backend);
    match commit_change(&state.config, &old, &new, &action, None) {
        Ok(updated) => {
            log_action(&state.config, "BULK", &format!("{} domini", updated), &req.backend);
            let mut msg = format!("{} domini → {}", updated, req.backend);
            if !skipped.is_empty() {
                msg.push_str(&format!(" (saltati, origine sconosciuta: {})", skipped.join(", ")));
            }
            reply(StatusCode::OK, true, msg)
        }
        Err(e) => reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    }
}

// ── Handler Storico ───────────────────────────────────────────────
async fn get_history(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let entries = read_history(&state.config);
    let undone: BTreeSet<String> = entries.iter().filter_map(|e| e.undo_of.clone()).collect();
    let view: Vec<HistoryView> = entries
        .into_iter()
        .rev()
        .take(200)
        .map(|e| {
            let u = undone.contains(&e.id);
            HistoryView { entry: e, undone: u }
        })
        .collect();
    Json(ApiResponse {
        success: true,
        message: format!("{} modifiche", view.len()),
        data: Some(view),
    })
}

// Annulla una modifica: solo se i domini interessati sono ancora come li ha
// lasciati, così non si cancella una modifica fatta dopo (anche dai Plesk)
async fn undo_change(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let _lock = match lock_maps() {
        Ok(l) => l,
        Err(e) => return reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    };
    let entries = read_history(&state.config);
    let Some(entry) = entries.iter().find(|e| e.id == id) else {
        return reply(StatusCode::NOT_FOUND, false, format!("Modifica {} non trovata", id));
    };
    if entries.iter().any(|e| e.undo_of.as_deref() == Some(id.as_str())) {
        return reply(StatusCode::CONFLICT, false, "Modifica già annullata".to_string());
    }
    let old = read_domains(&state.config);
    let current: HashMap<&str, MapEntry> = old.iter().map(|d| (d.name.as_str(), entry_of(d))).collect();
    let changed: Vec<&str> = entry
        .changes
        .iter()
        .filter(|c| current.get(c.domain.as_str()) != c.after.as_ref())
        .map(|c| c.domain.as_str())
        .collect();
    if !changed.is_empty() {
        return reply(
            StatusCode::CONFLICT,
            false,
            format!("Non annullabile: modificati di nuovo dopo: {}", changed.join(", ")),
        );
    }
    let mut new = old.clone();
    for c in &entry.changes {
        new.retain(|d| d.name != c.domain);
        if let Some(b) = &c.before {
            new.push(Domain { name: c.domain.clone(), backend: b.backend.clone(), origin: b.origin.clone() });
        }
    }
    // Ordine del file invariato per i domini rimasti, quelli rimessi in fondo
    let pos: HashMap<&str, usize> = old.iter().enumerate().map(|(i, d)| (d.name.as_str(), i)).collect();
    new.sort_by_key(|d| pos.get(d.name.as_str()).copied().unwrap_or(usize::MAX));
    let action = format!("Annullato: {}", entry.action);
    match commit_change(&state.config, &old, &new, &action, Some(id.clone())) {
        Ok(_) => {
            log_action(&state.config, "UNDO", &entry.action, &id);
            reply(StatusCode::OK, true, action)
        }
        Err(e) => reply(StatusCode::INTERNAL_SERVER_ERROR, false, e),
    }
}

// ── Handler Cache Varnish ─────────────────────────────────────────
async fn purge_cache(
    State(state): State<AppState>,
    Json(req): Json<CachePurgeRequest>,
) -> impl IntoResponse {
    match purge_varnish_cache(&state.config, &req.domain) {
        Ok(msg) => {
            log_action(&state.config, "PURGE", &req.domain, "cache purged");
            Json(ApiResponse::<()> {
                success: true,
                message: msg,
                data: None,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> {
                success: false,
                message: e,
                data: None,
            }),
        )
            .into_response(),
    }
}

// ── Handler Backend ───────────────────────────────────────────────
async fn get_backends(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let backends = list_backends(&state.config);
    Json(ApiResponse {
        success: true,
        message: format!("{} backend trovati", backends.len()),
        data: Some(backends),
    })
}

// Nuovo server Plesk: il blocco in haproxy.cfg lo scrive l'helper (root),
// che controlla, ricarica, sincronizza lo slave e committa nella repo
async fn add_backend(
    State(state): State<AppState>,
    Json(req): Json<BackendRequest>,
) -> impl IntoResponse {
    let name = req.name.trim().to_lowercase();
    let name = name.strip_suffix("_backend").unwrap_or(&name).to_string();
    let valid = name.len() <= 31
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return reply(StatusCode::BAD_REQUEST, false, "Nome non valido: lettere minuscole, cifre e -, es. server7".to_string());
    }
    let ip = match req.ip.trim().parse::<std::net::Ipv4Addr>() {
        Ok(ip) if !(ip.is_unspecified() || ip.is_loopback() || ip.is_broadcast() || ip.is_multicast()) => ip,
        _ => return reply(StatusCode::BAD_REQUEST, false, format!("Indirizzo IP non valido: {}", req.ip.trim())),
    };
    let ip = ip.to_string();
    let config = state.config.clone();
    let (n, i) = (name.clone(), ip.clone());
    // haproxy -c, reload e git: fuori dal thread che serve le richieste
    let res = tokio::task::spawn_blocking(move || run_helper(&config, &["add-backend", &n, &i]))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    match res {
        Ok(out) => {
            log_action(&state.config, "BACKEND", &format!("{}_backend", name), &ip);
            let warn: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
            let mut msg = format!("Backend {}_backend ({}) aggiunto", name, ip);
            if !warn.is_empty() {
                msg.push_str(&format!(" — {}", warn.join("; ")));
            }
            reply(StatusCode::OK, true, msg)
        }
        Err(e) => reply(StatusCode::BAD_REQUEST, false, e),
    }
}

// Rimozione: l'helper la rifiuta se un dominio (diretto o come origine dietro
// Varnish) o un'altra regola di haproxy.cfg usa ancora il backend
async fn delete_backend(
    State(state): State<AppState>,
    Path(backend): Path<String>,
) -> impl IntoResponse {
    let name = backend.strip_suffix("_backend").unwrap_or(&backend).to_string();
    let valid = !name.is_empty()
        && name.len() <= 31
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return reply(StatusCode::BAD_REQUEST, false, format!("Backend non valido: {}", backend));
    }
    let config = state.config.clone();
    let n = name.clone();
    let res = tokio::task::spawn_blocking(move || run_helper(&config, &["remove-backend", &n]))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    match res {
        Ok(out) => {
            log_action(&state.config, "BACKEND-DEL", &format!("{}_backend", name), "-");
            let warn: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
            let mut msg = format!("Backend {}_backend rimosso", name);
            if !warn.is_empty() {
                msg.push_str(&format!(" — {}", warn.join("; ")));
            }
            reply(StatusCode::OK, true, msg)
        }
        Err(e) => reply(StatusCode::BAD_REQUEST, false, e),
    }
}

// ── Handler Sistema ───────────────────────────────────────────────
async fn haproxy_reload(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match reload_haproxy(&state.config) {
        Ok(msg) => {
            log_action(&state.config, "RELOAD", "haproxy", "ok");
            Json(ApiResponse::<()> {
                success: true,
                message: msg,
                data: None,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()> {
                success: false,
                message: e,
                data: None,
            }),
        )
            .into_response(),
    }
}

async fn haproxy_status(
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let output = Command::new("systemctl")
        .args(["is-active", "haproxy"])
        .output();
    let status = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    };
    Json(ApiResponse {
        success: status == "active",
        message: format!("HAProxy: {}", status),
        data: Some(status),
    })
}

async fn get_logs(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let content = fs::read_to_string(&state.config.log_file).unwrap_or_default();
    let lines: Vec<String> = content
        .lines()
        .rev()
        .take(100)
        .map(|s| s.to_string())
        .collect();
    Json(ApiResponse {
        success: true,
        message: format!("{} log entries", lines.len()),
        data: Some(lines),
    })
}

// ── Serve file statici da UI_DIR ──────────────────────────────────
async fn serve_index(
    State(state): State<AppState>,
) -> impl IntoResponse {
    serve_file(&state.config, "index.html", "text/html").await
}

async fn serve_static(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    // Solo file di UI_DIR: niente "/" né ".." (il nome arriva già decodificato,
    // %2e%2e%2f diventerebbe ../)
    let safe = !filename.is_empty()
        && !filename.starts_with('.')
        && filename.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !safe {
        return (StatusCode::NOT_FOUND, "File non trovato").into_response();
    }
    let mime = if filename.ends_with(".css") {
        "text/css"
    } else if filename.ends_with(".js") {
        "application/javascript"
    } else {
        "text/plain"
    };
    serve_file(&state.config, &filename, mime).await
}

async fn serve_file(config: &Config, filename: &str, mime: &str) -> Response {
    let path = format!("{}/{}", config.ui_dir, filename);
    match fs::read(&path) {
        Ok(content) => Response::builder()
            .header(header::CONTENT_TYPE, mime)
            .body(Body::from(content))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("File non trovato"))
            .unwrap(),
    }
}

// `haproxy-manager hash-password`: legge la password da stdin e stampa
// l'hash per ADMIN_PASS_HASH (nel .env tra apici singoli: contiene "$")
fn hash_password() {
    let mut pass = String::new();
    std::io::stdin().read_line(&mut pass).expect("lettura da stdin");
    let pass = pass.trim_end_matches(['\n', '\r']);
    if pass.is_empty() {
        eprintln!("Password vuota");
        std::process::exit(1);
    }
    if pass.chars().count() < 12 {
        eprintln!("Attenzione: password corta, meglio almeno 12 caratteri");
    }
    println!("{}", bcrypt::hash(pass, 12).expect("bcrypt"));
}

// ── Main ──────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        return hash_password();
    }

    tracing_subscriber::fmt::init();

    let config = load_config();

    tracing::info!("Configuration loaded:");
    tracing::info!("  Listen address: {}", config.listen_addr);
    tracing::info!("  Domains map: {}", config.domains_map);
    tracing::info!("  HAProxy config: {}", config.haproxy_cfg);
    tracing::info!("  Log file: {}", config.log_file);
    tracing::info!("  History: {}", config.history_file);
    tracing::info!("  UI directory: {}", config.ui_dir);
    tracing::info!("  Helper: {}", config.helper);
    if config.admin_pass_hash.is_none() {
        if config.admin_pass.is_some() {
            tracing::warn!("ADMIN_PASS in chiaro: meglio ADMIN_PASS_HASH (haproxy-manager hash-password)");
        } else {
            tracing::warn!("Né ADMIN_PASS_HASH né ADMIN_PASS impostati: login impossibile");
        }
    }

    let state = AppState {
        sessions:    Arc::new(RwLock::new(HashMap::new())),
        login_guard: Arc::new(Mutex::new(LoginGuard::default())),
        cert_cache:  Arc::new(Mutex::new(None)),
        config,
    };

    let app = Router::new()
        // UI statica
        .route("/", get(serve_index))
        .route("/static/{filename}", get(serve_static))
        // Auth
        .route("/auth/login",  post(login))
        .route("/auth/logout", post(logout))
        // Domini
        .route("/api/domains",             get(get_domains))
        .route("/api/domains",             post(add_domain))
        .route("/api/domains/bulk",        post(bulk_update))
        .route("/api/domains/{domain}",    put(update_domain))
        .route("/api/domains/{domain}",    delete(delete_domain))
        // Storico
        .route("/api/history",             get(get_history))
        .route("/api/history/{id}/undo",   post(undo_change))
        // Cache Varnish
        .route("/api/cache/purge",         post(purge_cache))
        // Backend
        .route("/api/backends",            get(get_backends))
        .route("/api/backends",            post(add_backend))
        .route("/api/backends/{backend}",  delete(delete_backend))
        // Sistema
        .route("/api/haproxy/reload",      post(haproxy_reload))
        .route("/api/haproxy/status",      get(haproxy_status))
        .route("/api/logs",                get(get_logs))
        // Middleware
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let listener = TcpListener::bind(&state.config.listen_addr).await.unwrap();
    tracing::info!("HAProxy Manager → http://{}", state.config.listen_addr);
    axum::serve(listener, app).await.unwrap();
}
