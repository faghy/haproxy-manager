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
    collections::HashMap,
    fs,
    process::Command,
    sync::{Arc, RwLock},
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
        listen_addr: std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string()),
        admin_user: std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
        admin_pass: std::env::var("ADMIN_PASS").unwrap_or_else(|_| "CHANGE_ME".to_string()),
        ui_dir: std::env::var("UI_DIR").unwrap_or_else(|_| "/opt/haproxy-manager/ui".to_string()),
        varnish_adm: std::env::var("VARNISH_ADM").unwrap_or_else(|_| "/usr/bin/varnishadm".to_string()),
    }
}

#[derive(Clone)]
struct Config {
    domains_map: String,
    backends_map: String,
    haproxy_cfg: String,
    log_file: String,
    listen_addr: String,
    admin_user: String,
    admin_pass: String,
    ui_dir: String,
    varnish_adm: String,
}

// ── Strutture ─────────────────────────────────────────────────────
// Backend che passa da Varnish: il server di origine è in backends.map
const VARNISH_BACKEND: &str = "varnish_backend";
// Stesso lock di /usr/local/sbin/haproxy-domain (script degli eventi Plesk)
const MAPS_LOCK: &str = "/run/lock/haproxy-maps.lock";

#[derive(Clone, Serialize, Deserialize)]
struct Domain {
    name:    String,
    backend: String,
    // Server di origine (backends.map): uguale a backend se diretto
    #[serde(default)]
    origin:  Option<String>,
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

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    success: bool,
    message: String,
    data:    Option<T>,
}

#[derive(Clone)]
struct AppState {
    sessions: Arc<RwLock<HashMap<String, String>>>,
    config: Config,
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

// Lock condiviso con lo script degli eventi Plesk per la lettura-modifica-scrittura
fn lock_maps() -> Result<fs::File, String> {
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(MAPS_LOCK)
        .map_err(|e| e.to_string())?;
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

fn reload_haproxy(config: &Config) -> Result<String, String> {
    let check = Command::new("haproxy")
        .args(["-c", "-f", &config.haproxy_cfg])
        .output()
        .map_err(|e| e.to_string())?;
    if !check.status.success() {
        return Err(String::from_utf8_lossy(&check.stderr).to_string());
    }
    let reload = Command::new("systemctl")
        .args(["reload", "haproxy"])
        .output()
        .map_err(|e| e.to_string())?;
    if reload.status.success() {
        Ok("HAProxy ricaricato con successo".to_string())
    } else {
        Err(String::from_utf8_lossy(&reload.stderr).to_string())
    }
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
    // Anche www.: Varnish tiene in cache l'Host così come arriva
    let domain = normalize_domain(domain)?;
    let expr = format!("req.http.host ~ ^(www[.])?{}$", domain.replace('.', "[.]"));
    let output = Command::new(&config.varnish_adm)
        .args(["ban", &expr])
        .output()
        .map_err(|e| e.to_string())?;
    
    if output.status.success() {
        Ok(format!("Cache Varnish purgata per {}", domain))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

// ── Middleware Auth ───────────────────────────────────────────────
async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Route pubbliche
    if path == "/auth/login"
        || path == "/"
        || path.starts_with("/static")
        || path.ends_with(".html")
        || path.ends_with(".css")
        || path.ends_with(".js")
    {
        return next.run(request).await;
    }

    // Controlla token
    let token = request
        .headers()
        .get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(t) = token {
        if state.sessions.read().unwrap().contains_key(&t) {
            return next.run(request).await;
        }
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

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    if req.username == state.config.admin_user && req.password == state.config.admin_pass {
        let token = Uuid::new_v4().to_string();
        state
            .sessions
            .write()
            .unwrap()
            .insert(token.clone(), req.username);
        Json(ApiResponse {
            success: true,
            message: "Login effettuato".to_string(),
            data: Some(LoginResponse { token }),
        })
    } else {
        Json(ApiResponse::<LoginResponse> {
            success: false,
            message: "Credenziali non valide".to_string(),
            data: None,
        })
    }
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
    let domains = read_domains(&state.config);
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
    let mut domains = read_domains(&state.config);
    if domains.iter().any(|d| d.name == name) {
        return reply(StatusCode::CONFLICT, false, format!("Dominio {} già esistente", name));
    }
    let origin = match resolve_origin(&state.config, &req.backend, req.origin.as_deref(), None) {
        Ok(o) => o,
        Err(e) => return reply(StatusCode::BAD_REQUEST, false, e),
    };
    domains.push(Domain {
        name:    name.clone(),
        backend: req.backend.clone(),
        origin:  Some(origin.clone()),
    });
    match write_domains(&state.config, &domains) {
        Ok(_) => {
            log_action(&state.config, "ADD", &name, &format!("{} (origine {})", req.backend, origin));
            reply(StatusCode::OK, true, format!("Dominio {} aggiunto", name))
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
    let mut domains = read_domains(&state.config);
    let Some(d) = domains.iter_mut().find(|d| d.name == domain) else {
        return reply(StatusCode::NOT_FOUND, false, format!("Dominio {} non trovato", domain));
    };
    let origin = match resolve_origin(&state.config, &req.backend, req.origin.as_deref(), Some(d)) {
        Ok(o) => o,
        Err(e) => return reply(StatusCode::BAD_REQUEST, false, e),
    };
    let old = format!("{} (origine {})", d.backend, d.origin.as_deref().unwrap_or("-"));
    let new = format!("{} (origine {})", req.backend, origin);
    d.backend = req.backend.clone();
    d.origin = Some(origin);
    match write_domains(&state.config, &domains) {
        Ok(_) => {
            log_action(&state.config, "UPDATE", &domain, &format!("{} → {}", old, new));
            reply(StatusCode::OK, true, format!("Backend: {} → {}", old, new))
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
    let mut domains = read_domains(&state.config);
    let before = domains.len();
    domains.retain(|d| d.name != domain);
    if domains.len() == before {
        return reply(StatusCode::NOT_FOUND, false, format!("Dominio {} non trovato", domain));
    }
    match write_domains(&state.config, &domains) {
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
    let mut domains = read_domains(&state.config);
    let mut updated = 0;
    let mut skipped = Vec::new();
    for name in &req.domains {
        if let Some(d) = domains.iter_mut().find(|d| &d.name == name) {
            // Verso Varnish ogni dominio tiene la sua origine
            match resolve_origin(&state.config, &req.backend, None, Some(d)) {
                Ok(o) => {
                    d.backend = req.backend.clone();
                    d.origin = Some(o);
                    updated += 1;
                }
                Err(_) => skipped.push(name.clone()),
            }
        }
    }
    match write_domains(&state.config, &domains) {
        Ok(_) => {
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
    State(state): State<AppState>,
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
#[allow(unused_variables)]
async fn serve_index(
    State(state): State<AppState>,
) -> impl IntoResponse {
    serve_file(&state.config, "index.html", "text/html").await
}

async fn serve_static(
    State(state): State<AppState>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
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

// ── Main ──────────────────────────────────────────────────────────
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let config = load_config();
    
    tracing::info!("Configuration loaded:");
    tracing::info!("  Listen address: {}", config.listen_addr);
    tracing::info!("  Domains map: {}", config.domains_map);
    tracing::info!("  HAProxy config: {}", config.haproxy_cfg);
    tracing::info!("  Log file: {}", config.log_file);
    tracing::info!("  UI directory: {}", config.ui_dir);
    tracing::info!("  Varnish admin: {}", config.varnish_adm);

    let state = AppState {
        sessions: Arc::new(RwLock::new(HashMap::new())),
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
        // Cache Varnish
        .route("/api/cache/purge",         post(purge_cache))
        // Backend
        .route("/api/backends",            get(get_backends))
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