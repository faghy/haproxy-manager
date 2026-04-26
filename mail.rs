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

// ── Configurazione ────────────────────────────────────────────────
const DOMAINS_MAP: &str = "/etc/haproxy/maps/domains.map";
const HAPROXY_CFG: &str = "/etc/haproxy/haproxy.cfg";
const LOG_FILE:    &str = "/var/log/haproxy-manager.log";
const LISTEN_ADDR: &str = "127.0.0.1:8080";
const ADMIN_USER:  &str = "admin";
const ADMIN_PASS:  &str = "CAMBIA_QUESTA_PASSWORD";
const UI_DIR:      &str = "/opt/haproxy-manager/ui";

// ── Strutture ─────────────────────────────────────────────────────
#[derive(Clone, Serialize, Deserialize)]
struct Domain {
    name:    String,
    backend: String,
}

#[derive(Deserialize)]
struct DomainRequest {
    name:    String,
    backend: String,
}

#[derive(Deserialize)]
struct BulkRequest {
    domains: Vec<String>,
    backend: String,
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
}

// ── File I/O ──────────────────────────────────────────────────────
fn read_domains() -> Vec<Domain> {
    let content = fs::read_to_string(DOMAINS_MAP).unwrap_or_default();
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                Some(Domain {
                    name:    parts[0].to_string(),
                    backend: parts[1].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

fn write_domains(domains: &[Domain]) -> Result<(), String> {
    let content = domains
        .iter()
        .map(|d| format!("{:<50} {}", d.name, d.backend))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(DOMAINS_MAP, content + "\n").map_err(|e| e.to_string())
}

fn reload_haproxy() -> Result<String, String> {
    let check = Command::new("haproxy")
        .args(["-c", "-f", HAPROXY_CFG])
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

fn log_action(action: &str, domain: &str, detail: &str) {
    let line = format!(
        "[{}] {} | {} → {}\n",
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        action, domain, detail
    );
    let content = fs::read_to_string(LOG_FILE).unwrap_or_default();
    let mut lines: Vec<&str> = content.lines().collect();
    lines.push(Box::leak(line.clone().into_boxed_str()));
    if lines.len() > 1000 {
        lines = lines[lines.len() - 1000..].to_vec();
    }
    let _ = fs::write(LOG_FILE, lines.join("\n") + "\n");
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
    if req.username == ADMIN_USER && req.password == ADMIN_PASS {
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
async fn get_domains() -> impl IntoResponse {
    let domains = read_domains();
    Json(ApiResponse {
        success: true,
        message: format!("{} domini trovati", domains.len()),
        data: Some(domains),
    })
}

async fn add_domain(Json(req): Json<DomainRequest>) -> impl IntoResponse {
    let mut domains = read_domains();
    if domains.iter().any(|d| d.name == req.name) {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<()> {
                success: false,
                message: format!("Dominio {} già esistente", req.name),
                data: None,
            }),
        )
            .into_response();
    }
    domains.push(Domain {
        name:    req.name.clone(),
        backend: req.backend.clone(),
    });
    match write_domains(&domains) {
        Ok(_) => {
            log_action("ADD", &req.name, &req.backend);
            Json(ApiResponse::<()> {
                success: true,
                message: format!("Dominio {} aggiunto", req.name),
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

async fn update_domain(
    Path(domain): Path<String>,
    Json(req): Json<DomainRequest>,
) -> impl IntoResponse {
    let mut domains = read_domains();
    match domains.iter_mut().find(|d| d.name == domain) {
        Some(d) => {
            let old = d.backend.clone();
            d.backend = req.backend.clone();
            match write_domains(&domains) {
                Ok(_) => {
                    log_action("UPDATE", &domain, &format!("{} → {}", old, req.backend));
                    Json(ApiResponse::<()> {
                        success: true,
                        message: format!("Backend: {} → {}", old, req.backend),
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
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()> {
                success: false,
                message: format!("Dominio {} non trovato", domain),
                data: None,
            }),
        )
            .into_response(),
    }
}

async fn delete_domain(Path(domain): Path<String>) -> impl IntoResponse {
    let mut domains = read_domains();
    let before = domains.len();
    domains.retain(|d| d.name != domain);
    if domains.len() == before {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()> {
                success: false,
                message: format!("Dominio {} non trovato", domain),
                data: None,
            }),
        )
            .into_response();
    }
    match write_domains(&domains) {
        Ok(_) => {
            log_action("DELETE", &domain, "-");
            Json(ApiResponse::<()> {
                success: true,
                message: format!("Dominio {} rimosso", domain),
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

async fn bulk_update(Json(req): Json<BulkRequest>) -> impl IntoResponse {
    let mut domains = read_domains();
    let mut updated = 0;
    for name in &req.domains {
        if let Some(d) = domains.iter_mut().find(|d| &d.name == name) {
            d.backend = req.backend.clone();
            updated += 1;
        }
    }
    match write_domains(&domains) {
        Ok(_) => {
            log_action("BULK", &format!("{} domini", updated), &req.backend);
            Json(ApiResponse::<()> {
                success: true,
                message: format!("{} domini → {}", updated, req.backend),
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
async fn get_backends() -> impl IntoResponse {
    let content = fs::read_to_string(HAPROXY_CFG).unwrap_or_default();
    let backends: Vec<String> = content
        .lines()
        .filter(|l| l.trim().starts_with("backend "))
        .map(|l| l.trim().replace("backend ", ""))
        .collect();
    Json(ApiResponse {
        success: true,
        message: format!("{} backend trovati", backends.len()),
        data: Some(backends),
    })
}

// ── Handler Sistema ───────────────────────────────────────────────
async fn haproxy_reload() -> impl IntoResponse {
    match reload_haproxy() {
        Ok(msg) => {
            log_action("RELOAD", "haproxy", "ok");
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

async fn haproxy_status() -> impl IntoResponse {
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

async fn get_logs() -> impl IntoResponse {
    let content = fs::read_to_string(LOG_FILE).unwrap_or_default();
    // Fix errore E0515: Vec<String> invece di Vec<&str>
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
async fn serve_index() -> impl IntoResponse {
    serve_file("index.html", "text/html").await
}

async fn serve_static(Path(filename): Path<String>) -> impl IntoResponse {
    let mime = if filename.ends_with(".css") {
        "text/css"
    } else if filename.ends_with(".js") {
        "application/javascript"
    } else {
        "text/plain"
    };
    serve_file(&filename, mime).await
}

async fn serve_file(filename: &str, mime: &str) -> Response {
    let path = format!("{}/{}", UI_DIR, filename);
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

    let state = AppState {
        sessions: Arc::new(RwLock::new(HashMap::new())),
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
        // Backend
        .route("/api/backends",            get(get_backends))
        // Sistema
        .route("/api/haproxy/reload",      post(haproxy_reload))
        .route("/api/haproxy/status",      get(haproxy_status))
        .route("/api/logs",                get(get_logs))
        // Middleware
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    let listener = TcpListener::bind(LISTEN_ADDR).await.unwrap();
    tracing::info!("HAProxy Manager → http://{}", LISTEN_ADDR);
    axum::serve(listener, app).await.unwrap();
}
