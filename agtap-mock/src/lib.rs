pub mod scenario;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::header::HeaderName;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use rcgen::generate_simple_self_signed;
use serde::Deserialize;

use crate::scenario::Scenario;

// ── Configuration ────────────────────────────────────────────────────────────

pub struct MockConfig {
    pub scenarios_dir: PathBuf,
    pub port: u16, // 0 for random
}

/// Handle returned by start_server. Server shuts down when this is dropped.
pub struct ServerHandle {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub addr: SocketAddr,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ── Server state ─────────────────────────────────────────────────────────────

struct AppState {
    /// Map from scenario name → loaded scenario
    scenarios: HashMap<String, Scenario>,
}

// ── Route handler ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ScenarioQuery {
    scenario: Option<String>,
}

async fn handle_messages(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ScenarioQuery>,
    _body: String,
) -> impl IntoResponse {
    // Always require ?scenario= query parameter
    let scenario = match query.scenario {
        Some(ref name) => state.scenarios.get(name),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                "Missing ?scenario= query parameter".to_string(),
            );
        }
    };

    let scenario = match scenario {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                HeaderMap::new(),
                format!(
                    "No scenario named '{}'. Available: {:?}",
                    query.scenario.as_deref().unwrap_or(""),
                    state.scenarios.keys().collect::<Vec<_>>(),
                ),
            );
        }
    };

    let status =
        StatusCode::from_u16(scenario.response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers = HeaderMap::new();
    if let Some(ref h) = scenario.response.headers {
        for (k, v) in h {
            let lower = k.to_lowercase();
            // Skip hop-by-hop headers — axum manages these
            if lower == "transfer-encoding" || lower == "content-length" {
                continue;
            }
            if let (Ok(name), Ok(val)) = (k.parse::<HeaderName>(), HeaderValue::from_str(v)) {
                headers.insert(name, val);
            }
        }
    }

    let resp_body = scenario.response.body.raw.trim().to_string();

    // For non-streaming responses, add content-length if not present
    let is_sse = scenario.response.headers.as_ref().map_or(false, |h| {
        h.iter()
            .any(|(k, v)| k == "content-type" && v.contains("text/event-stream"))
    });

    if !is_sse && !headers.contains_key("content-length") {
        if let Ok(val) = HeaderValue::from_str(&resp_body.len().to_string()) {
            headers.insert("content-length", val);
        }
    }

    (status, headers, resp_body)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Start the mock HTTPS server.
///
/// Returns the bound address and a handle. The server runs until the handle
/// is dropped or `shutdown()` is called.
pub async fn start_server(config: MockConfig) -> (SocketAddr, ServerHandle) {
    let loaded = scenario::load_scenarios(&config.scenarios_dir, None);
    let mut scenarios = HashMap::new();
    for (name, s) in loaded {
        scenarios.insert(name, s);
    }
    eprintln!(
        "agtap-mock: loaded {} scenarios from {}",
        scenarios.len(),
        config.scenarios_dir.display()
    );

    let state = Arc::new(AppState { scenarios });

    let app = Router::new()
        .route("/v1/messages", post(handle_messages))
        .route("/v1/chat/completions", post(handle_messages))
        .route("/mcp", post(handle_messages))
        .with_state(state);

    // Generate self-signed certificate
    let subject_alt_names = vec![
        "api.anthropic.com".to_string(),
        "api.openai.com".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let cert = generate_simple_self_signed(subject_alt_names)
        .expect("Failed to generate self-signed cert");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
    .await
    .expect("Failed to create TLS config");

    // Bind a TCP listener first to get the actual address (supports port 0)
    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    let listener = std::net::TcpListener::bind(addr).expect("Failed to bind TCP listener");
    let bound_addr = listener.local_addr().expect("Failed to get local addr");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();

    // Spawn the server task
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls_config)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .expect("Server error");
    });

    // Spawn a task to listen for shutdown signal
    tokio::spawn(async move {
        let _ = shutdown_rx.await;
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(1)));
    });

    // Give the server a moment to start accepting connections
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let server_handle = ServerHandle {
        shutdown_tx: Some(shutdown_tx),
        addr: bound_addr,
    };

    (bound_addr, server_handle)
}
