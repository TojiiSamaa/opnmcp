//! HTTP « streamable » sans session : chaque requête a son propre serveur MCP au-dessus du runtime, qui
//! porte les clients du pare-feu et les changements en attente. Sans session il n'y a personne à interroger :
//! l'elicitation ne s'applique pas, le client doit se fier à l'annotation « destructif » des outils.

use crate::error::{ErrorType, OpnError, Result};
use crate::server::{Registry, Session};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

pub struct HttpOptions {
    pub host: String,
    pub port: u16,
    /// Jeton Bearer. Obligatoire sauf si le serveur n'écoute que sur la boucle locale.
    pub token: Option<String>,
    /// Valeurs acceptées en plus dans l'en-tête Host, derrière un proxy inverse.
    pub allowed_hosts: Vec<String>,
}

pub fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn token_matches(header: Option<&str>, token: &str) -> bool {
    let given = header.unwrap_or("").as_bytes();
    let wanted = format!("Bearer {token}");
    let wanted = wanted.as_bytes();
    // Comparaison en temps constant sur la longueur attendue.
    let mut diff = (given.len() ^ wanted.len()) as u8;
    for (i, w) in wanted.iter().enumerate() {
        diff |= given.get(i).copied().unwrap_or(0) ^ w;
    }
    diff == 0
}

struct AppState {
    registry: Arc<Registry>,
    token: Option<String>,
    allowed: HashSet<String>,
}

fn deny(status: StatusCode, message: &str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], json!({ "error": message }).to_string()).into_response()
}

async fn handle(State(state): State<Arc<AppState>>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    // Une page web peut faire appeler une adresse locale par un navigateur : vérifier Host arrête le DNS rebinding.
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !state.allowed.contains(host) {
        return deny(StatusCode::FORBIDDEN, "Host not allowed. See OPNSENSE_MCP_ALLOWED_HOSTS.");
    }
    if let Some(token) = &state.token {
        if !token_matches(headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()), token) {
            return deny(StatusCode::UNAUTHORIZED, "Invalid or missing bearer token.");
        }
    }
    if uri.path() != "/mcp" {
        return deny(StatusCode::NOT_FOUND, "Not found. The endpoint is /mcp.");
    }
    if method != Method::POST {
        return deny(StatusCode::METHOD_NOT_ALLOWED, "This server keeps no session: only POST is supported.");
    }
    let Ok(message) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "application/json")], json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "Parse error" } }).to_string()).into_response();
    };
    let session = Session::new(state.registry.clone(), None);
    let reply = match message {
        Value::Array(batch) => {
            let replies: Vec<Value> = futures::future::join_all(batch.into_iter().map(|m| session.handle(m))).await.into_iter().flatten().collect();
            (!replies.is_empty()).then_some(Value::Array(replies))
        }
        single => session.handle(single).await,
    };
    session.close();
    match reply {
        Some(r) => ([(header::CONTENT_TYPE, "application/json")], r.to_string()).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

pub async fn serve(registry: Arc<Registry>, options: HttpOptions) -> Result<()> {
    let HttpOptions { host, port, token, allowed_hosts } = options;
    if token.is_none() && !is_loopback(&host) {
        return Err(OpnError::new(ErrorType::ConfigError, format!("Refusing to listen on {host} without a token: anyone on the network could drive the firewall.")).hint("Set OPNSENSE_MCP_TOKEN, or listen on 127.0.0.1."));
    }
    let listener = tokio::net::TcpListener::bind((host.as_str(), port)).await.map_err(|e| OpnError::new(ErrorType::ConfigError, format!("Cannot listen on {host}:{port}: {e}")))?;
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    let shown = if host.contains(':') { format!("[{host}]") } else { host.clone() };
    let mut allowed: HashSet<String> = allowed_hosts.into_iter().collect();
    for name in [shown.as_str(), "localhost", "127.0.0.1", "[::1]"] {
        if name == shown || is_loopback(&host) {
            allowed.insert(format!("{name}:{bound}"));
        }
    }
    eprintln!("[osmcp] listening on http://{shown}:{bound}/mcp");
    let app = Router::new().fallback(handle).with_state(Arc::new(AppState { registry, token, allowed }));
    axum::serve(listener, app).await.map_err(|e| OpnError::new(ErrorType::InternalError, format!("HTTP server stopped: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison() {
        assert!(token_matches(Some("Bearer abc"), "abc"));
        assert!(!token_matches(Some("Bearer abd"), "abc"));
        assert!(!token_matches(Some("Bearer abcd"), "abc"));
        assert!(!token_matches(None, "abc"));
    }

    #[test]
    fn loopback() {
        assert!(is_loopback("127.0.0.1") && is_loopback("::1") && is_loopback("localhost"));
        assert!(!is_loopback("0.0.0.0") && !is_loopback("10.0.0.1"));
    }
}
