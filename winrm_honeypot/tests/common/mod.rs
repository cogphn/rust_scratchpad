#![allow(dead_code)] // each test binary uses a different subset of these helpers

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use winrm_honeypot::config::Config;
use winrm_honeypot::logging::EventLog;
use winrm_honeypot::server::{AppState, router};

/// Sends a raw request (CRLF already included) and returns the raw response.
///
/// A server may answer and close before a large body has finished uploading
/// (413 Payload Too Large does exactly that), so a failed write is not treated
/// as a test failure: the response is what the caller asserts on.
pub async fn raw(addr: SocketAddr, request: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let _ = stream.write_all(request.as_bytes()).await;
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).to_string()
}

pub fn status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

pub fn header_values(resp: &str, name: &str) -> Vec<String> {
    let name = format!("{}:", name.to_lowercase());
    resp.lines()
        .take_while(|l| !l.is_empty())
        .filter(|l| l.to_lowercase().starts_with(&name))
        .map(|l| l[name.len()..].trim().to_string())
        .collect()
}

/// Spawns a server on an ephemeral port. Returns the bound address and the
/// temp dir holding the event log (keep it alive for the duration of the test).
pub async fn start() -> (SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::from_toml_str(
        r#"
        [[credentials]]
        domain = "CORP"
        username = "Administrator"
        password = "Summer2026!"
        "#,
    )
    .unwrap();
    cfg.server.listen = "127.0.0.1:0".to_string();
    cfg.log.path = dir.path().join("events.log").to_str().unwrap().to_string();

    let log = Arc::new(EventLog::open(&cfg.log.path).unwrap());
    let state = Arc::new(AppState {
        cfg: Arc::new(cfg),
        log,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, dir)
}

pub fn read_log(dir: &tempfile::TempDir) -> String {
    std::fs::read_to_string(dir.path().join("events.log")).unwrap_or_default()
}
