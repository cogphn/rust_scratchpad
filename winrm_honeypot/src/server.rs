//! HTTP/WS-Management surface: one endpoint (`POST /wsman`) that challenges
//! unauthenticated clients exactly like IIS/WinRM does.

use crate::config::Config;
use crate::logging::EventLog;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::post;
use std::net::SocketAddr;
use std::sync::Arc;

/// Largest request body we will buffer. WinRM command payloads are small; a
/// honeypot must not let a stranger decide how much memory it uses.
pub const MAX_BODY: usize = 256 * 1024;

/// What the server advertises about itself.
const SERVER_HEADER: &str = "Microsoft-HTTPAPI/2.0";

pub struct AppState {
    pub cfg: Arc<Config>,
    pub log: Arc<EventLog>,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/wsman", post(wsman_handler))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(axum::middleware::map_response(add_server_header))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            log_every_request,
        ))
        .with_state(state)
}

/// Scanners and `nxc` look for this header; hyper lowercases header *names*
/// (HTTP treats them case-insensitively) but the value is what is checked.
async fn add_server_header(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::SERVER, HeaderValue::from_static(SERVER_HEADER));
    resp
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// Logs *every* request, including the ones no handler will see (a `GET
/// /wsman` probe, a request to a random path). "Record all attempted
/// activity" would otherwise miss exactly the cheapest reconnaissance.
async fn log_every_request(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = peer.to_string();
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let len = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none")
        .to_string();

    st.log.event(
        "request",
        &[
            ("ip", ip.as_str()),
            ("method", method.as_str()),
            ("path", path.as_str()),
            ("len", len.as_str()),
            ("ua", ua.as_str()),
            ("auth", auth.as_str()),
        ],
    );

    next.run(req).await
}

// The `Bytes` argument is what enforces `MAX_BODY`; keep it last (it is the
// only body-consuming extractor).
async fn wsman_handler(State(st): State<Arc<AppState>>, _body: Bytes) -> Response {
    challenge(&st, None)
}

/// 401 with one `WWW-Authenticate` header per configured scheme, in config
/// order. `ntlm_type2` carries the NTLM challenge once negotiation is underway.
pub fn challenge(st: &AppState, ntlm_type2: Option<&[u8]>) -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;

    for scheme in &st.cfg.server.schemes {
        let value = match scheme {
            crate::config::Scheme::Negotiate => match ntlm_type2 {
                Some(msg) => format!("Negotiate {}", {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(msg)
                }),
                None => "Negotiate".to_string(),
            },
            crate::config::Scheme::Basic => "Basic realm=\"WSMAN\"".to_string(),
        };
        if let Ok(v) = HeaderValue::from_str(&value) {
            resp.headers_mut().append(header::WWW_AUTHENTICATE, v);
        }
    }
    resp
}

/// Binds, logs the startup line and serves until Ctrl+C. Returns the address
/// that was actually bound (tests use port 0).
pub async fn serve(cfg: Config, log: Arc<EventLog>) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = cfg.server.listen.parse()?;
    let state = Arc::new(AppState {
        cfg: Arc::new(cfg),
        log: log.clone(),
    });

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot bind {addr}: {e}. If this host runs real WinRM, that port is already taken."
        )
    })?;
    let bound = listener.local_addr()?;

    log.event(
        "startup",
        &[
            ("listen", &bound.to_string()),
            ("computer", &state.cfg.identity.computer_name),
            ("domain", &state.cfg.identity.domain),
            ("credentials", &state.cfg.credentials.len().to_string()),
        ],
    );

    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    Ok(bound)
}
