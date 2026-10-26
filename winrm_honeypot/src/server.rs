//! HTTP/WS-Management surface: one endpoint (`POST /wsman`) that challenges
//! unauthenticated clients exactly like IIS/WinRM does.

use crate::config::Config;
use crate::logging::EventLog;
use crate::soap;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
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
async fn wsman_handler(
    State(st): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth {
        None => challenge(&st, None),
        Some(value) if scheme_is(value, "basic") => match parse_basic(value) {
            Some(basic) => on_basic(&st, peer, basic, &body),
            None => {
                let ip = peer.to_string();
                st.log.event(
                    "auth",
                    &[
                        ("scheme", "basic"),
                        ("ip", ip.as_str()),
                        ("raw", value),
                        ("result", "malformed"),
                    ],
                );
                bad_request("malformed Basic credentials")
            }
        },
        // Negotiate/NTLM arrives in the next phase; anything else is refused.
        Some(_) => challenge(&st, None),
    }
}

fn scheme_is(header_value: &str, scheme: &str) -> bool {
    header_value
        .split_once(' ')
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Credentials decoded out of `Authorization: Basic base64([DOMAIN]user:pass)`.
#[derive(Debug)]
pub struct BasicOutcome {
    pub domain: String,
    pub user: String,
    pub password: String,
}

/// Accepts `user:pass`, `DOMAIN\user:pass` and `user@domain:pass`. Only the
/// first colon separates user from password, so passwords may contain colons.
pub fn parse_basic(header_value: &str) -> Option<BasicOutcome> {
    use base64::Engine;
    let (_, b64) = header_value.split_once(' ')?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8_lossy(&raw);
    let (ident, password) = text.split_once(':')?;

    let (domain, user) = if let Some((d, u)) = ident.split_once('\\') {
        (d.to_string(), u.to_string())
    } else if let Some((u, d)) = ident.split_once('@') {
        (d.to_string(), u.to_string())
    } else {
        (String::new(), ident.to_string())
    };

    Some(BasicOutcome {
        domain,
        user,
        password: password.to_string(),
    })
}

fn on_basic(st: &AppState, peer: SocketAddr, b: BasicOutcome, body: &Bytes) -> Response {
    let ip = peer.to_string();
    // A bare `user` authenticates against the identity domain, like a local
    // account on the machine the honeypot claims to be.
    let domain = if b.domain.is_empty() {
        st.cfg.identity.domain.clone()
    } else {
        b.domain.clone()
    };

    let matched = st
        .cfg
        .find_credential(&domain, &b.user)
        .is_some_and(|c| c.password == b.password);

    st.log.event(
        "auth",
        &[
            ("scheme", "basic"),
            ("ip", ip.as_str()),
            ("domain", domain.as_str()),
            ("user", b.user.as_str()),
            // The whole point of the honeypot: record what was tried.
            ("password", b.password.as_str()),
            ("result", if matched { "ok" } else { "denied" }),
        ],
    );

    if matched {
        authenticated_exchange(st, body)
    } else {
        challenge(st, None)
    }
}

fn bad_request(why: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::from(soap::fault(why)));
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/soap+xml;charset=UTF-8"),
    );
    resp
}

/// Behaviour once credentials are accepted: `Identify` is answered, everything
/// else is a fault. Nothing is ever executed.
fn authenticated_exchange(st: &AppState, body: &Bytes) -> Response {
    if body.is_empty() {
        return bad_request("empty request body");
    }
    let text = String::from_utf8_lossy(body);
    if text.contains("Identify") {
        let mut resp = Response::new(axum::body::Body::from(soap::identify_response(
            &st.cfg.identity,
        )));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/soap+xml;charset=UTF-8"),
        );
        return resp;
    }
    let mut resp = Response::new(axum::body::Body::from(soap::fault(
        "The WS-Management service cannot process the request.",
    )));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/soap+xml;charset=UTF-8"),
    );
    resp
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
