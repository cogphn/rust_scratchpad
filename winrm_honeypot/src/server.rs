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
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Largest request body we will buffer. WinRM command payloads are small; a
/// honeypot must not let a stranger decide how much memory it uses.
pub const MAX_BODY: usize = 256 * 1024;

/// What the server advertises about itself.
const SERVER_HEADER: &str = "Microsoft-HTTPAPI/2.0";

/// How long a server challenge stays usable. Tools send the Type 3 almost
/// immediately; anything older is a stray and must not be honoured.
const CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

pub struct PendingChallenge {
    pub bytes: [u8; 8],
    pub issued: Instant,
}

pub struct AppState {
    pub cfg: Arc<Config>,
    pub log: Arc<EventLog>,
    /// Server challenge per source IP. Keyed by IP, not by connection: most
    /// tooling opens a fresh TCP connection for each NTLM step.
    pub pending: Mutex<HashMap<IpAddr, PendingChallenge>>,
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

    // Record attempted commands before auth decides: an unauthenticated attempt
    // to run something is the most interesting event a honeypot can see.
    if let Some(cmd) = soap::extract_command(&String::from_utf8_lossy(&body)) {
        let ip = peer.to_string();
        let len = body.len().to_string();
        st.log.event(
            "command",
            &[
                ("ip", ip.as_str()),
                ("cmd", cmd.as_str()),
                ("auth", auth.unwrap_or("none")),
                ("len", len.as_str()),
            ],
        );
    }

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
        Some(value) if scheme_is(value, "negotiate") || scheme_is(value, "ntlm") => {
            on_negotiate(&st, peer, value, &body)
        }
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

/// NTLM over HTTP: Type 1 -> Type 2 challenge, Type 3 -> verify.
fn on_negotiate(st: &AppState, peer: SocketAddr, header_value: &str, body: &Bytes) -> Response {
    use base64::Engine;

    let ip = peer.to_string();
    let Some((scheme, token_b64)) = header_value
        .split_once(' ')
        .map(|(s, t)| (s.trim(), t.trim()))
    else {
        return challenge(st, None);
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token_b64) else {
        st.log.event(
            "auth",
            &[
                ("scheme", "negotiate"),
                ("ip", ip.as_str()),
                ("result", "bad_base64"),
            ],
        );
        return challenge(st, None);
    };

    let Some(msg) = crate::ntlm::find_message(&decoded) else {
        // Kerberos/other SPNEGO mechanisms have no NTLMSSP body.
        st.log.event(
            "auth",
            &[
                ("scheme", "negotiate"),
                ("ip", ip.as_str()),
                ("result", "non_ntlm_token"),
            ],
        );
        return challenge(st, None);
    };

    match crate::ntlm::message_type(msg) {
        Some(1) => {
            let challenge_bytes = crate::ntlm::random_challenge();
            let type2 = crate::ntlm::build_type2(
                &identity_for(&st.cfg),
                challenge_bytes,
                crate::ntlm::filetime_now(),
            );
            {
                let mut pending = st.pending.lock().unwrap_or_else(|e| e.into_inner());
                // Bound the map: hostile clients can otherwise grow it forever.
                pending.retain(|_, c| c.issued.elapsed() < CHALLENGE_TTL);
                pending.insert(
                    peer.ip(),
                    PendingChallenge {
                        bytes: challenge_bytes,
                        issued: Instant::now(),
                    },
                );
            }
            st.log.event(
                "auth",
                &[
                    ("scheme", "ntlm_type1"),
                    ("ip", ip.as_str()),
                    ("result", "challenge_sent"),
                ],
            );
            challenge(st, Some((scheme, type2.as_slice())))
        }
        Some(3) => on_authenticate(st, peer, msg, body),
        _ => {
            st.log.event(
                "auth",
                &[
                    ("scheme", "negotiate"),
                    ("ip", ip.as_str()),
                    ("result", "unsupported_message_type"),
                ],
            );
            challenge(st, None)
        }
    }
}

fn on_authenticate(st: &AppState, peer: SocketAddr, msg: &[u8], body: &Bytes) -> Response {
    let ip = peer.to_string();
    let Some(t3) = crate::ntlm::parse_type3(msg) else {
        st.log.event(
            "auth",
            &[
                ("scheme", "ntlm_type3"),
                ("ip", ip.as_str()),
                ("result", "malformed"),
            ],
        );
        return challenge(st, None);
    };

    let challenge_bytes = {
        let mut pending = st.pending.lock().unwrap_or_else(|e| e.into_inner());
        match pending.remove(&peer.ip()) {
            Some(c) if c.issued.elapsed() < CHALLENGE_TTL => Some(c.bytes),
            _ => None,
        }
    };

    let Some(challenge_bytes) = challenge_bytes else {
        log_type3(st, &ip, &t3, None, "no_challenge");
        return challenge(st, None);
    };

    let Some(cred) = st.cfg.find_credential(&t3.domain, &t3.user) else {
        log_type3(st, &ip, &t3, Some(&challenge_bytes), "unknown_user");
        return challenge(st, None);
    };

    // Hash the way the *client* did: with the user name and domain as sent.
    // Fall back to the configured domain spelling for clients that lower-case
    // it while the config has the canonical upper-case form.
    let ok = match &t3.v2 {
        Some(v2) => {
            let mut ok = crate::ntlm::verify_ntlmv2(
                &cred.password,
                &t3.user,
                &t3.domain,
                &challenge_bytes,
                v2,
            );
            if !ok {
                let configured = cred.domain_or(&st.cfg.identity.domain);
                ok = crate::ntlm::verify_ntlmv2(
                    &cred.password,
                    &t3.user,
                    configured,
                    &challenge_bytes,
                    v2,
                );
            }
            ok
        }
        None => false,
    };

    log_type3(
        st,
        &ip,
        &t3,
        Some(&challenge_bytes),
        if ok { "ok" } else { "denied" },
    );

    if ok {
        authenticated_exchange(st, body)
    } else {
        challenge(st, None)
    }
}

fn log_type3(
    st: &AppState,
    ip: &str,
    t3: &crate::ntlm::Type3,
    challenge_bytes: Option<&[u8; 8]>,
    result: &str,
) {
    let flags = format!("0x{:08x}", t3.flags);
    let mut fields: Vec<(&str, String)> = vec![
        ("scheme", "ntlm_type3".into()),
        ("ip", ip.into()),
        ("domain", t3.domain.clone()),
        ("user", t3.user.clone()),
        ("workstation", t3.workstation.clone()),
        ("flags", flags),
        ("result", result.into()),
    ];

    match (&t3.v2, challenge_bytes) {
        (Some(v2), Some(ch)) => {
            fields.push((
                "ntlmv2",
                crate::ntlm::netntlmv2_line(&t3.user, &t3.domain, ch, v2),
            ));
        }
        (Some(v2), None) => {
            fields.push(("ntproofstr", crate::ntlm::hex(&v2.proof)));
            fields.push(("blob", crate::ntlm::hex(&v2.blob)));
        }
        (None, _) => {
            fields.push(("response", "non_ntlmv2".into()));
        }
    }

    let refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    st.log.event("auth", &refs);
}

fn identity_for(cfg: &Config) -> crate::ntlm::ServerIdentity<'_> {
    crate::ntlm::ServerIdentity {
        netbios_name: &cfg.identity.computer_name,
        domain: &cfg.identity.domain,
        dns_host: &cfg.identity.dns_domain,
        dns_domain: &cfg.identity.dns_domain,
        version: crate::config::parse_os_version(&cfg.identity.os_version)
            .unwrap_or((10, 0, 20348)),
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

/// 401 that either continues an NTLM handshake or advertises what we accept.
///
/// `ntlm` carries the scheme the client actually used plus the Type 2 message.
/// The reply must repeat *that* scheme: a client that sent `Authorization:
/// NTLM ...` ignores a `WWW-Authenticate: Negotiate ...` challenge and starts
/// over (curl does exactly this), while Windows clients expect `Negotiate`.
pub fn challenge(st: &AppState, ntlm: Option<(&str, &[u8])>) -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;

    let mut advertised: Vec<String> = Vec::new();

    if let Some((scheme, msg)) = ntlm {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(msg);
        advertised.push(scheme.to_ascii_lowercase());
        append_challenge(&mut resp, format!("{scheme} {b64}"));
    }

    for scheme in &st.cfg.server.schemes {
        let value = match scheme {
            crate::config::Scheme::Negotiate => {
                if advertised.iter().any(|s| s == "negotiate") {
                    continue;
                }
                "Negotiate".to_string()
            }
            crate::config::Scheme::Basic => {
                if advertised.iter().any(|s| s == "basic") {
                    continue;
                }
                "Basic realm=\"WSMAN\"".to_string()
            }
        };
        advertised.push(value.to_ascii_lowercase());
        append_challenge(&mut resp, value);
    }

    resp
}

fn append_challenge(resp: &mut Response, value: String) {
    if let Ok(v) = HeaderValue::from_str(&value) {
        resp.headers_mut().append(header::WWW_AUTHENTICATE, v);
    }
}

/// Binds, logs the startup line and serves until Ctrl+C. Returns the address
/// that was actually bound (tests use port 0).
pub async fn serve(cfg: Config, log: Arc<EventLog>) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = cfg.server.listen.parse()?;
    let state = Arc::new(AppState {
        cfg: Arc::new(cfg),
        log: log.clone(),
        pending: Mutex::new(HashMap::new()),
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
