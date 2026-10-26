mod common;

#[tokio::test]
async fn unauth_post_wsman_returns_401_with_both_schemes() {
    let (addr, _dir) = common::start().await;
    let resp = common::raw(
        addr,
        "POST /wsman HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    assert!(common::status_line(&resp).contains("401"), "{resp}");
    let schemes = common::header_values(&resp, "www-authenticate");
    assert_eq!(schemes.len(), 2, "{resp}");
    assert_eq!(schemes[0], "Negotiate");
    assert_eq!(schemes[1], "Basic realm=\"WSMAN\"");
    assert_eq!(
        common::header_values(&resp, "server"),
        vec!["Microsoft-HTTPAPI/2.0"]
    );
}

#[tokio::test]
async fn unknown_path_is_404_and_get_wsman_is_405() {
    let (addr, _dir) = common::start().await;

    let a = common::raw(
        addr,
        "GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(common::status_line(&a).contains("404"), "{a}");

    let b = common::raw(
        addr,
        "GET /wsman HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(common::status_line(&b).contains("405"), "{b}");
}

#[tokio::test]
async fn request_is_logged_with_source_ip() {
    let (addr, dir) = common::start().await;
    let _ = common::raw(
        addr,
        "POST /wsman HTTP/1.1\r\nHost: x\r\nUser-Agent: NetExec\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;

    let log = common::read_log(&dir);
    assert!(log.contains("event=request"), "{log}");
    assert!(log.contains("ip=127.0.0.1:"), "{log}");
    assert!(log.contains("ua=NetExec"), "{log}");
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let (addr, _dir) = common::start().await;
    let big = "A".repeat(300 * 1024);
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{big}",
        big.len()
    );
    let resp = common::raw(addr, &req).await;
    assert!(
        common::status_line(&resp).contains("413") || common::status_line(&resp).contains("400"),
        "{resp}"
    );
}

/// A scanner's cheapest move is `GET /wsman`. Nothing routes it, so it must be
/// logged by the middleware, not the handler.
#[tokio::test]
async fn unrouted_probe_is_also_logged() {
    let (addr, dir) = common::start().await;
    let resp = common::raw(
        addr,
        "GET /wsman HTTP/1.1\r\nHost: x\r\nUser-Agent: scanner/1.0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(common::status_line(&resp).contains("405"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("method=GET"), "{log}");
    assert!(log.contains("path=/wsman"), "{log}");
    assert!(log.contains("ua=scanner/1.0"), "{log}");
}

/// Real IIS answers 411 when a POST declares neither Content-Length nor
/// chunking; a scanner comparing us against a genuine server expects that.
#[tokio::test]
async fn post_without_a_length_is_411_like_iis() {
    let (addr, _dir) = common::start().await;
    let resp = common::raw(
        addr,
        "POST /wsman HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(common::status_line(&resp).contains("411"), "{resp}");
}
