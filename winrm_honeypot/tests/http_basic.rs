mod common;

#[tokio::test]
async fn correct_password_is_not_challenged_again() {
    let (addr, dir) = common::start().await;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        common::basic_authorization("CORP\\Administrator:Summer2026!")
    );
    let resp = common::raw(addr, &req).await;
    assert!(!common::status_line(&resp).contains("401"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("scheme=basic"), "{log}");
    assert!(log.contains("result=ok"), "{log}");
    assert!(log.contains("user=Administrator"), "{log}");
}

#[tokio::test]
async fn wrong_password_is_challenged_and_logged() {
    let (addr, dir) = common::start().await;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        common::basic_authorization("CORP\\Administrator:wrong")
    );
    let resp = common::raw(addr, &req).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("result=denied"), "{log}");
    assert!(log.contains("password=wrong"), "{log}");
}

#[tokio::test]
async fn unknown_user_is_challenged_but_recorded() {
    let (addr, dir) = common::start().await;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        common::basic_authorization("CORP\\ghost:whatever")
    );
    let resp = common::raw(addr, &req).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");
    assert!(
        common::read_log(&dir).contains("user=ghost"),
        "{}",
        common::read_log(&dir)
    );
}

#[tokio::test]
async fn malformed_base64_is_400_and_logged() {
    let (addr, dir) = common::start().await;
    let resp = common::raw(
        addr,
        "POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Basic !!!not-base64!!!\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(common::status_line(&resp).contains("400"), "{resp}");
    assert!(
        common::read_log(&dir).contains("result=malformed"),
        "{}",
        common::read_log(&dir)
    );
}

#[tokio::test]
async fn password_may_contain_colons() {
    let (addr, dir) = common::start_with_password("pa:ss:word").await;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        common::basic_authorization("CORP\\Administrator:pa:ss:word")
    );
    let resp = common::raw(addr, &req).await;
    assert!(!common::status_line(&resp).contains("401"), "{resp}");
    assert!(
        common::read_log(&dir).contains("result=ok"),
        "{}",
        common::read_log(&dir)
    );
}

#[tokio::test]
async fn upn_style_user_is_accepted() {
    let (addr, dir) = common::start().await;
    let req = format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Length: 0\r\nConnection: close\r\n\r\n",
        common::basic_authorization("Administrator@CORP:Summer2026!")
    );
    let resp = common::raw(addr, &req).await;
    assert!(!common::status_line(&resp).contains("401"), "{resp}");
    assert!(
        common::read_log(&dir).contains("result=ok"),
        "{}",
        common::read_log(&dir)
    );
}
