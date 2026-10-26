mod common;

const IDENTIFY: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>"#;

/// What evil-winrm / pypsrp send when they try to run something.
const COMMAND_LINE: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/><s:Body><rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:Command>whoami /priv</rsp:Command></rsp:CommandLine></s:Body></s:Envelope>"#;

fn soap_post(body: &str, auth: Option<&str>) -> String {
    format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\n{}Content-Type: application/soap+xml;charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        auth.unwrap_or(""),
        body.len(),
        body
    )
}

#[tokio::test]
async fn identify_returns_microsoft_product_info() {
    let (addr, _dir) = common::start().await;
    let resp = common::raw(
        addr,
        &soap_post(
            IDENTIFY,
            Some(&common::basic_authorization(
                "CORP\\Administrator:Summer2026!",
            )),
        ),
    )
    .await;

    assert!(common::status_line(&resp).contains("200"), "{resp}");
    assert!(resp.contains("<wsmid:IdentifyResponse>"), "{resp}");
    assert!(resp.contains("Microsoft Corporation"), "{resp}");
    assert!(resp.contains("OS: 10.0.20348"), "{resp}");
    assert!(
        common::header_values(&resp, "content-type")
            .iter()
            .any(|v| v.starts_with("application/soap+xml")),
        "{resp}"
    );
}

#[tokio::test]
async fn unknown_soap_action_faults_and_records_the_command() {
    let (addr, dir) = common::start().await;
    let resp = common::raw(
        addr,
        &soap_post(
            COMMAND_LINE,
            Some(&common::basic_authorization(
                "CORP\\Administrator:Summer2026!",
            )),
        ),
    )
    .await;

    assert!(common::status_line(&resp).contains("500"), "{resp}");
    assert!(resp.contains("<s:Fault>"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("event=command"), "{log}");
    assert!(log.contains("cmd=\"whoami /priv\""), "{log}");
}

#[tokio::test]
async fn authorised_command_attempts_are_logged_even_when_auth_fails() {
    let (addr, dir) = common::start().await;
    let resp = common::raw(addr, &soap_post(COMMAND_LINE, None)).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");

    let log = common::read_log(&dir);
    assert!(
        log.contains("event=command"),
        "unauthenticated attempt not recorded:\n{log}"
    );
    assert!(log.contains("cmd=\"whoami /priv\""), "{log}");
}

#[tokio::test]
async fn xml_entities_are_never_expanded() {
    let (addr, dir) = common::start().await;
    // Billion laughs: a parser that expands entities hangs or dies here.
    let evil = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:Command>&lol9;</rsp:Command></rsp:CommandLine></s:Body></s:Envelope>"#;

    let request = soap_post(
        evil,
        Some(&common::basic_authorization(
            "CORP\\Administrator:Summer2026!",
        )),
    );
    let call = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        common::raw(addr, &request),
    );
    let resp = call
        .await
        .expect("server must answer promptly: no entity expansion");
    assert!(common::status_line(&resp).contains("500"), "{resp}");

    let log = common::read_log(&dir);
    // The literal text is recorded; nothing was substituted.
    assert!(log.contains("&lol9;"), "{log}");
}
