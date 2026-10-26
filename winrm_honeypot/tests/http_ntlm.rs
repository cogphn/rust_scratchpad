mod common;

use base64::Engine;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Minimal NTLMSSP_NEGOTIATE (Type 1): signature, type, flags, empty secbufs.
fn type1() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&0x0008_8205u32.to_le_bytes());
    m.extend_from_slice(&[0u8; 16]); // domain/workstation secbufs
    m.extend_from_slice(&[0u8; 8]); // version
    m
}

fn post_with_token(token: &[u8]) -> String {
    format!(
        "POST /wsman HTTP/1.1\r\nHost: x\r\nAuthorization: Negotiate {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        b64(token)
    )
}

fn type2_from(resp: &str) -> Vec<u8> {
    let header = common::header_values(resp, "www-authenticate")
        .into_iter()
        .find(|v| v.starts_with("Negotiate "))
        .unwrap_or_else(|| panic!("no Type 2 challenge in:\n{resp}"));
    base64::engine::general_purpose::STANDARD
        .decode(header.trim_start_matches("Negotiate "))
        .expect("valid base64")
}

fn server_challenge(type2: &[u8]) -> [u8; 8] {
    let mut ch = [0u8; 8];
    ch.copy_from_slice(&type2[24..32]);
    ch
}

#[tokio::test]
async fn type1_gets_a_type2_challenge() {
    let (addr, _dir) = common::start().await;
    let resp = common::raw(addr, &post_with_token(&type1())).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");

    let type2 = type2_from(&resp);
    assert_eq!(&type2[0..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(type2[8..12].try_into().unwrap()), 2);

    // NetExec fingerprints the host from the Type 2 TargetInfo.
    let needle: Vec<u8> = "WIN-SRV01"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert!(
        type2.windows(needle.len()).any(|w| w == needle),
        "Type 2 is missing NbComputerName"
    );
}

#[tokio::test]
async fn correct_ntlm_password_is_accepted_and_hashed_to_the_log() {
    let (addr, dir) = common::start().await;

    let type2 = type2_from(&common::raw(addr, &post_with_token(&type1())).await);
    let challenge = server_challenge(&type2);

    let type3 = winrm_honeypot::ntlm::tests_support::synth_type3(
        "CORP",
        "Administrator",
        "WS01",
        challenge,
        "Summer2026!",
    );
    let resp = common::raw(addr, &post_with_token(&type3)).await;
    assert!(!common::status_line(&resp).contains("401"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("scheme=ntlm_type3"), "{log}");
    assert!(log.contains("result=ok"), "{log}");
    assert!(log.contains("user=Administrator"), "{log}");
    assert!(log.contains("workstation=WS01"), "{log}");

    let line = log
        .lines()
        .find(|l| l.contains("ntlmv2="))
        .unwrap_or_else(|| panic!("no hashcat line in:\n{log}"));
    let hash = line.split("ntlmv2=").nth(1).unwrap().trim();
    // USER::DOMAIN:challenge:NTProofStr:blob
    let parts: Vec<&str> = hash.split(':').collect();
    assert_eq!(parts.len(), 6, "{hash}");
    assert_eq!(parts[0], "Administrator");
    assert_eq!(parts[2], "CORP");
    assert_eq!(parts[3].len(), 16, "challenge is 8 bytes of hex");
}

#[tokio::test]
async fn wrong_ntlm_password_is_challenged_but_hashed() {
    let (addr, dir) = common::start().await;

    let type2 = type2_from(&common::raw(addr, &post_with_token(&type1())).await);
    let type3 = winrm_honeypot::ntlm::tests_support::synth_type3(
        "CORP",
        "Administrator",
        "WS01",
        server_challenge(&type2),
        "nope",
    );
    let resp = common::raw(addr, &post_with_token(&type3)).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");

    let log = common::read_log(&dir);
    assert!(log.contains("result=denied"), "{log}");
    assert!(log.contains("ntlmv2="), "{log}");
}

#[tokio::test]
async fn type3_without_a_prior_challenge_is_refused() {
    let (addr, dir) = common::start().await;

    // No Type 1 first: there is no server challenge to verify against.
    let type3 = winrm_honeypot::ntlm::tests_support::synth_type3(
        "CORP",
        "Administrator",
        "WS01",
        [9u8; 8],
        "Summer2026!",
    );
    let resp = common::raw(addr, &post_with_token(&type3)).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");
    assert!(common::read_log(&dir).contains("result=no_challenge"));
}

#[tokio::test]
async fn kerberos_style_token_is_logged_and_refused() {
    let (addr, dir) = common::start().await;
    // SPNEGO-ish blob with no NTLMSSP signature.
    let resp = common::raw(addr, &post_with_token(&[0x60, 0x1e, 0x06, 0x06, 0x2b])).await;
    assert!(common::status_line(&resp).contains("401"), "{resp}");
    assert!(common::read_log(&dir).contains("result=non_ntlm_token"));
}
