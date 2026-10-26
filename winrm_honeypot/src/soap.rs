//! Minimal WS-Management SOAP envelopes.
//!
//! Everything here is string-built on purpose: no XML parser means no entity
//! expansion, no XXE, and nothing to exploit on the honeypot itself.

use crate::config::Identity;

/// The reply a real server gives to `wsmid:Identify` (what `Test-WSMan` reads).
pub fn identify_response(id: &Identity) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:IdentifyResponse><wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion><wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor><wsmid:ProductVersion>OS: {} SP: 0.0 Stack: 3.0</wsmid:ProductVersion></wsmid:IdentifyResponse></s:Body></s:Envelope>"#,
        escape_xml(&id.os_version)
    )
}

/// A SOAP fault that looks like a WS-Management rejection.
pub fn fault(reason: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"><s:Header/><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">{}</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#,
        escape_xml(reason)
    )
}

/// Escapes for XML text content. `&` must be replaced first or the later
/// replacements get double-escaped.
pub fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Best-effort extraction of the command a WS-Man `CommandLine` request wants to
/// run, for logging.
///
/// Deliberately string-based: no XML parser means no XXE, no entity expansion
/// and no billion-laughs, and the literal text is what gets recorded.
pub fn extract_command(body: &str) -> Option<String> {
    for tag in ["Command", "Arguments"] {
        if let Some(value) = extract_element(body, tag) {
            return Some(value);
        }
    }
    None
}

/// Finds `<prefix:tag ...>text</prefix:tag>` for any namespace prefix.
fn extract_element(body: &str, tag: &str) -> Option<String> {
    let needle = format!(":{tag}");
    let mut from = 0usize;

    while let Some(rel) = body[from..].find(&needle) {
        let at = from + rel;
        let after = body.get(at + needle.len()..)?;
        // Must be the whole local name: reject `<rsp:CommandLine ...>`.
        let first = after.chars().next()?;
        if first != '>' && !first.is_whitespace() {
            from = at + needle.len();
            continue;
        }

        let open_start = body[..at].rfind('<')?;
        let qname = &body[open_start + 1..at + needle.len()];
        let gt = body[at + needle.len()..].find('>')? + at + needle.len();
        let close = format!("</{qname}>");
        let content_start = gt + 1;
        let end = body[content_start..].find(&close)? + content_start;
        return Some(unescape_xml(&body[content_start..end]));
    }
    None
}

/// Reverses [`escape_xml`] for the five predefined entities. `&amp;` last so
/// `&amp;lt;` decodes to `&lt;` rather than `<`.
pub fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            computer_name: "WIN-SRV01".to_string(),
            domain: "CORP".to_string(),
            dns_domain: "corp.local".to_string(),
            os_version: "10.0.20348".to_string(),
        }
    }

    #[test]
    fn identify_reports_microsoft_product_info() {
        let xml = identify_response(&identity());
        assert!(xml.contains("<wsmid:IdentifyResponse>"), "{xml}");
        assert!(xml.contains("Microsoft Corporation"), "{xml}");
        assert!(xml.contains("OS: 10.0.20348 SP: 0.0 Stack: 3.0"), "{xml}");
        assert!(xml.starts_with("<s:Envelope"), "{xml}");
    }

    #[test]
    fn identify_escapes_the_version_string() {
        let mut id = identity();
        id.os_version = "<script>".to_string();
        let xml = identify_response(&id);
        assert!(xml.contains("&lt;script&gt;"), "{xml}");
        assert!(!xml.contains("<script>"), "{xml}");
    }

    #[test]
    fn fault_escapes_reason_and_has_a_sender_code() {
        let xml = fault("<script>");
        assert!(xml.contains("&lt;script&gt;"), "{xml}");
        assert!(xml.contains("s:Sender"), "{xml}");
        assert!(xml.contains("<s:Fault>"), "{xml}");
    }

    #[test]
    fn escape_xml_does_not_double_escape_ampersands() {
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml("<a & b>"), "&lt;a &amp; b&gt;");
    }

    #[test]
    fn extracts_a_command_from_the_rsp_namespace() {
        let body = r#"<rsp:CommandLine><rsp:Command>whoami /all</rsp:Command></rsp:CommandLine>"#;
        assert_eq!(extract_command(body).as_deref(), Some("whoami /all"));
    }

    #[test]
    fn extracts_from_any_namespace_prefix() {
        let body =
            r#"<p:CommandLine xmlns:p="urn:x"><p:Command>ipconfig</p:Command></p:CommandLine>"#;
        assert_eq!(extract_command(body).as_deref(), Some("ipconfig"));
    }

    #[test]
    fn handles_attributes_on_the_command_tag() {
        let body = r#"<rsp:Command xmlns:rsp="urn:x">net user</rsp:Command>"#;
        assert_eq!(extract_command(body).as_deref(), Some("net user"));
    }

    #[test]
    fn extracts_entity_escaped_commands() {
        let body = r#"<rsp:Command>cmd /c echo &lt;hi&gt;</rsp:Command>"#;
        assert_eq!(extract_command(body).as_deref(), Some("cmd /c echo <hi>"));
    }

    #[test]
    fn does_not_confuse_commandline_with_command() {
        let body = r#"<rsp:CommandLine><rsp:Command>whoami</rsp:Command></rsp:CommandLine>"#;
        assert_eq!(extract_command(body).as_deref(), Some("whoami"));
    }

    #[test]
    fn returns_none_when_there_is_no_command() {
        assert_eq!(extract_command("<s:Envelope/>"), None);
        assert_eq!(extract_command(""), None);
    }

    /// A billion-laughs payload is recorded literally: nothing is expanded.
    #[test]
    fn entities_are_never_expanded() {
        let body = r#"<rsp:Command>&lol9;</rsp:Command>"#;
        assert_eq!(extract_command(body).as_deref(), Some("&lol9;"));
    }
}
