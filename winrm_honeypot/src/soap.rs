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
}
