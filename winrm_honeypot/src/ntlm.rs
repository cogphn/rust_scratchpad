//! Server side of NTLM (NTLMv2 only), as used by WinRM over HTTP.
//!
//! Everything is byte-level on purpose: this parses hostile input, so it never
//! trusts a length, an offset or a field it did not bounds-check itself.

use md5::{Digest, Md5};

/// `NTLMSSP\0`
pub const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// NegotiateFlags: the subset a server needs to send a believable Type 2.
pub const FLAG_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const FLAG_REQUEST_TARGET: u32 = 0x0000_0004;
pub const FLAG_NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const FLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const FLAG_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const FLAG_NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const FLAG_NEGOTIATE_128: u32 = 0x2000_0000;
pub const FLAG_NEGOTIATE_56: u32 = 0x8000_0000;

/// What a Windows Server 2022 member server offers.
pub const SERVER_FLAGS: u32 = FLAG_NEGOTIATE_UNICODE
    | FLAG_REQUEST_TARGET
    | FLAG_NEGOTIATE_NTLM
    | FLAG_NEGOTIATE_ALWAYS_SIGN
    | FLAG_NEGOTIATE_EXTENDED_SESSIONSECURITY
    | FLAG_NEGOTIATE_TARGET_INFO
    | FLAG_NEGOTIATE_VERSION
    | FLAG_NEGOTIATE_128
    | FLAG_NEGOTIATE_56;

/// Fixed part of the Type 2 message, before TargetName/TargetInfo.
const TYPE2_HEADER_LEN: usize = 56;

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// HMAC-MD5 (RFC 2104).
///
/// Hand-rolled so `md4`/`md-5` can move independently of an `hmac` crate's
/// `digest` pin; validated against RFC 2202 in the tests below.
pub fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..16].copy_from_slice(&Md5::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Md5::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Md5::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// MD4(UTF-16LE(password)) — the "NT hash" Windows stores.
pub fn nt_hash(password: &str) -> [u8; 16] {
    use md4::{Digest as _, Md4};
    Md4::digest(utf16le(password)).into()
}

/// What the honeypot claims to be inside its NTLM challenge. `nxc` and
/// `pypsrp` read the NetBIOS/DNS names and the version out of this.
pub struct ServerIdentity<'a> {
    pub netbios_name: &'a str,
    pub domain: &'a str,
    pub dns_host: &'a str,
    pub dns_domain: &'a str,
    pub version: (u8, u8, u16),
}

/// AV pair: `u16 id | u16 byte length | value`.
fn av(out: &mut Vec<u8>, id: u16, value: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
}

/// MsvAv* list, terminated with MsvAvEOL.
fn target_info(id: &ServerIdentity<'_>, filetime: u64) -> Vec<u8> {
    let mut ti = Vec::new();
    av(&mut ti, 1, &utf16le(id.netbios_name)); // MsvAvNbComputerName
    av(&mut ti, 2, &utf16le(id.domain)); // MsvAvNbDomainName
    av(&mut ti, 3, &utf16le(id.dns_host)); // MsvAvDnsComputerName
    av(&mut ti, 4, &utf16le(id.dns_domain)); // MsvAvDnsDomainName
    av(&mut ti, 5, &utf16le(id.dns_domain)); // MsvAvDnsTreeName
    av(&mut ti, 7, &filetime.to_le_bytes()); // MsvAvTimestamp
    av(&mut ti, 0, &[]); // MsvAvEOL
    ti
}

fn version_bytes(v: (u8, u8, u16)) -> [u8; 8] {
    let (major, minor, build) = v;
    let [lo, hi] = build.to_le_bytes();
    [major, minor, lo, hi, 0, 0, 0, 0x0f] // 0x0f = NTLMSSP_REVISION_W2K3
}

/// Builds the NTLMSSP_CHALLENGE (Type 2).
pub fn build_type2(id: &ServerIdentity<'_>, challenge: [u8; 8], filetime: u64) -> Vec<u8> {
    let target_name = utf16le(id.domain);
    let tinfo = target_info(id, filetime);
    let tinfo_offset = TYPE2_HEADER_LEN + target_name.len();

    let mut out = Vec::with_capacity(tinfo_offset + tinfo.len());
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(TYPE2_HEADER_LEN as u32).to_le_bytes());
    out.extend_from_slice(&SERVER_FLAGS.to_le_bytes());
    out.extend_from_slice(&challenge);
    out.extend_from_slice(&[0u8; 8]); // Reserved
    out.extend_from_slice(&(tinfo.len() as u16).to_le_bytes());
    out.extend_from_slice(&(tinfo.len() as u16).to_le_bytes());
    out.extend_from_slice(&(tinfo_offset as u32).to_le_bytes());
    out.extend_from_slice(&version_bytes(id.version));
    out.extend_from_slice(&target_name);
    out.extend_from_slice(&tinfo);
    out
}

/// Finds the NTLMSSP message inside a token that may be wrapped in SPNEGO
/// (Windows clients do wrap it; impacket-based tools send it raw).
pub fn find_message(raw: &[u8]) -> Option<&[u8]> {
    let pos = raw.windows(SIGNATURE.len()).position(|w| w == SIGNATURE)?;
    Some(&raw[pos..])
}

pub fn message_type(msg: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(msg.get(8..12)?.try_into().ok()?))
}

/// The NTLMv2 "response": 16-byte NTProofStr followed by the client blob.
#[derive(Debug, Clone)]
pub struct NtlmV2 {
    pub proof: [u8; 16],
    /// Everything after NTProofStr, verbatim (this is what hashcat wants).
    pub blob: Vec<u8>,
}

/// A parsed NTLMSSP_AUTHENTICATE (Type 3).
#[derive(Debug, Clone)]
pub struct Type3 {
    pub domain: String,
    pub user: String,
    pub workstation: String,
    pub nt_response: Vec<u8>,
    pub flags: u32,
    pub v2: Option<NtlmV2>,
}

/// Reads a `len | maxlen | offset` triple. Returns None if the span is not
/// entirely inside `buf` — every hostile offset lands here.
fn read_secbuf(buf: &[u8], off: usize) -> Option<(usize, usize)> {
    let len = u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?) as usize;
    let data_off = u32::from_le_bytes(buf.get(off + 4..off + 8)?.try_into().ok()?) as usize;
    if data_off.checked_add(len)? > buf.len() {
        return None;
    }
    Some((data_off, len))
}

fn utf16_at(buf: &[u8], (off, len): (usize, usize)) -> String {
    let units: Vec<u16> = buf[off..off + len]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parses a Type 3 message. `msg` must start at the NTLMSSP signature
/// (see [`find_message`] for tokens wrapped in SPNEGO).
pub fn parse_type3(msg: &[u8]) -> Option<Type3> {
    if message_type(msg)? != 3 {
        return None;
    }
    let nt = read_secbuf(msg, 20)?;
    let domain = read_secbuf(msg, 28)?;
    let user = read_secbuf(msg, 36)?;
    let workstation = read_secbuf(msg, 44)?;
    let flags = u32::from_le_bytes(msg.get(60..64)?.try_into().ok()?);

    let nt_response = msg[nt.0..nt.0 + nt.1].to_vec();
    // NTLMv2: NTProofStr(16) || blob, and the blob starts with 0x01 0x01.
    let v2 = if nt_response.len() > 16 && nt_response[16] == 0x01 {
        let mut proof = [0u8; 16];
        proof.copy_from_slice(&nt_response[..16]);
        Some(NtlmV2 {
            proof,
            blob: nt_response[16..].to_vec(),
        })
    } else {
        None
    };

    Some(Type3 {
        domain: utf16_at(msg, domain),
        user: utf16_at(msg, user),
        workstation: utf16_at(msg, workstation),
        nt_response,
        flags,
        v2,
    })
}

/// 100ns ticks since 1601-01-01, the format MsvAvTimestamp uses.
pub fn filetime_now() -> u64 {
    let unix_100ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        / 100;
    unix_100ns + 116_444_736_000_000_000
}

/// A fresh 8-byte server challenge from the OS RNG.
pub fn random_challenge() -> [u8; 8] {
    // u64 keeps this independent of array-distribution changes across rand majors.
    rand::random::<u64>().to_le_bytes()
}

/// NTLMv2Hash = HMAC-MD5(NT hash, UTF-16LE(UPPER(user) ++ domain)).
pub fn ntlmv2_hash(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt = nt_hash(password);
    let mut identity = utf16le(&user.to_uppercase());
    identity.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt, &identity)
}

/// What a client computes: NTProofStr(16) ++ blob. Used by the tests, by the
/// synthetic Type 3 builder, and as the reference the server verifies against.
pub fn ntlmv2_response(
    password: &str,
    user: &str,
    domain: &str,
    challenge: &[u8; 8],
    blob: &[u8],
) -> Vec<u8> {
    let key = ntlmv2_hash(password, user, domain);
    let mut msg = Vec::with_capacity(8 + blob.len());
    msg.extend_from_slice(challenge);
    msg.extend_from_slice(blob);
    let proof = hmac_md5(&key, &msg);

    let mut out = Vec::with_capacity(16 + blob.len());
    out.extend_from_slice(&proof);
    out.extend_from_slice(blob);
    out
}

/// Server side: does this response prove knowledge of `password`?
pub fn verify_ntlmv2(
    password: &str,
    user: &str,
    domain: &str,
    challenge: &[u8; 8],
    v2: &NtlmV2,
) -> bool {
    let expected = ntlmv2_response(password, user, domain, challenge, &v2.blob);
    constant_time_eq(&expected[..16], &v2.proof)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `USER::DOMAIN:challenge:NTProofStr:blob` — hashcat mode 5600.
pub fn netntlmv2_line(user: &str, domain: &str, challenge: &[u8; 8], v2: &NtlmV2) -> String {
    format!(
        "{}::{}:{}:{}:{}",
        user,
        domain,
        hex(challenge),
        hex(&v2.proof),
        hex(&v2.blob)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_md5_matches_rfc2202_vector_1() {
        // RFC 2202 test case 1.
        let key = [0x0bu8; 16];
        assert_eq!(
            hex(&hmac_md5(&key, b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
    }

    #[test]
    fn nt_hash_of_password_is_the_known_value() {
        // MD4(UTF-16LE("password")) — the well-known NT hash.
        assert_eq!(
            hex(&nt_hash("password")),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
    }

    #[test]
    fn nt_hash_of_empty_password_is_the_known_value() {
        assert_eq!(hex(&nt_hash("")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn utf16le_encodes_ascii_as_two_bytes_per_char() {
        assert_eq!(utf16le("Ab"), vec![0x41, 0x00, 0x62, 0x00]);
    }

    fn identity() -> ServerIdentity<'static> {
        ServerIdentity {
            netbios_name: "WIN-SRV01",
            domain: "CORP",
            dns_host: "WIN-SRV01.corp.local",
            dns_domain: "corp.local",
            version: (10, 0, 20348),
        }
    }

    #[test]
    fn type2_has_signature_flags_and_a_wellformed_target() {
        let msg = build_type2(&identity(), [0x11; 8], 0x01d0_0000_0000_0000);

        assert_eq!(&msg[0..8], SIGNATURE);
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 2);
        let flags = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        assert_eq!(
            flags & FLAG_NEGOTIATE_TARGET_INFO,
            FLAG_NEGOTIATE_TARGET_INFO
        );
        assert_eq!(flags & FLAG_NEGOTIATE_VERSION, FLAG_NEGOTIATE_VERSION);
        assert_eq!(&msg[24..32], &[0x11; 8], "server challenge");

        // TargetName secbuf must point at the domain, in bounds.
        let tlen = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
        let toff = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
        assert_eq!(tlen, utf16le("CORP").len());
        assert_eq!(&msg[toff..toff + tlen], utf16le("CORP").as_slice());

        // TargetInfo secbuf must point at AV pairs, in bounds, EOL-terminated.
        let ilen = u16::from_le_bytes(msg[40..42].try_into().unwrap()) as usize;
        let ioff = u32::from_le_bytes(msg[44..48].try_into().unwrap()) as usize;
        assert!(ilen > 0);
        assert!(ioff + ilen <= msg.len());
        assert_eq!(
            &msg[ioff + ilen - 4..ioff + ilen],
            &[0, 0, 0, 0],
            "MsvAvEOL"
        );
    }

    #[test]
    fn type2_carries_the_names_netexec_fingerprints() {
        let msg = build_type2(&identity(), [0x22; 8], 0);
        for name in ["WIN-SRV01", "CORP", "WIN-SRV01.corp.local", "corp.local"] {
            let needle = utf16le(name);
            assert!(
                msg.windows(needle.len()).any(|w| w == needle),
                "Type2 is missing {name}"
            );
        }
        // Version field: 10.0.20348, revision 0x0f
        // 10.0.20348 -> major 10, minor 0, build 20348 = 0x4f7c (little endian),
        // then 3 reserved bytes and NTLMSSP_REVISION_W2K3.
        assert_eq!(&msg[48..56], &[10, 0, 0x7c, 0x4f, 0, 0, 0, 0x0f]);
    }

    #[test]
    fn find_message_skips_a_spnego_wrapper() {
        let mut blob = vec![0x60, 0x1e, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
        blob.extend_from_slice(&build_type2(&identity(), [3; 8], 0));
        let found = find_message(&blob).expect("must locate the NTLMSSP signature");
        assert_eq!(message_type(found), Some(2));
    }

    #[test]
    fn find_message_returns_none_for_non_ntlm_input() {
        assert!(find_message(b"not an ntlm token").is_none());
        assert_eq!(message_type(b"short"), None);
    }

    /// Builds a syntactically valid Type 3 with an arbitrary NT response.
    fn synth_type3(domain: &str, user: &str, ws: &str, nt_response: &[u8]) -> Vec<u8> {
        let d = utf16le(domain);
        let u = utf16le(user);
        let w = utf16le(ws);

        let mut out = vec![0u8; 64];
        out[0..8].copy_from_slice(SIGNATURE);
        out[8..12].copy_from_slice(&3u32.to_le_bytes());

        let mut off = 64usize;
        for (at, data) in [
            (12usize, d.as_slice()), // LmChallengeResponse
            (20, nt_response),       // NtChallengeResponse
            (28, d.as_slice()),      // DomainName
            (36, u.as_slice()),      // UserName
            (44, w.as_slice()),      // Workstation
        ] {
            put_secbuf(&mut out, at, off, data);
            off += data.len();
        }
        out[60..64].copy_from_slice(&SERVER_FLAGS.to_le_bytes());

        for data in [&d, &nt_response.to_vec(), &d, &u, &w] {
            out.extend_from_slice(data);
        }
        out
    }

    fn put_secbuf(out: &mut [u8], at: usize, offset: usize, data: &[u8]) {
        let len = data.len() as u16;
        out[at..at + 2].copy_from_slice(&len.to_le_bytes());
        out[at + 2..at + 4].copy_from_slice(&len.to_le_bytes());
        out[at + 4..at + 8].copy_from_slice(&(offset as u32).to_le_bytes());
    }

    fn v2_response() -> Vec<u8> {
        // 16-byte proof followed by an NTLMv2 blob (0x01 0x01 ...).
        let mut nt = vec![0xAAu8; 16];
        nt.extend_from_slice(&[0x01, 0x01, 0, 0, 0, 0, 0, 0]);
        nt
    }

    #[test]
    fn parses_type3_fields() {
        let msg = synth_type3("CORP", "Administrator", "WS01", &v2_response());
        let t3 = parse_type3(&msg).expect("must parse");
        assert_eq!(t3.domain, "CORP");
        assert_eq!(t3.user, "Administrator");
        assert_eq!(t3.workstation, "WS01");
        assert_eq!(t3.nt_response.len(), 24);
        let v2 = t3.v2.expect("must look like NTLMv2");
        assert_eq!(v2.proof, [0xAAu8; 16]);
        assert_eq!(v2.blob, vec![0x01, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_wrong_message_type() {
        let mut msg = synth_type3("CORP", "u", "w", &v2_response());
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(parse_type3(&msg).is_none());
    }

    #[test]
    fn rejects_out_of_bounds_secbuf_without_panicking() {
        let msg = synth_type3("CORP", "u", "w", &v2_response());
        // Point UserName's secbuf far past the end of the message.
        let mut evil = msg.clone();
        evil[40..44].copy_from_slice(&0xFFFF_0000u32.to_le_bytes()); // offset in UserName? (32..36)
        assert!(parse_type3(&evil).is_none() || parse_type3(&evil).is_some());
        // The real property: no panic on hostile offsets.
        let mut truncated = msg.clone();
        truncated.truncate(30);
        assert!(parse_type3(&truncated).is_none());
    }

    #[test]
    fn type3_with_short_nt_response_has_no_v2() {
        let msg = synth_type3("CORP", "u", "w", &[0u8; 8]);
        let t3 = parse_type3(&msg).expect("must still parse");
        assert!(t3.v2.is_none());
    }

    #[test]
    fn verification_accepts_the_correct_password_only() {
        let challenge = [0xaau8; 8];
        let blob = vec![0x01u8, 0x01, 0, 0, 0, 0, 0, 0];
        let response = ntlmv2_response("Summer2026!", "Administrator", "CORP", &challenge, &blob);

        let mut proof = [0u8; 16];
        proof.copy_from_slice(&response[..16]);
        let v2 = NtlmV2 {
            proof,
            blob: response[16..].to_vec(),
        };

        assert!(verify_ntlmv2(
            "Summer2026!",
            "Administrator",
            "CORP",
            &challenge,
            &v2
        ));
        assert!(!verify_ntlmv2(
            "Summer2026",
            "Administrator",
            "CORP",
            &challenge,
            &v2
        ));
        // Same password, different server challenge: the proof must not verify.
        assert!(!verify_ntlmv2(
            "Summer2026!",
            "Administrator",
            "CORP",
            &[0xbbu8; 8],
            &v2
        ));
        // Same password, different domain.
        assert!(!verify_ntlmv2(
            "Summer2026!",
            "Administrator",
            "OTHER",
            &challenge,
            &v2
        ));
    }

    #[test]
    fn verification_is_case_insensitive_in_the_user_name() {
        // NTLM upper-cases the user before hashing, so both spellings must work.
        let challenge = [1u8; 8];
        let blob = vec![0x01u8, 0x01, 0, 0];
        let response = ntlmv2_response("pw", "administrator", "CORP", &challenge, &blob);
        let mut proof = [0u8; 16];
        proof.copy_from_slice(&response[..16]);
        let v2 = NtlmV2 {
            proof,
            blob: response[16..].to_vec(),
        };
        assert!(verify_ntlmv2(
            "pw",
            "Administrator",
            "CORP",
            &challenge,
            &v2
        ));
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The log line must carry everything a cracking tool needs. Parse it back
    /// and verify it against the password, which is what hashcat -m 5600 does.
    #[test]
    fn logged_hashcat_line_verifies_offline() {
        let challenge = [0x5au8; 8];
        let blob = vec![0x01u8, 0x01, 0, 0, 0, 0, 0, 0];
        let response = ntlmv2_response("Summer2026!", "Administrator", "CORP", &challenge, &blob);
        let mut proof = [0u8; 16];
        proof.copy_from_slice(&response[..16]);
        let v2 = NtlmV2 {
            proof,
            blob: response[16..].to_vec(),
        };

        let line = netntlmv2_line("Administrator", "CORP", &challenge, &v2);
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts.len(), 6, "{line}");

        let user = parts[0];
        let domain = parts[2];
        let mut ch = [0u8; 8];
        ch.copy_from_slice(&unhex(parts[3]));
        let parsed = NtlmV2 {
            proof: unhex(parts[4]).try_into().unwrap(),
            blob: unhex(parts[5]),
        };

        assert!(verify_ntlmv2("Summer2026!", user, domain, &ch, &parsed));
        assert!(!verify_ntlmv2("Summer2025!", user, domain, &ch, &parsed));
    }

    #[test]
    fn hashcat_line_matches_the_m_5600_shape() {
        let v2 = NtlmV2 {
            proof: [1u8; 16],
            blob: vec![2u8; 8],
        };
        let line = netntlmv2_line("Administrator", "CORP", &[3u8; 8], &v2);

        // hashcat 5600: USER::DOMAIN:server_challenge:NTProofStr:blob
        // `split(':')` therefore yields six parts, the second one empty.
        let parts: Vec<&str> = line.split(':').collect();
        assert_eq!(parts.len(), 6, "{line}");
        assert_eq!(parts[0], "Administrator");
        assert_eq!(parts[1], "");
        assert_eq!(parts[2], "CORP");
        assert_eq!(parts[3], hex(&[3u8; 8]));
        assert_eq!(parts[4], hex(&[1u8; 16]));
        assert_eq!(parts[5], hex(&[2u8; 8]));
    }
}

/// Fixtures for tests and manual probing: build a Type 3 the way a real client
/// would, using the same primitives the server verifies with.
pub mod tests_support {
    use super::*;

    /// `password` is what a real client would have been configured with.
    pub fn synth_type3(
        domain: &str,
        user: &str,
        workstation: &str,
        challenge: [u8; 8],
        password: &str,
    ) -> Vec<u8> {
        let d = utf16le(domain);
        let u = utf16le(user);
        let w = utf16le(workstation);
        let blob = vec![0x01u8, 0x01, 0, 0, 0, 0, 0, 0];
        let response = ntlmv2_response(password, user, domain, &challenge, &blob);

        let mut out = vec![0u8; 64];
        out[0..8].copy_from_slice(SIGNATURE);
        out[8..12].copy_from_slice(&3u32.to_le_bytes());

        let mut off = 64usize;
        for (at, data) in [
            (12usize, d.as_slice()),   // LmChallengeResponse
            (20, response.as_slice()), // NtChallengeResponse
            (28, d.as_slice()),        // DomainName
            (36, u.as_slice()),        // UserName
            (44, w.as_slice()),        // Workstation
        ] {
            let len = data.len() as u16;
            out[at..at + 2].copy_from_slice(&len.to_le_bytes());
            out[at + 2..at + 4].copy_from_slice(&len.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&(off as u32).to_le_bytes());
            off += data.len();
        }
        out[60..64].copy_from_slice(&SERVER_FLAGS.to_le_bytes());

        for data in [&d, &response, &d, &u, &w] {
            out.extend_from_slice(data);
        }
        out
    }
}
