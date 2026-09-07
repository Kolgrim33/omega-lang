// TLS certificate and protocol/cipher checks — no cryptography performed.
//
// For TLS 1.2 and earlier, the server's certificate is sent *unencrypted*
// as one of the first handshake messages, before any encryption keys
// exist. This module sends a ClientHello, reads the plaintext
// ServerHello + Certificate messages, then disconnects — it never
// completes a real encrypted session. That's enough to read certificate
// validity/subject/issuer and the negotiated protocol version/cipher,
// without needing any actual cryptographic operations (no key exchange,
// no signature verification, no encryption).
//
// Deliberately NOT implemented: anything requiring real crypto — key
// exchange, decrypting TLS 1.3's encrypted Certificate message, or
// completing a session to exchange real application data. Same reasoning
// as SSH being excluded from credcheck.rs: hand-rolled crypto isn't
// something to responsibly build without an audited library.
//
// Protocol/cipher "support" checks work by sending a ClientHello that
// only offers a narrow, deliberately weak set of options and seeing
// whether the server accepts (negotiates) or rejects (sends an Alert) —
// the same technique tools like testssl.sh use, just without decrypting
// anything afterward.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TIMEOUT_MS: u64 = 3000;

// A modern, broad cipher suite list for the "what does this server
// normally negotiate" baseline handshake.
const MODERN_CIPHERS: &[u16] = &[
    0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
    0xc030, // ECDHE-RSA-AES256-GCM-SHA384
    0xc02b, // ECDHE-ECDSA-AES128-GCM-SHA256
    0xc02c, // ECDHE-ECDSA-AES256-GCM-SHA384
    0x009c, // RSA-AES128-GCM-SHA256
    0x009d, // RSA-AES256-GCM-SHA384
    0x002f, // RSA-AES128-SHA
    0x0035, // RSA-AES256-SHA
];

// Deliberately weak/broken cipher suites — if a server accepts a
// ClientHello offering ONLY these, that's a real finding.
const WEAK_CIPHERS: &[(u16, &str)] = &[
    (0x0001, "NULL-MD5 (no encryption)"),
    (0x0002, "NULL-SHA (no encryption)"),
    (0x0003, "EXPORT-RC4-40-MD5 (export-grade, broken)"),
    (0x0004, "RC4-MD5 (broken cipher)"),
    (0x0005, "RC4-SHA (broken cipher)"),
    (0x0009, "DES-CBC-SHA (broken cipher)"),
    (0x000a, "3DES-EDE-CBC-SHA (weak, deprecated)"),
];

pub fn check_tls(host: &str, port: u16) -> Vec<String> {
    let mut findings = Vec::new();

    match do_handshake(host, port, MODERN_CIPHERS, (3, 3)) {
        Ok(hello) => {
            findings.push(format!(
                "Negotiated: {} / {}",
                version_name(hello.version),
                cipher_name(hello.cipher_suite)
            ));
            match hello.cert_der {
                Some(der) => match parse_x509_basic(&der) {
                    Ok(info) => findings.extend(cert_findings(&info)),
                    Err(e) => findings.push(format!("could not parse certificate: {}", e)),
                },
                None => {
                    if hello.version == (3, 4) {
                        findings.push(
                            "note: server negotiated TLS 1.3 — its Certificate message is encrypted and can't be read without a full crypto implementation".to_string(),
                        );
                    }
                }
            }
        }
        Err(e) => {
            findings.push(format!("TLS handshake failed: {}", e));
            return findings;
        }
    }

    // Legacy protocol version probes.
    if handshake_accepts_version(host, port, (3, 1)) {
        findings.push("Server still accepts TLS 1.0 — a deprecated, weak protocol version".to_string());
    }
    if handshake_accepts_version(host, port, (3, 2)) {
        findings.push("Server still accepts TLS 1.1 — a deprecated, weak protocol version".to_string());
    }

    // Weak cipher probe: offer ONLY weak suites and see if anything gets negotiated.
    let weak_ids: Vec<u16> = WEAK_CIPHERS.iter().map(|(id, _)| *id).collect();
    if let Ok(hello) = do_handshake(host, port, &weak_ids, (3, 3)) {
        if let Some((_, name)) = WEAK_CIPHERS.iter().find(|(id, _)| *id == hello.cipher_suite) {
            findings.push(format!("Server accepted weak cipher suite: {}", name));
        }
    }

    findings
}

fn handshake_accepts_version(host: &str, port: u16, version: (u8, u8)) -> bool {
    do_handshake(host, port, MODERN_CIPHERS, version).is_ok()
}

struct HelloResult {
    version: (u8, u8),
    cipher_suite: u16,
    cert_der: Option<Vec<u8>>,
}

fn do_handshake(
    host: &str,
    port: u16,
    cipher_suites: &[u16],
    client_version: (u8, u8),
) -> Result<HelloResult, String> {
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect failed: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS))).ok();
    stream.set_write_timeout(Some(Duration::from_millis(TIMEOUT_MS))).ok();

    let client_hello = build_client_hello(host, cipher_suites, client_version);
    stream
        .write_all(&client_hello)
        .map_err(|e| format!("write failed: {}", e))?;

    let flight = recv_handshake_flight(&mut stream)?;

    let (version, cipher_suite, consumed) = parse_server_hello(&flight)?;
    let cert_der = find_certificate(&flight[consumed..]);

    Ok(HelloResult {
        version,
        cipher_suite,
        cert_der,
    })
}

fn build_client_hello(sni: &str, cipher_suites: &[u16], version: (u8, u8)) -> Vec<u8> {
    let mut hello_body = Vec::new();
    hello_body.push(version.0);
    hello_body.push(version.1);

    // "Random" — doesn't need to be cryptographically secure here, this
    // is only used to solicit a ServerHello/Certificate, never to derive
    // any actual encryption key.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for i in 0..32u8 {
        hello_body.push((nanos.wrapping_add(i as u32) & 0xFF) as u8);
    }

    hello_body.push(0); // session_id length = 0

    hello_body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for cs in cipher_suites {
        hello_body.extend_from_slice(&cs.to_be_bytes());
    }

    hello_body.push(1); // compression methods length
    hello_body.push(0); // null compression

    // Extensions: SNI only — required by virtually every real HTTPS host
    // to select the right certificate.
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes()); // server name list length
    sni_ext.push(0); // name type = host_name
    sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // extension type = server_name
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = hello_body.len() as u32;
    handshake.push((len >> 16) as u8);
    handshake.push((len >> 8) as u8);
    handshake.push(len as u8);
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16); // Handshake content type
    record.push(version.0);
    record.push(version.1);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Reads TLS records until an Alert is seen or a full handshake flight
/// (ServerHello onward) appears to have arrived, returning the
/// concatenated payload of all Handshake-type records received.
fn recv_handshake_flight(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut handshake_data = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_millis(TIMEOUT_MS);

    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let mut chunk = &buf[..n];
        while chunk.len() >= 5 {
            let content_type = chunk[0];
            let frag_len = u16::from_be_bytes([chunk[3], chunk[4]]) as usize;
            if chunk.len() < 5 + frag_len {
                break; // partial record — would need to buffer across reads; rare in practice for this handshake stage
            }
            let fragment = &chunk[5..5 + frag_len];
            if content_type == 0x15 {
                // Alert
                let desc = fragment.get(1).copied().unwrap_or(0);
                return Err(format!("server sent TLS alert (code {})", desc));
            }
            if content_type == 0x16 {
                handshake_data.extend_from_slice(fragment);
            }
            chunk = &chunk[5 + frag_len..];
        }
        // Stop once we've seen a ServerHelloDone (0x0e) in what we've
        // collected, or once we have enough to have gotten past
        // Certificate for most servers — good enough for this narrow use.
        if handshake_data.iter().position(|&b| b == 0x0e).is_some() || handshake_data.len() > 16000
        {
            break;
        }
    }

    if handshake_data.is_empty() {
        return Err("no handshake data received (timeout or connection closed)".to_string());
    }
    Ok(handshake_data)
}

/// Parses the ServerHello at the start of `data`. Returns (version,
/// cipher_suite, bytes_consumed) so the caller can look for a
/// Certificate message afterward.
fn parse_server_hello(data: &[u8]) -> Result<((u8, u8), u16, usize), String> {
    if data.len() < 4 || data[0] != 0x02 {
        return Err("expected ServerHello".to_string());
    }
    let len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return Err("truncated ServerHello".to_string());
    }
    let body = &data[4..4 + len];
    if body.len() < 2 {
        return Err("ServerHello too short".to_string());
    }
    let version = (body[0], body[1]);
    let mut pos = 2 + 32; // version + random
    if pos >= body.len() {
        return Err("truncated ServerHello".to_string());
    }
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > body.len() {
        return Err("truncated ServerHello".to_string());
    }
    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);

    Ok((version, cipher_suite, 4 + len))
}

/// Walks handshake messages looking for a Certificate message (type
/// 0x0b), then extracts the first (leaf) certificate's DER bytes.
fn find_certificate(mut data: &[u8]) -> Option<Vec<u8>> {
    while data.len() >= 4 {
        let msg_type = data[0];
        let len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let body = &data[4..4 + len];
        if msg_type == 0x0b {
            // Certificate message: 3-byte total length, then a list of
            // (3-byte cert length + DER bytes) entries. Take the first.
            if body.len() < 3 {
                return None;
            }
            let mut p = 3;
            if p + 3 > body.len() {
                return None;
            }
            let cert_len = u32::from_be_bytes([0, body[p], body[p + 1], body[p + 2]]) as usize;
            p += 3;
            if p + cert_len > body.len() {
                return None;
            }
            return Some(body[p..p + cert_len].to_vec());
        }
        data = &data[4 + len..];
    }
    None
}

struct X509Info {
    not_before: Option<i64>,
    not_after: Option<i64>,
    not_after_display: String,
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
}

/// Deliberately simplified X.509 parsing: walks the top-level
/// Certificate/TBSCertificate/Validity structure properly (it's shallow
/// and well-defined), but finds Subject/Issuer Common Name by scanning
/// for the CN OID byte pattern (06 03 55 04 03) rather than fully
/// recursing through Name/RDN/AttributeTypeAndValue structures. This is
/// pragmatic rather than a fully general ASN.1 Name parser, but reliable
/// for the common case.
fn parse_x509_basic(der: &[u8]) -> Result<X509Info, String> {
    let (_, cert_content, _) = read_tlv(der, 0)?;
    let (_, tbs_content, _) = read_tlv(cert_content, 0)?;

    let mut pos = 0;
    // Optional [0] version tag (context-specific, constructed: 0xA0).
    if tbs_content.get(pos) == Some(&0xA0) {
        let (_, _, next) = read_tlv(tbs_content, pos)?;
        pos = next;
    }
    // serialNumber (INTEGER)
    let (_, _, next) = read_tlv(tbs_content, pos)?;
    pos = next;
    // signature AlgorithmIdentifier (SEQUENCE)
    let (_, _, next) = read_tlv(tbs_content, pos)?;
    pos = next;
    // issuer (Name)
    let (_, issuer_content, next) = read_tlv(tbs_content, pos)?;
    pos = next;
    let issuer_cn = find_cn(issuer_content);
    // validity (SEQUENCE of two Time values)
    let (_, validity_content, next) = read_tlv(tbs_content, pos)?;
    pos = next;
    let (nb_tag, nb_content, v_next) = read_tlv(validity_content, 0)?;
    let (na_tag, na_content, _) = read_tlv(validity_content, v_next)?;
    let not_before = parse_asn1_time(nb_tag, nb_content);
    let (not_after, not_after_display) = match parse_asn1_time(na_tag, na_content) {
        Some(secs) => (Some(secs), String::from_utf8_lossy(na_content).to_string()),
        None => (None, String::from_utf8_lossy(na_content).to_string()),
    };
    // subject (Name)
    let (_, subject_content, _) = read_tlv(tbs_content, pos)?;
    let subject_cn = find_cn(subject_content);

    Ok(X509Info {
        not_before,
        not_after,
        not_after_display,
        subject_cn,
        issuer_cn,
    })
}

/// Scans for the CN OID (2.5.4.3 => DER bytes 06 03 55 04 03) and reads
/// the string value immediately following it.
fn find_cn(data: &[u8]) -> Option<String> {
    let pattern = [0x06, 0x03, 0x55, 0x04, 0x03];
    for i in 0..data.len().saturating_sub(pattern.len()) {
        if &data[i..i + pattern.len()] == pattern {
            let value_start = i + pattern.len();
            if let Ok((_, content, _)) = read_tlv(data, value_start) {
                return Some(String::from_utf8_lossy(content).to_string());
            }
        }
    }
    None
}

/// Reads one ASN.1 DER TLV (tag, length, value) starting at `pos`.
/// Returns (tag, content_slice, position_after_this_tlv). Handles both
/// short-form and long-form (multi-byte) length encoding; does not
/// handle indefinite-length encoding (not used in DER, only in BER).
fn read_tlv(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), String> {
    if pos >= data.len() {
        return Err("unexpected end of DER data".to_string());
    }
    let tag = data[pos];
    let mut p = pos + 1;
    if p >= data.len() {
        return Err("truncated DER TLV".to_string());
    }
    let len_byte = data[p];
    p += 1;
    let length = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if p + num_bytes > data.len() || num_bytes > 4 {
            return Err("invalid or oversized DER length".to_string());
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[p + i] as usize;
        }
        p += num_bytes;
        len
    };
    if p + length > data.len() {
        return Err("DER length exceeds available data".to_string());
    }
    Ok((tag, &data[p..p + length], p + length))
}

/// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime
/// ("YYYYMMDDHHMMSSZ") into Unix epoch seconds. Two-digit years follow
/// RFC 5280: YY < 50 means 20YY, otherwise 19YY.
fn parse_asn1_time(tag: u8, content: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(content).ok()?;
    let (year, rest) = if tag == 0x17 {
        // UTCTime
        let yy: i64 = s.get(0..2)?.parse().ok()?;
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (year, &s[2..])
    } else {
        // GeneralizedTime
        let yyyy: i64 = s.get(0..4)?.parse().ok()?;
        (yyyy, &s[4..])
    };
    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: i64 = rest.get(4..6)?.parse().ok()?;
    let min: i64 = rest.get(6..8)?.parse().ok()?;
    let sec: i64 = rest.get(8..10)?.parse().ok()?;

    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Howard Hinnant's days-from-civil-date algorithm — a well-known,
/// correct conversion from a Gregorian calendar date to days since the
/// Unix epoch (1970-01-01), used here only for date comparison, not any
/// security-relevant computation.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn cert_findings(info: &X509Info) -> Vec<String> {
    let mut findings = Vec::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if let Some(subject) = &info.subject_cn {
        findings.push(format!("Certificate subject: {}", subject));
    }
    if let Some(issuer) = &info.issuer_cn {
        findings.push(format!("Certificate issuer: {}", issuer));
    }
    match info.not_after {
        Some(not_after) if not_after < now => {
            findings.push(format!(
                "Certificate EXPIRED (not valid after {})",
                info.not_after_display
            ));
        }
        Some(not_after) if not_after - now < 30 * 86400 => {
            findings.push(format!(
                "Certificate expiring within 30 days (not valid after {})",
                info.not_after_display
            ));
        }
        Some(_) => {
            findings.push(format!(
                "Certificate valid, not expiring soon (not valid after {})",
                info.not_after_display
            ));
        }
        None => {
            findings.push("could not parse certificate expiry date".to_string());
        }
    }
    let _ = info.not_before; // parsed but not currently used in a finding

    findings
}

fn version_name(v: (u8, u8)) -> &'static str {
    match v {
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "unknown TLS version",
    }
}

fn cipher_name(id: u16) -> String {
    MODERN_CIPHERS
        .iter()
        .find(|&&c| c == id)
        .map(|_| format!("cipher 0x{:04x}", id))
        .unwrap_or_else(|| format!("cipher 0x{:04x}", id))
}
