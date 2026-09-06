// Default-credential checks — a narrowly-scoped, curated list of common
// factory-default logins, tested against HTTP Basic Auth, FTP, and
// Telnet. This is a standard, well-established part of authorized
// penetration testing (the same category as nmap's own
// http-default-accounts and ftp-anon NSE scripts) — not a general
// brute-forcer. The credential list is intentionally small (a handful of
// widely-known defaults, not a wordlist) to keep this a legitimate
// "is this device still on its factory defaults" check, and to minimize
// the risk of triggering account lockouts on a real target.
//
// SSH is deliberately NOT included: a correct, safe SSH client requires
// real cryptographic key exchange that cannot be responsibly hand-rolled
// without a dedicated, audited crypto library.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Small, curated set of widely-known factory defaults — deliberately
/// not a wordlist. Testing stops at the first hit per service.
const DEFAULT_CREDS: &[(&str, &str)] = &[
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", ""),
    ("administrator", "administrator"),
    ("guest", "guest"),
    ("user", "user"),
    ("admin", "1234"),
];

pub fn check_ftp(host: &str, port: u16) -> Vec<String> {
    let mut findings = Vec::new();
    for (user, pass) in DEFAULT_CREDS {
        if let Ok(true) = try_ftp_login(host, port, user, pass) {
            findings.push(format!(
                "DEFAULT CREDENTIALS VALID: FTP {}/{} on port {}",
                user, pass, port
            ));
            break;
        }
    }
    findings
}

fn try_ftp_login(host: &str, port: u16, user: &str, pass: &str) -> Result<bool, String> {
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .ok();

    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf); // banner — ignored, just drains it

    stream
        .write_all(format!("USER {}\r\n", user).as_bytes())
        .ok();
    let _ = stream.read(&mut buf);

    stream
        .write_all(format!("PASS {}\r\n", pass).as_bytes())
        .ok();
    let n = stream.read(&mut buf).unwrap_or(0);
    let response = String::from_utf8_lossy(&buf[..n]);

    Ok(response.starts_with("230"))
}

pub fn check_telnet(host: &str, port: u16) -> Vec<String> {
    let mut findings = Vec::new();
    for (user, pass) in DEFAULT_CREDS {
        if let Ok(true) = try_telnet_login(host, port, user, pass) {
            findings.push(format!(
                "DEFAULT CREDENTIALS VALID (best-effort heuristic): Telnet {}/{} on port {}",
                user, pass, port
            ));
            break;
        }
    }
    findings
}

/// Best-effort only: real Telnet option negotiation (IAC sequences) is
/// stripped rather than properly answered, and success/failure is
/// guessed from prompt text rather than a real protocol-level signal —
/// this will miss or misjudge some devices.
fn try_telnet_login(host: &str, port: u16, user: &str, pass: &str) -> Result<bool, String> {
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .ok();

    let _banner = read_clean(&mut stream);
    std::thread::sleep(Duration::from_millis(200));

    stream.write_all(format!("{}\r\n", user).as_bytes()).ok();
    let _after_user = read_clean(&mut stream);

    stream.write_all(format!("{}\r\n", pass).as_bytes()).ok();
    let after_pass = read_clean(&mut stream).to_lowercase();

    let failed = after_pass.contains("incorrect")
        || after_pass.contains("failed")
        || after_pass.contains("denied")
        || after_pass.contains("login");
    let looks_like_shell =
        after_pass.contains('$') || after_pass.contains('#') || after_pass.contains('>');

    Ok(!failed && looks_like_shell)
}

fn read_clean(stream: &mut TcpStream) -> String {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    strip_telnet_iac(&buf[..n])
}

/// Strips Telnet IAC (0xFF) option-negotiation sequences (3 bytes each)
/// rather than answering them — enough to read the human-readable text
/// around them without implementing full RFC 854 negotiation.
fn strip_telnet_iac(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0xFF && i + 2 < data.len() {
            i += 3;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn check_http_basic_auth(host: &str, port: u16) -> Vec<String> {
    let mut findings = Vec::new();
    let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);

    // Only bother if the baseline unauthenticated request is actually
    // rejected — no point testing credentials against an open page.
    let baseline = match crate::http::get(host, port, "/", timeout) {
        Ok(r) => r,
        Err(_) => return findings,
    };
    if baseline.status != 401 {
        return findings;
    }

    for (user, pass) in DEFAULT_CREDS {
        if let Ok(status) = get_status_with_basic_auth(host, port, "/", user, pass, timeout) {
            if status != 401 {
                findings.push(format!(
                    "DEFAULT CREDENTIALS VALID: HTTP Basic Auth {}/{} on port {}",
                    user, pass, port
                ));
                break;
            }
        }
    }
    findings
}

fn get_status_with_basic_auth(
    host: &str,
    port: u16,
    path: &str,
    user: &str,
    pass: &str,
    timeout: Duration,
) -> Result<u16, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("connect to {}:{} failed: {}", host, port, e))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let credentials = base64_encode(format!("{}:{}", user, pass).as_bytes());
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nUser-Agent: omega\r\nConnection: close\r\n\r\n",
        path, host, credentials
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write failed: {}", e))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read failed: {}", e))?;

    let text = String::from_utf8_lossy(&raw);
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let status_line = text[..header_end]
        .lines()
        .next()
        .ok_or("empty HTTP response")?;
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse status line: {}", status_line))
}

/// Standard base64 encoding (RFC 4648), hand-rolled to keep the
/// zero-dependency design rather than pulling in a crate for one use.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);

        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}
