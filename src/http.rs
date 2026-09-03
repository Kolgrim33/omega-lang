// Minimal HTTP/1.1 GET client over a plain TCP socket — no external HTTP
// crate, matching the project's zero-dependency design. Always sends
// `Connection: close` so the server closes the socket when done, which
// lets us read to EOF instead of needing to parse Content-Length/chunked
// encoding to know when the response ends. Callers today only need
// status + headers, so the body is read but not exposed — keeping this
// deliberately narrow rather than a general-purpose HTTP client.
//
// Known limitation: plain HTTP only, no TLS. Ports like 443/8443 are
// still probed as plain HTTP and will simply fail to respond
// meaningfully — callers surface that as an explicit finding rather than
// silently misreporting an HTTPS-only host as "no findings".

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

pub fn get(host: &str, port: u16, path: &str, timeout: Duration) -> Result<HttpResponse, String> {
    let mut stream = TcpStream::connect((host, port))
        .map_err(|e| format!("connect to {}:{} failed: {}", host, port, e))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: omega\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write to {}:{} failed: {}", host, port, e))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read from {}:{} failed: {}", host, port, e))?;

    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let text = String::from_utf8_lossy(raw);
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let header_section = &text[..header_end];
    let mut lines = header_section.lines();

    let status_line = lines.next().ok_or("empty HTTP response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("could not parse status line: {}", status_line))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok(HttpResponse { status, headers })
}
