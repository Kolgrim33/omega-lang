// Minimal DNS client over a raw UDP socket — no external crate, matching
// the project's zero-dependency design. Implements just enough of the
// wire protocol (RFC 1035) for A and TXT record lookups: query
// construction, name compression handling, and RDATA parsing for the
// record types Omega's DNS checks actually need. NS parsing is included
// for completeness but isn't wired into any check yet.
//
// Known limitation: reads the first nameserver from /etc/resolv.conf
// (Unix-only, matching the existing `id -u` privilege check elsewhere in
// this codebase), falling back to 8.8.8.8 if unavailable. No retry logic
// beyond the OS-level UDP timeout.

use std::fs;
use std::net::UdpSocket;
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 3000;
const FALLBACK_RESOLVER: &str = "8.8.8.8";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A,
    Txt,
    Ns,
}

impl RecordType {
    fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Txt => 16,
        }
    }
}

fn system_resolver() -> String {
    if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver ") {
                let ns = rest.trim();
                if !ns.is_empty() {
                    return ns.to_string();
                }
            }
        }
    }
    FALLBACK_RESOLVER.to_string()
}

pub fn query(domain: &str, record_type: RecordType) -> Result<Vec<String>, String> {
    let resolver = system_resolver();
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("failed to bind UDP socket: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(DEFAULT_TIMEOUT_MS)))
        .ok();

    let query_packet = build_query(domain, record_type);
    socket
        .send_to(&query_packet, (resolver.as_str(), 53))
        .map_err(|e| format!("failed to send DNS query to {}: {}", resolver, e))?;

    let mut buf = [0u8; 4096];
    let (len, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("no response from {} (timeout or error): {}", resolver, e))?;

    parse_response(&buf[..len], record_type)
}

fn query_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos & 0xFFFF) as u16
}

fn build_query(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut packet = Vec::new();
    let id = query_id();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in domain.trim_end_matches('.').split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // root label

    packet.extend_from_slice(&record_type.code().to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    packet
}

fn parse_response(buf: &[u8], record_type: RecordType) -> Result<Vec<String>, String> {
    if buf.len() < 12 {
        return Err("DNS response too short".to_string());
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if rcode != 0 {
        return Err(format!("DNS query failed with rcode {}", rcode));
    }

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut results = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            break;
        }
        let rdata = &buf[pos..pos + rdlength];

        if rtype == record_type.code() {
            match record_type {
                RecordType::A => {
                    if rdata.len() == 4 {
                        results.push(format!(
                            "{}.{}.{}.{}",
                            rdata[0], rdata[1], rdata[2], rdata[3]
                        ));
                    }
                }
                RecordType::Txt => {
                    let mut text = String::new();
                    let mut i = 0;
                    while i < rdata.len() {
                        let seg_len = rdata[i] as usize;
                        i += 1;
                        if i + seg_len > rdata.len() {
                            break;
                        }
                        text.push_str(&String::from_utf8_lossy(&rdata[i..i + seg_len]));
                        i += seg_len;
                    }
                    results.push(text);
                }
                RecordType::Ns => {
                    let (name, _) = read_name(buf, pos)?;
                    results.push(name);
                }
            }
        }
        pos += rdlength;
    }

    Ok(results)
}

fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        if pos >= buf.len() {
            return Err("truncated DNS name".to_string());
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut end_pos = start;
    let mut guard = 0;

    loop {
        guard += 1;
        if guard > 128 {
            return Err("DNS name compression loop".to_string());
        }
        if pos >= buf.len() {
            return Err("truncated DNS name".to_string());
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err("truncated DNS name pointer".to_string());
            }
            if !jumped {
                end_pos = pos + 2;
            }
            let offset = (((len & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            pos = offset;
            jumped = true;
            continue;
        }
        if pos + 1 + len > buf.len() {
            return Err("truncated DNS name label".to_string());
        }
        labels.push(String::from_utf8_lossy(&buf[pos + 1..pos + 1 + len]).to_string());
        pos += 1 + len;
    }

    Ok((labels.join("."), end_pos))
}
