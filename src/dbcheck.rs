// Exposed database detection: checks whether common database services
// are reachable with no authentication at all. One of the most common,
// highest-severity real findings in security assessments — an
// internet- or network-exposed database with zero auth is a
// well-documented, recurring incident category.
//
// Each check is a minimal presence/auth probe, not a full client
// implementation:
// - Redis: one RESP PING command; "+PONG" back means no auth required.
// - MongoDB: one hand-built OP_QUERY {listDatabases:1} against
//   admin.$cmd — a real database list back (not an auth error) means
//   no auth required. Uses small purpose-built BSON encoding for this
//   one fixed command, not a general BSON library, and scans the raw
//   response bytes for the "databases"/"errmsg" field names (BSON
//   field names are literal cstrings in the binary) rather than a full
//   BSON decoder.
// - Elasticsearch: exposes a plain HTTP REST API — a 200 on GET / with
//   no credentials is itself the finding. Reuses the existing http.rs
//   client.
// - Memcached: has no authentication mechanism in typical deployments,
//   so any reachable instance is itself the finding.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TIMEOUT_MS: u64 = 2000;

pub fn check_redis(ip: &str, port: u16) -> Option<String> {
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();

    stream.write_all(b"*1\r\n$4\r\nPING\r\n").ok()?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.starts_with("+PONG") {
        Some(format!(
            "VULNERABLE: Redis on port {} responds to PING with no authentication required",
            port
        ))
    } else {
        None
    }
}

pub fn check_memcached(ip: &str, port: u16) -> Option<String> {
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();

    stream.write_all(b"stats\r\n").ok()?;
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).ok()?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.starts_with("STAT ") {
        Some(format!(
            "VULNERABLE: Memcached exposed on port {} (no authentication mechanism exists for this protocol — restrict network access)",
            port
        ))
    } else {
        None
    }
}

pub fn check_elasticsearch(ip: &str, port: u16) -> Option<String> {
    let resp = crate::http::get(ip, port, "/", Duration::from_millis(TIMEOUT_MS)).ok()?;
    if resp.status == 200 {
        Some(format!(
            "VULNERABLE: possible unauthenticated Elasticsearch on port {} (200 OK with no credentials)",
            port
        ))
    } else {
        None
    }
}

pub fn check_mongodb(ip: &str, port: u16) -> Option<String> {
    let mut stream = TcpStream::connect((ip, port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .ok();

    let query = build_mongo_list_databases_query();
    stream.write_all(&query).ok()?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);

    if text.contains("databases") && !text.contains("errmsg") {
        Some(format!(
            "VULNERABLE: MongoDB on port {} returned database list with no authentication required",
            port
        ))
    } else {
        None
    }
}

// --- Minimal, purpose-built BSON + MongoDB wire protocol for exactly
// one fixed command: { listDatabases: 1 } against admin.$cmd. Not a
// general BSON encoder — just enough to build this one query.

fn bson_int32_element(name: &str, value: i32) -> Vec<u8> {
    let mut out = vec![0x10u8]; // BSON int32 type
    out.extend_from_slice(name.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

fn bson_document(elements: &[u8]) -> Vec<u8> {
    let mut doc = Vec::new();
    let total_len = 4 + elements.len() + 1;
    doc.extend_from_slice(&(total_len as i32).to_le_bytes());
    doc.extend_from_slice(elements);
    doc.push(0x00);
    doc
}

fn build_mongo_list_databases_query() -> Vec<u8> {
    let element = bson_int32_element("listDatabases", 1);
    let query_doc = bson_document(&element);

    let mut body = Vec::new();
    body.extend_from_slice(&0i32.to_le_bytes()); // flags
    body.extend_from_slice(b"admin.$cmd\0"); // fullCollectionName
    body.extend_from_slice(&0i32.to_le_bytes()); // numberToSkip
    body.extend_from_slice(&(-1i32).to_le_bytes()); // numberToReturn
    body.extend_from_slice(&query_doc);

    let mut message = Vec::new();
    let request_id = 1i32;
    let response_to = 0i32;
    let op_code = 2004i32; // OP_QUERY
    let message_length = (16 + body.len()) as i32;

    message.extend_from_slice(&message_length.to_le_bytes());
    message.extend_from_slice(&request_id.to_le_bytes());
    message.extend_from_slice(&response_to.to_le_bytes());
    message.extend_from_slice(&op_code.to_le_bytes());
    message.extend_from_slice(&body);

    message
}
