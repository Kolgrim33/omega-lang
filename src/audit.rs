// Append-only audit logging: a timestamped, per-statement record of
// every action Omega took and its outcome, written as JSON Lines (one
// JSON object per line) — both human-diffable and trivially
// machine-parseable.
//
// Scope: this logs at the level of each top-level script statement
// (e.g. "scan_ports", "scan_creds") and its overall outcome — it does
// NOT currently log per-host detail within a scan (e.g. which specific
// host inside a /24 was in/out of scope, or which credential pair
// succeeded). Those details still appear in stdout/report output; the
// audit log's job is the higher-level accountability record of what the
// script attempted and when.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuditLog {
    file: File,
}

impl AuditLog {
    pub fn open(path: &str) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("failed to open audit log '{}': {}", path, e))?;
        Ok(AuditLog { file })
    }

    pub fn write_entry(&mut self, action: &str, detail: &str, outcome: &str) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!(
            "{{\"timestamp\": {}, \"action\": \"{}\", \"detail\": \"{}\", \"outcome\": \"{}\"}}\n",
            ts,
            json_escape(action),
            json_escape(detail),
            json_escape(outcome)
        );
        let _ = self.file.write_all(line.as_bytes());
        let _ = self.file.flush();
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
