// Plain target-list export for tool chaining — the actual pentest
// workflow of "recon tool -> target list -> next tool" rather than one
// tool doing everything. Deliberately dumb formats (no findings, no
// severity, just addresses) since the whole point is universal
// compatibility with whatever the next tool in the chain expects.

use crate::interpreter::Host;
use std::fs;

/// One "ip:port" line per open port. Hosts with no open ports (never
/// scanned, or scanned with nothing open) still get a bare "ip" line —
/// still useful for feeding into another discovery tool.
pub fn write_txt(path: &str, hosts: &[Host]) -> Result<(), String> {
    let mut out = String::new();
    for host in hosts {
        if host.open_ports.is_empty() {
            out.push_str(&host.ip);
            out.push('\n');
        } else {
            for port in &host.open_ports {
                out.push_str(&format!("{}:{}\n", host.ip, port));
            }
        }
    }
    fs::write(path, out).map_err(|e| format!("failed to write export to '{}': {}", path, e))
}

/// ip,port,service header + one row per open port. Hosts with no open
/// ports still get a row with empty port/service fields, so the host
/// itself isn't silently dropped from the export.
pub fn write_csv(path: &str, hosts: &[Host]) -> Result<(), String> {
    let mut out = String::from("ip,port,service\n");
    for host in hosts {
        if host.open_ports.is_empty() {
            out.push_str(&format!("{},,\n", csv_escape(&host.ip)));
        } else {
            for port in &host.open_ports {
                let service = host
                    .services
                    .iter()
                    .find(|(p, _)| p == port)
                    .map(|(_, s)| s.as_str())
                    .unwrap_or("");
                out.push_str(&format!(
                    "{},{},{}\n",
                    csv_escape(&host.ip),
                    port,
                    csv_escape(service)
                ));
            }
        }
    }
    fs::write(path, out).map_err(|e| format!("failed to write export to '{}': {}", path, e))
}

/// Minimal CSV field escaping: wrap in quotes and double any embedded
/// quotes if the field contains a comma, quote, or newline. IP addresses
/// and service names essentially never need this, but it's cheap
/// correctness to have rather than assume.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}
