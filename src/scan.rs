// Backends for discover / scan ports / identify services.
//
// This is exactly the "under the hood" translation layer described in the
// Omega design doc: the .omega script never mentions Nmap, it just says
// `discover hosts` / `scan ports` / `identify services`, and this module
// decides how to actually do that. Nmap is used when it's on PATH; when
// it isn't (e.g. this sandbox), Omega falls back to a plain TCP-connect
// probe so the language still runs end to end.

use crate::parallel::parallel_map;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

const DEFAULT_TIMEOUT_MS: u64 = 300;

/// A small set of common ports used for fallback discovery/scanning when
/// nmap isn't available and no explicit port range was given.
const COMMON_PORTS: &[u16] = &[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080];

static NMAP_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Whether nmap is on PATH. Cached after the first check so parallel
/// discovery/scanning across many hosts doesn't spawn a `nmap -V` process
/// per host just to answer this.
pub fn nmap_available() -> bool {
    *NMAP_AVAILABLE.get_or_init(|| {
        Command::new("nmap")
            .arg("-V")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Returns true if the host responds to a TCP connect attempt on any probe
/// port, or answers to `nmap -sn` when nmap is available.
pub fn discover_host(ip: &str) -> bool {
    if nmap_available() {
        if let Ok(output) = Command::new("nmap").arg("-sn").arg(ip).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.contains("Host is up");
        }
    }
    let results = parallel_map(COMMON_PORTS, |&p| tcp_probe(ip, p).is_ok());
    results.into_iter().any(|up| up)
}

/// Runs `discover_host` across many candidate IPs in parallel and returns
/// just the ones that answered, in the same order they were given. This is
/// what makes `discover hosts` practical on anything wider than a single
/// address: without it, a /24 would mean up to 256 hosts probed one at a
/// time.
pub fn discover_hosts(ips: &[String]) -> Vec<String> {
    let flags = parallel_map(ips, |ip| discover_host(ip));
    ips.iter()
        .zip(flags)
        .filter_map(|(ip, up)| if up { Some(ip.clone()) } else { None })
        .collect()
}

/// Returns the list of open ports found on `ip`. `port_range` is an
/// optional "start-end" string (e.g. "1-1024"); when absent the fallback
/// path checks COMMON_PORTS instead of every port, to stay fast without
/// nmap's raw-socket scanning.
pub fn scan_ports(ip: &str, port_range: Option<&str>) -> Result<Vec<u16>, String> {
    if nmap_available() {
        let mut cmd = Command::new("nmap");
        match port_range {
            // An explicit "ports 1-1024" style range in the script maps
            // straight to nmap -p.
            Some(range) => {
                cmd.arg("-p").arg(range);
            }
            // No explicit range: let nmap use its own default port set
            // (its top ~1000 most common ports) rather than an arbitrary
            // "1-1024" cutoff, since that default already includes things
            // like 8080 that a hardcoded low range would miss.
            None => {}
        }
        let output = cmd
            .arg(ip)
            .output()
            .map_err(|e| format!("failed to run nmap: {}", e))?;
        let text = String::from_utf8_lossy(&output.stdout);
        return Ok(parse_nmap_ports(&text));
    }

    let candidates: Vec<u16> = match port_range {
        Some(range) => parse_port_range(range)?,
        None => COMMON_PORTS.to_vec(),
    };
    let is_open = parallel_map(&candidates, |&p| tcp_probe(ip, p).is_ok());
    let mut open: Vec<u16> = candidates
        .into_iter()
        .zip(is_open)
        .filter_map(|(p, ok)| if ok { Some(p) } else { None })
        .collect();
    open.sort_unstable();
    Ok(open)
}

/// Best-effort service name for each open port. Uses `nmap -sV` when
/// available; otherwise falls back to a small built-in port/service table,
/// which is intentionally conservative (it labels unknowns "unknown"
/// rather than guessing).
pub fn identify_services(ip: &str, ports: &[u16]) -> Vec<(u16, String)> {
    if nmap_available() && !ports.is_empty() {
        let port_list = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        if let Ok(output) = Command::new("nmap")
            .arg("-sV")
            .arg("-p")
            .arg(&port_list)
            .arg(ip)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let parsed = parse_nmap_services(&text);
            if !parsed.is_empty() {
                return parsed;
            }
        }
    }

    ports
        .iter()
        .map(|&p| (p, guess_service(p).to_string()))
        .collect()
}

fn tcp_probe(ip: &str, port: u16) -> std::io::Result<()> {
    let addr: SocketAddr = format!("{}:{}", ip, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no address resolved"))?;
    TcpStream::connect_timeout(&addr, Duration::from_millis(DEFAULT_TIMEOUT_MS))?;
    Ok(())
}

fn parse_port_range(range: &str) -> Result<Vec<u16>, String> {
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| format!("invalid port range '{}', expected e.g. '1-1024'", range))?;
    let start: u16 = start
        .parse()
        .map_err(|_| format!("invalid port range '{}'", range))?;
    let end: u16 = end
        .parse()
        .map_err(|_| format!("invalid port range '{}'", range))?;

    // Without nmap, a full 1-65535 connect scan would be far too slow, so
    // cap the contiguous sweep width. But silently dropping ports from the
    // range would be worse than being slow: always keep any COMMON_PORTS
    // that fall inside the requested range too, even past the cap, so a
    // request like "1-9000" still checks well-known ports such as 8080.
    const MAX_FALLBACK_PORTS: usize = 1024;
    let capped_end = end.min(start.saturating_add(MAX_FALLBACK_PORTS as u16));
    if capped_end < end {
        eprintln!(
            "warning: no nmap available, so 'scan ports {{ ports {} }}' only connect-scans {}-{} directly (plus common ports in range)",
            range, start, capped_end
        );
    }

    let mut ports: Vec<u16> = (start..=capped_end).collect();
    for &p in COMMON_PORTS {
        if p > capped_end && p >= start && p <= end && !ports.contains(&p) {
            ports.push(p);
        }
    }
    Ok(ports)
}

fn guess_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        3306 => "mysql",
        3389 => "rdp",
        8080 => "http-alt",
        _ => "unknown",
    }
}

fn parse_nmap_ports(nmap_output: &str) -> Vec<u16> {
    nmap_output
        .lines()
        .filter(|l| l.contains("/tcp") && l.contains("open"))
        .filter_map(|l| l.split('/').next())
        .filter_map(|p| p.trim().parse::<u16>().ok())
        .collect()
}

fn parse_nmap_services(nmap_output: &str) -> Vec<(u16, String)> {
    nmap_output
        .lines()
        .filter(|l| l.contains("/tcp") && l.contains("open"))
        .filter_map(|l| {
            let mut fields = l.split_whitespace();
            let port_field = fields.next()?; // e.g. "22/tcp"
            let port: u16 = port_field.split('/').next()?.parse().ok()?;
            fields.next(); // "open"
            let service = fields.next().unwrap_or("unknown").to_string();
            Some((port, service))
        })
        .collect()
}
