// Backends for discover / scan ports / identify services / OS detection /
// NSE scripts.
//
// This is exactly the "under the hood" translation layer described in the
// Omega design doc: the .omega script never mentions Nmap, it just says
// `discover hosts` / `scan ports` / `identify services`, and this module
// decides how to actually do that. Nmap is used when it's on PATH; when
// it isn't (e.g. this sandbox), Omega falls back to a plain TCP-connect
// probe so the language still runs end to end — though OS detection and
// NSE scripts have no meaningful TCP-connect equivalent, so the fallback
// backend reports those as unsupported via ProbeBackend's default methods
// rather than faking a result.

use crate::backend::ProbeBackend;
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
static HAS_ROOT: OnceLock<bool> = OnceLock::new();

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

/// Whether the current process has root/administrator privileges. Cached
/// like nmap_available above. Shells out to `id -u` rather than pulling in
/// a libc/nix crate dependency, matching the project's zero-dependency
/// design goal — this only needs to work on the Unix-like systems `id` is
/// available on.
fn has_root_privileges() -> bool {
    *HAS_ROOT.get_or_init(|| {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    })
}

/// Picks nmap when it's on PATH, otherwise the TCP-connect fallback.
/// Both backends are zero-sized (unit structs), so boxing them is cheap
/// and this can be called freely without worrying about reuse.
pub fn select_backend() -> Box<dyn ProbeBackend + Send + Sync> {
    if nmap_available() {
        Box::new(NmapBackend)
    } else {
        Box::new(TcpConnectBackend)
    }
}

pub struct NmapBackend;

impl ProbeBackend for NmapBackend {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn discover_host(&self, ip: &str) -> bool {
        if let Ok(output) = Command::new("nmap").arg("-sn").arg(ip).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            return text.contains("Host is up");
        }
        // nmap is on PATH but this invocation failed (permissions, etc.)
        // — fall back to a direct probe rather than silently reporting
        // the host as down.
        TcpConnectBackend.discover_host(ip)
    }

    fn scan_ports(&self, ip: &str, port_range: Option<&str>) -> Result<Vec<u16>, String> {
        let mut cmd = Command::new("nmap");
        match port_range {
            Some(range) => {
                cmd.arg("-p").arg(range);
            }
            None => {}
        }
        let output = cmd
            .arg(ip)
            .output()
            .map_err(|e| format!("failed to run nmap: {}", e))?;
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_nmap_ports(&text))
    }

    fn identify_services(&self, ip: &str, ports: &[u16]) -> Vec<(u16, String)> {
        if ports.is_empty() {
            return Vec::new();
        }
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
        TcpConnectBackend.identify_services(ip, ports)
    }

    fn detect_os(&self, ip: &str) -> Result<String, String> {
        // nmap -O needs raw socket access, which normally means root.
        // Checking up front gives a clear, actionable message instead of
        // nmap's own much less friendly failure output.
        if !has_root_privileges() {
            return Err(
                "OS detection requires root privileges (nmap -O needs raw socket access); re-run with sudo".to_string(),
            );
        }
        let output = Command::new("nmap")
            .arg("-O")
            .arg(ip)
            .output()
            .map_err(|e| format!("failed to run nmap -O: {}", e))?;
        let text = String::from_utf8_lossy(&output.stdout);
        parse_nmap_os(&text)
            .ok_or_else(|| format!("nmap -O produced no confident OS match for {}", ip))
    }

    fn run_nse_scripts(&self, ip: &str, category: &str) -> Result<Vec<String>, String> {
        let output = Command::new("nmap")
            .arg("--script")
            .arg(category)
            .arg(ip)
            .output()
            .map_err(|e| format!("failed to run nmap --script {}: {}", category, e))?;
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(parse_nmap_script_output(&text))
    }
}

pub struct TcpConnectBackend;

impl ProbeBackend for TcpConnectBackend {
    fn name(&self) -> &'static str {
        "tcp-connect"
    }

    fn discover_host(&self, ip: &str) -> bool {
        let results = parallel_map(COMMON_PORTS, |&p| tcp_probe(ip, p).is_ok());
        results.into_iter().any(|up| up)
    }

    fn scan_ports(&self, ip: &str, port_range: Option<&str>) -> Result<Vec<u16>, String> {
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

    fn identify_services(&self, _ip: &str, ports: &[u16]) -> Vec<(u16, String)> {
        ports
            .iter()
            .map(|&p| (p, guess_service(p).to_string()))
            .collect()
    }

    // detect_os and run_nse_scripts intentionally not overridden here —
    // TcpConnectBackend inherits ProbeBackend's default "unsupported,
    // requires nmap" implementations, since there's no honest
    // TCP-connect equivalent for either.
}

// ---- Public API — unchanged signatures for existing functions, so
// interpreter.rs needs no edits for those. Two new functions added for
// OS detection and NSE scripts. ----

pub fn discover_host(ip: &str) -> bool {
    select_backend().discover_host(ip)
}

pub fn discover_hosts(ips: &[String]) -> Vec<String> {
    let backend = select_backend();
    let flags = parallel_map(ips, |ip| backend.discover_host(ip));
    ips.iter()
        .zip(flags)
        .filter_map(|(ip, up)| if up { Some(ip.clone()) } else { None })
        .collect()
}

pub fn scan_ports(ip: &str, port_range: Option<&str>) -> Result<Vec<u16>, String> {
    select_backend().scan_ports(ip, port_range)
}

pub fn identify_services(ip: &str, ports: &[u16]) -> Vec<(u16, String)> {
    select_backend().identify_services(ip, ports)
}

/// Best-effort OS fingerprint for `ip`. Err if unsupported by the
/// selected backend (TCP-connect fallback) or if nmap lacks sufficient
/// privileges for -O.
pub fn detect_os(ip: &str) -> Result<String, String> {
    select_backend().detect_os(ip)
}

/// Runs nmap's NSE script `category` (e.g. "vuln") against `ip`.
pub fn run_nse_scripts(ip: &str, category: &str) -> Result<Vec<String>, String> {
    select_backend().run_nse_scripts(ip, category)
}

// ---- Shared helpers (unchanged from before) ----

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
            let port_field = fields.next()?;
            let port: u16 = port_field.split('/').next()?.parse().ok()?;
            fields.next();
            let service = fields.next().unwrap_or("unknown").to_string();
            Some((port, service))
        })
        .collect()
}

/// Extracts an OS guess from `nmap -O` output. Prefers the confident
/// "OS details:" line; falls back to the first "Aggressive OS guesses:"
/// entry (before the confidence percentage) when nmap wasn't certain
/// enough to print OS details directly.
fn parse_nmap_os(nmap_output: &str) -> Option<String> {
    for line in nmap_output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("OS details: ") {
            return Some(rest.to_string());
        }
    }
    for line in nmap_output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Aggressive OS guesses: ") {
            let first = rest.split(',').next().unwrap_or(rest).trim();
            return Some(first.to_string());
        }
    }
    None
}

/// NSE script output lines are the ones nmap prefixes with "|" (e.g.
/// "|_http-title: ..." or "| vulners: ..."). Everything else in the
/// output is the normal port-table text, which callers already get from
/// scan_ports/identify_services, so only the script lines are kept here.
fn parse_nmap_script_output(nmap_output: &str) -> Vec<String> {
    nmap_output
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .map(|l| l.trim().to_string())
        .collect()
}
