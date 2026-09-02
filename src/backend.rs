/// Anything that can discover a host, scan its ports, or identify
/// services on it. Nmap and the built-in TCP-connect fallback both
/// implement this instead of being hardcoded branches inside each
/// function in scan.rs — adding a new backend (SSH banner-grab, HTTP
/// probe, etc. per the design doc's "under the hood" diagram) means
/// writing a new impl here, not touching scan.rs's public API or
/// interpreter.rs at all.
pub trait ProbeBackend {
    fn name(&self) -> &'static str;

    /// True if `ip` responds (TCP connect on a probe port, or `nmap -sn`).
    fn discover_host(&self, ip: &str) -> bool;

    /// Open ports on `ip`. `port_range` is an optional "start-end" string
    /// (e.g. "1-1024"); None means "use this backend's default port set".
    fn scan_ports(&self, ip: &str, port_range: Option<&str>) -> Result<Vec<u16>, String>;

    /// Best-effort (port, service name) pairs for the given open ports.
    fn identify_services(&self, ip: &str, ports: &[u16]) -> Vec<(u16, String)>;
}
