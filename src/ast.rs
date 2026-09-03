// Omega AST.
//
// Deliberately small: this covers the first milestone (target, discover,
// scan ports, identify services, report) plus authorized_scope and a basic
// assessment {} block, since those are central to the language's "safe by
// design" pitch. New statement kinds get added here as the language grows.
#[derive(Debug, Clone)]
pub enum Stmt {
    Target(String),
    AuthorizedScope(String),
    // "discover" and "discover hosts" are accepted as the same statement
    // by the parser (the trailing "hosts" is optional sugar); there's
    // nothing to carry here unless a future discover variant (e.g.
    // "discover services") needs to distinguish itself.
    Discover,
    ScanPorts { options: ScanOptions },
    IdentifyServices,
    Report,
    Assessment { name: String, body: Vec<Stmt> },
}
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// e.g. "1-1024" or "1-65535". None means "use Omega's default range".
    pub ports: Option<String>,
    pub services: bool,
    pub timeout_secs: Option<u64>,
    /// Requests an OS fingerprint (maps to nmap -O). Requires nmap plus
    /// root/administrator privileges; unsupported backends (or nmap
    /// without sufficient privileges) report a clear error instead of
    /// silently doing nothing.
    pub os_detect: bool,
    /// Requests nmap's NSE scripting engine for the given category (e.g.
    /// "vuln", "default"). None means no NSE scripts requested.
    pub nse_scripts: Option<String>,
}
pub type Program = Vec<Stmt>;
