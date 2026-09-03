// Omega AST.
#[derive(Debug, Clone)]
pub enum Stmt {
    Target(String),
    AuthorizedScope(String),
    Discover,
    ScanPorts { options: ScanOptions },
    ScanWeb { options: WebScanOptions },
    IdentifyServices,
    Report { destination: Option<ReportDestination> },
    Assessment { name: String, body: Vec<Stmt> },
}
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub ports: Option<String>,
    pub services: bool,
    pub timeout_secs: Option<u64>,
    pub os_detect: bool,
    pub nse_scripts: Option<String>,
}
#[derive(Debug, Clone, Default)]
pub struct WebScanOptions {
    pub paths: bool,
    pub headers: bool,
    /// Explicit port to check. None means "try common web ports among
    /// this host's already-discovered open ports".
    pub port: Option<u16>,
}
#[derive(Debug, Clone)]
pub enum ReportFormat {
    Json,
    Html,
}
#[derive(Debug, Clone)]
pub struct ReportDestination {
    pub path: String,
    pub format: ReportFormat,
}
pub type Program = Vec<Stmt>;
