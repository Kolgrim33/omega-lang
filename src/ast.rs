// Omega AST.
#[derive(Debug, Clone)]
pub enum Stmt {
    Target(String),
    AuthorizedScope(String),
    Discover,
    ScanPorts { options: ScanOptions },
    IdentifyServices,
    /// `report` (destination: None, prints to stdout) or
    /// `report to "findings.json"` / `report to "findings.html"`.
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
