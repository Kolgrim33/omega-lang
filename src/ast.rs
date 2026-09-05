// Omega AST.
#[derive(Debug, Clone)]
pub enum Stmt {
    Target(String),
    AuthorizedScope(String),
    Discover,
    ScanPorts { options: ScanOptions },
    ScanWeb { options: WebScanOptions },
    ScanDns { domain: String, options: DnsScanOptions },
    ScanNetwork,
    IdentifyServices,
    Report { destination: Option<ReportDestination> },
    ExportHosts { destination: ExportDestination },
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
    pub port: Option<u16>,
}
#[derive(Debug, Clone, Default)]
pub struct DnsScanOptions {
    pub spf: bool,
    pub dmarc: bool,
    pub subdomains: bool,
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
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Txt,
    Csv,
}
#[derive(Debug, Clone)]
pub struct ExportDestination {
    pub path: String,
    pub format: ExportFormat,
}
pub type Program = Vec<Stmt>;
