use crate::ast::{
    DnsScanOptions, ExportDestination, ExportFormat, Program, ReportDestination, ReportFormat,
    ScanOptions, Stmt, WebScanOptions,
};
use crate::dnschecks;
use crate::export;
use crate::ip::{format_ipv4, Cidr};
use crate::parallel::parallel_map;
use crate::report;
use crate::scan;
use crate::webchecks;

#[derive(Debug, Clone)]
pub struct Host {
    pub ip: String,
    pub open_ports: Vec<u16>,
    pub services: Vec<(u16, String)>,
    pub os: Option<String>,
    pub findings: Vec<String>,
}

pub struct Interpreter {
    authorized_scope: Option<Cidr>,
    target: Option<Cidr>,
    hosts: Vec<Host>,
    domain_findings: Vec<(String, Vec<String>)>,
}

const DEFAULT_WEB_PORTS: &[u16] = &[80, 8080, 8000, 8888, 443, 8443];

impl Interpreter {
    pub fn new() -> Self {
        Interpreter {
            authorized_scope: None,
            target: None,
            hosts: Vec::new(),
            domain_findings: Vec::new(),
        }
    }
    pub fn run(&mut self, program: &Program) -> Result<(), String> {
        for stmt in program {
            self.exec(stmt)?;
        }
        Ok(())
    }
    fn exec(&mut self, stmt: &Stmt) -> Result<(), String> {
        match stmt {
            Stmt::Target(addr) => {
                let cidr = Cidr::parse(addr)?;
                if self.authorized_scope.is_none() {
                    self.authorized_scope = Some(cidr);
                }
                self.target = Some(cidr);
                Ok(())
            }
            Stmt::AuthorizedScope(addr) => {
                self.authorized_scope = Some(Cidr::parse(addr)?);
                Ok(())
            }
            Stmt::Discover => self.exec_discover(),
            Stmt::ScanPorts { options } => self.exec_scan_ports(options),
            Stmt::ScanWeb { options } => self.exec_scan_web(options),
            Stmt::ScanDns { domain, options } => self.exec_scan_dns(domain, options),
            Stmt::IdentifyServices => self.exec_identify_services(),
            Stmt::Report { destination } => match destination {
                None => {
                    self.print_report();
                    Ok(())
                }
                Some(dest) => self.write_report(dest),
            },
            Stmt::ExportHosts { destination } => self.export_hosts(destination),
            Stmt::Assessment { name, body } => {
                println!("== assessment: {} ==", name);
                for inner in body {
                    self.exec(inner)?;
                }
                Ok(())
            }
        }
    }
    fn exec_discover(&mut self) -> Result<(), String> {
        let target = self
            .target
            .ok_or_else(|| "discover: no target set (use 'target <cidr>' first)".to_string())?;
        println!("discovering hosts in target range...");
        let mut in_scope_ips = Vec::new();
        for ip in target.hosts() {
            let ip_str = format_ipv4(ip);
            if self.in_scope(ip) {
                in_scope_ips.push(ip_str);
            } else {
                eprintln!("ERROR: target {} is outside authorized scope.", ip_str);
            }
        }

        let alive = scan::discover_hosts(&in_scope_ips);
        for ip_str in &alive {
            println!("  host up: {}", ip_str);
            self.hosts.push(Host {
                ip: ip_str.clone(),
                open_ports: Vec::new(),
                services: Vec::new(),
                os: None,
                findings: Vec::new(),
            });
        }
        if alive.is_empty() {
            println!("  no hosts responded");
        }
        Ok(())
    }

    fn exec_scan_ports(&mut self, options: &ScanOptions) -> Result<(), String> {
        if self.hosts.is_empty() {
            return Err(
                "scan ports: no discovered hosts to scan (run 'discover hosts' first)"
                    .to_string(),
            );
        }
        println!("scanning ports...");

        let scope = self.authorized_scope;
        let port_range = options.ports.as_deref();

        let results: Vec<Result<(String, Vec<u16>), String>> =
            parallel_map(&self.hosts, |host| -> Result<(String, Vec<u16>), String> {
                let ip_num = crate::ip::parse_ipv4(&host.ip)?;
                if !in_scope(scope, ip_num) {
                    eprintln!("ERROR: target {} is outside authorized scope.", host.ip);
                    return Ok((host.ip.clone(), Vec::new()));
                }
                let ports = scan::scan_ports(&host.ip, port_range)?;
                Ok((host.ip.clone(), ports))
            });

        for r in results {
            let (ip, ports) = r?;
            println!("  {}: {} open port(s)", ip, ports.len());
            if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                host.open_ports = ports;
            }
        }

        if options.services {
            self.exec_identify_services()?;
        }
        if options.os_detect {
            self.exec_os_detect()?;
        }
        if let Some(category) = &options.nse_scripts {
            self.exec_nse_scripts(category)?;
        }
        Ok(())
    }

    fn exec_scan_web(&mut self, options: &WebScanOptions) -> Result<(), String> {
        if self.hosts.is_empty() {
            return Err("scan web: no discovered hosts (run 'discover hosts' first)".to_string());
        }
        println!("running web checks...");

        let scope = self.authorized_scope;
        let explicit_port = options.port;
        let check_paths = options.paths;
        let check_headers = options.headers;

        let jobs: Vec<(String, u16)> = self
            .hosts
            .iter()
            .flat_map(|h| {
                let ports: Vec<u16> = match explicit_port {
                    Some(p) => vec![p],
                    None => h
                        .open_ports
                        .iter()
                        .copied()
                        .filter(|p| DEFAULT_WEB_PORTS.contains(p))
                        .collect(),
                };
                let ip = h.ip.clone();
                ports.into_iter().map(move |p| (ip.clone(), p))
            })
            .collect();

        if jobs.is_empty() {
            println!("  no web ports to check (run 'scan ports' first, or specify 'port <n>' explicitly)");
            return Ok(());
        }

        let results: Vec<(String, u16, Vec<String>)> = parallel_map(&jobs, |(ip, port)| {
            let ip_num = crate::ip::parse_ipv4(ip).unwrap_or(0);
            if !in_scope(scope, ip_num) {
                eprintln!("ERROR: target {} is outside authorized scope.", ip);
                return (ip.clone(), *port, Vec::new());
            }
            let mut findings = webchecks::run_checks(ip, *port, check_paths, check_headers);
            if (*port == 443 || *port == 8443) && findings.iter().any(|f| f.contains("failed")) {
                findings.push(
                    "note: HTTPS/TLS web checks are not yet supported by Omega — this port was probed as plain HTTP"
                        .to_string(),
                );
            }
            (ip.clone(), *port, findings)
        });

        for (ip, port, findings) in results {
            if findings.is_empty() {
                println!("  {}:{}: no findings", ip, port);
            } else {
                println!("  {}:{}: {} finding(s)", ip, port, findings.len());
            }
            if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                host.findings.extend(findings);
            }
        }

        Ok(())
    }

    fn exec_scan_dns(&mut self, domain: &str, options: &DnsScanOptions) -> Result<(), String> {
        if self.authorized_scope.is_none() {
            return Err(
                "scan dns: no authorized_scope declared — set one before running DNS checks, even though DNS lookups aren't IP-scoped".to_string(),
            );
        }
        println!("running DNS checks on {}...", domain);
        let mut findings = Vec::new();
        if options.spf {
            findings.extend(dnschecks::check_spf(domain));
        }
        if options.dmarc {
            findings.extend(dnschecks::check_dmarc(domain));
        }
        if options.subdomains {
            findings.extend(dnschecks::enumerate_subdomains(domain));
        }

        if findings.is_empty() {
            println!("  no findings");
        } else {
            for f in &findings {
                println!("  {}", f);
            }
        }
        self.domain_findings.push((domain.to_string(), findings));
        Ok(())
    }

    fn exec_identify_services(&mut self) -> Result<(), String> {
        println!("identifying services...");
        let scannable: Vec<&Host> = self.hosts.iter().filter(|h| !h.open_ports.is_empty()).collect();
        let results: Vec<(String, Vec<(u16, String)>)> = parallel_map(&scannable, |h| {
            (h.ip.clone(), scan::identify_services(&h.ip, &h.open_ports))
        });

        for (ip, services) in results {
            if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                host.services = services;
            }
        }
        Ok(())
    }

    fn exec_os_detect(&mut self) -> Result<(), String> {
        println!("detecting OS...");
        let ips: Vec<String> = self.hosts.iter().map(|h| h.ip.clone()).collect();
        let results: Vec<(String, Result<String, String>)> =
            parallel_map(&ips, |ip| (ip.clone(), scan::detect_os(ip)));

        for (ip, result) in results {
            match result {
                Ok(os) => {
                    println!("  {}: {}", ip, os);
                    if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                        host.os = Some(os);
                    }
                }
                Err(e) => {
                    eprintln!("  {}: OS detection failed ({})", ip, e);
                }
            }
        }
        Ok(())
    }

    fn exec_nse_scripts(&mut self, category: &str) -> Result<(), String> {
        println!("running NSE scripts ({})...", category);
        let ips: Vec<String> = self.hosts.iter().map(|h| h.ip.clone()).collect();
        let results: Vec<(String, Result<Vec<String>, String>)> = parallel_map(&ips, |ip| {
            (ip.clone(), scan::run_nse_scripts(ip, category))
        });

        for (ip, result) in results {
            match result {
                Ok(findings) => {
                    if findings.is_empty() {
                        println!("  {}: no findings", ip);
                    } else {
                        println!("  {}: {} finding(s)", ip, findings.len());
                    }
                    if let Some(host) = self.hosts.iter_mut().find(|h| h.ip == ip) {
                        host.findings.extend(findings);
                    }
                }
                Err(e) => {
                    eprintln!("  {}: NSE scripts failed ({})", ip, e);
                }
            }
        }
        Ok(())
    }

    fn write_report(&self, dest: &ReportDestination) -> Result<(), String> {
        match dest.format {
            ReportFormat::Json => report::write_json(
                &dest.path,
                self.target,
                self.authorized_scope,
                &self.hosts,
                &self.domain_findings,
            )?,
            ReportFormat::Html => report::write_html(
                &dest.path,
                self.target,
                self.authorized_scope,
                &self.hosts,
                &self.domain_findings,
            )?,
        }
        println!("report written to {}", dest.path);
        Ok(())
    }

    fn export_hosts(&self, dest: &ExportDestination) -> Result<(), String> {
        if self.hosts.is_empty() {
            return Err(
                "export hosts: no discovered hosts to export (run 'discover hosts' first)"
                    .to_string(),
            );
        }
        match dest.format {
            ExportFormat::Txt => export::write_txt(&dest.path, &self.hosts)?,
            ExportFormat::Csv => export::write_csv(&dest.path, &self.hosts)?,
        }
        println!("exported {} host(s) to {}", self.hosts.len(), dest.path);
        Ok(())
    }

    fn in_scope(&self, ip: u32) -> bool {
        in_scope(self.authorized_scope, ip)
    }
    fn print_report(&self) {
        println!();
        println!("=================== omega report ===================");
        if let Some(t) = self.target {
            println!("target: {}", cidr_display(t));
        }
        if let Some(s) = self.authorized_scope {
            println!("authorized scope: {}", cidr_display(s));
        }
        println!("hosts discovered: {}", self.hosts.len());
        println!();
        for host in &self.hosts {
            println!("host: {}", host.ip);
            if host.open_ports.is_empty() {
                println!("  ports: none scanned / none open");
            } else if host.services.is_empty() {
                for p in &host.open_ports {
                    println!("  port {}: open", p);
                }
            } else {
                for (p, svc) in &host.services {
                    println!("  port {}: open ({})", p, svc);
                }
            }
            if let Some(os) = &host.os {
                println!("  os: {}", os);
            }
            if !host.findings.is_empty() {
                println!("  findings:");
                for line in &host.findings {
                    println!("    {}", line);
                }
            }
            println!();
        }
        if !self.domain_findings.is_empty() {
            println!("domains checked:");
            for (domain, findings) in &self.domain_findings {
                println!("  {}", domain);
                for f in findings {
                    println!("    {}", f);
                }
            }
            println!();
        }
        println!("======================================================");
    }
}
fn cidr_display(c: Cidr) -> String {
    format!("{}/{}", format_ipv4(c.base), c.prefix)
}
fn in_scope(scope: Option<Cidr>, ip: u32) -> bool {
    match scope {
        Some(s) => s.contains(ip),
        None => true,
    }
}
