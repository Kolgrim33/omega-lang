use crate::ast::{Program, ScanOptions, Stmt};
use crate::ip::{format_ipv4, Cidr};
use crate::parallel::parallel_map;
use crate::scan;

#[derive(Debug, Clone)]
pub struct Host {
    pub ip: String,
    pub open_ports: Vec<u16>,
    pub services: Vec<(u16, String)>,
}

pub struct Interpreter {
    /// Where operations are allowed to run. Set explicitly via
    /// `authorized_scope`, or implicitly to the first `target` declared if
    /// no explicit scope was given. This is the "safe by design" piece
    /// from the language spec: scope is a runtime property, not just a
    /// convention.
    authorized_scope: Option<Cidr>,
    target: Option<Cidr>,
    hosts: Vec<Host>,
}

impl Interpreter {
    pub fn new() -> Self {
        Interpreter {
            authorized_scope: None,
            target: None,
            hosts: Vec::new(),
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
            Stmt::IdentifyServices => self.exec_identify_services(),
            Stmt::Report => {
                self.print_report();
                Ok(())
            }
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

        // Scope enforcement happens first and sequentially (it's cheap and
        // the ordering of ERROR lines should match the target list), then
        // the actual liveness probing for in-scope hosts runs in parallel
        // so a /24 doesn't mean 254 sequential connect timeouts.
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

        // Scan every host's ports in parallel; scope is re-checked per
        // host (defensive, in case scope was narrowed after discover) but
        // the network probing itself is what actually benefits from
        // running concurrently.
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
