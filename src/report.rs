// Structured report output (JSON / HTML) for `report to "..."`.
//
// Hand-rolled rather than pulling in serde_json or a templating crate,
// matching the project's zero-dependency design goal. Escaping is done
// manually for both formats — see json_escape / html_escape below.

use crate::interpreter::Host;
use crate::ip::{format_ipv4, Cidr};
use std::fs;

/// A single classified finding line, derived from an NSE script output
/// line. Classification is intentionally simple and conservative: nmap's
/// own script output already flags real vulnerabilities with the literal
/// word "VULNERABLE", so that's the most reliable signal available
/// without parsing each script's bespoke output format individually.
pub struct Finding {
    pub severity: &'static str, // "high" | "medium" | "info"
    pub text: String,
}

pub fn classify_nse_line(line: &str) -> Finding {
    let upper = line.to_uppercase();
    let severity = if upper.contains("VULNERABLE") {
        "high"
    } else if upper.contains("CVE-") {
        "medium"
    } else {
        "info"
    };
    Finding {
        severity,
        text: line.to_string(),
    }
}

pub fn write_json(
    path: &str,
    target: Option<Cidr>,
    scope: Option<Cidr>,
    hosts: &[Host],
) -> Result<(), String> {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"target\": {},\n", opt_cidr_json(target)));
    out.push_str(&format!("  \"authorized_scope\": {},\n", opt_cidr_json(scope)));
    out.push_str(&format!("  \"hosts_discovered\": {},\n", hosts.len()));
    out.push_str("  \"hosts\": [\n");
    for (i, host) in hosts.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"ip\": \"{}\",\n", json_escape(&host.ip)));
        out.push_str("      \"open_ports\": [\n");
        for (j, port) in host.open_ports.iter().enumerate() {
            let service = host
                .services
                .iter()
                .find(|(p, _)| p == port)
                .map(|(_, s)| s.as_str())
                .unwrap_or("unknown");
            out.push_str(&format!(
                "        {{ \"port\": {}, \"service\": \"{}\" }}{}\n",
                port,
                json_escape(service),
                if j + 1 < host.open_ports.len() { "," } else { "" }
            ));
        }
        out.push_str("      ],\n");
        match &host.os {
            Some(os) => out.push_str(&format!("      \"os\": \"{}\",\n", json_escape(os))),
            None => out.push_str("      \"os\": null,\n"),
        }
        out.push_str("      \"findings\": [\n");
        for (j, line) in host.nse_findings.iter().enumerate() {
            let f = classify_nse_line(line);
            out.push_str(&format!(
                "        {{ \"severity\": \"{}\", \"text\": \"{}\" }}{}\n",
                f.severity,
                json_escape(&f.text),
                if j + 1 < host.nse_findings.len() { "," } else { "" }
            ));
        }
        out.push_str("      ]\n");
        out.push_str(&format!(
            "    }}{}\n",
            if i + 1 < hosts.len() { "," } else { "" }
        ));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");

    fs::write(path, out).map_err(|e| format!("failed to write report to '{}': {}", path, e))
}

pub fn write_html(
    path: &str,
    target: Option<Cidr>,
    scope: Option<Cidr>,
    hosts: &[Host],
) -> Result<(), String> {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Omega Report</title>\n");
    out.push_str("<style>\nbody{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;}\n");
    out.push_str("h1{color:#58a6ff;} h2{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:4px;}\n");
    out.push_str(".finding{padding:4px 8px;margin:2px 0;border-radius:4px;}\n");
    out.push_str(".high{background:#3d1418;border-left:4px solid #f85149;}\n");
    out.push_str(".medium{background:#3d2e14;border-left:4px solid #d29922;}\n");
    out.push_str(".info{background:#161b22;border-left:4px solid #30363d;}\n");
    out.push_str("table{border-collapse:collapse;} td,th{padding:4px 12px;text-align:left;border-bottom:1px solid #30363d;}\n");
    out.push_str("</style></head><body>\n");
    out.push_str("<h1>Omega Security Report</h1>\n");
    out.push_str(&format!("<p><b>Target:</b> {}</p>\n", opt_cidr_html(target)));
    out.push_str(&format!("<p><b>Authorized scope:</b> {}</p>\n", opt_cidr_html(scope)));
    out.push_str(&format!("<p><b>Hosts discovered:</b> {}</p>\n", hosts.len()));

    for host in hosts {
        out.push_str(&format!("<h2>Host: {}</h2>\n", html_escape(&host.ip)));
        if !host.open_ports.is_empty() {
            out.push_str("<table><tr><th>Port</th><th>Service</th></tr>\n");
            for port in &host.open_ports {
                let service = host
                    .services
                    .iter()
                    .find(|(p, _)| p == port)
                    .map(|(_, s)| s.as_str())
                    .unwrap_or("unknown");
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td></tr>\n",
                    port,
                    html_escape(service)
                ));
            }
            out.push_str("</table>\n");
        }
        if let Some(os) = &host.os {
            out.push_str(&format!("<p><b>OS:</b> {}</p>\n", html_escape(os)));
        }
        if !host.nse_findings.is_empty() {
            out.push_str("<div>\n");
            for line in &host.nse_findings {
                let f = classify_nse_line(line);
                out.push_str(&format!(
                    "<div class=\"finding {}\">{}</div>\n",
                    f.severity,
                    html_escape(&f.text)
                ));
            }
            out.push_str("</div>\n");
        }
    }

    out.push_str("</body></html>\n");
    fs::write(path, out).map_err(|e| format!("failed to write report to '{}': {}", path, e))
}

fn opt_cidr_json(c: Option<Cidr>) -> String {
    match c {
        Some(c) => format!(
            "\"{}\"",
            json_escape(&format!("{}/{}", format_ipv4(c.base), c.prefix))
        ),
        None => "null".to_string(),
    }
}

fn opt_cidr_html(c: Option<Cidr>) -> String {
    match c {
        Some(c) => html_escape(&format!("{}/{}", format_ipv4(c.base), c.prefix)),
        None => "(none)".to_string(),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}
