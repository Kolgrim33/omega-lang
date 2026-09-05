// DNS-specific security checks: SPF/DMARC record presence (email
// spoofing protection), and subdomain enumeration against a curated
// wordlist. Zone transfer (AXFR) testing is not implemented yet — see
// the README's "what's next" list.

use crate::dns::{self, RecordType};

const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "webmail", "ftp", "admin", "portal", "vpn", "remote",
    "api", "dev", "test", "staging", "git", "jenkins", "jira",
    "confluence", "grafana", "kibana", "monitor", "status", "ns1", "ns2",
    "mx", "smtp", "blog", "shop", "cdn", "cpanel", "autodiscover", "owa",
    "sso", "auth", "app", "beta",
];

pub fn check_spf(domain: &str) -> Vec<String> {
    let mut findings = Vec::new();
    match dns::query(domain, RecordType::Txt) {
        Ok(records) => {
            let spf = records.iter().find(|r| r.starts_with("v=spf1"));
            match spf {
                Some(record) => findings.push(format!("SPF record present: {}", record)),
                None => findings.push(
                    "Missing SPF record — domain is more vulnerable to email spoofing"
                        .to_string(),
                ),
            }
        }
        Err(e) => findings.push(format!("SPF check failed: {}", e)),
    }
    findings
}

pub fn check_dmarc(domain: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let dmarc_domain = format!("_dmarc.{}", domain);
    match dns::query(&dmarc_domain, RecordType::Txt) {
        Ok(records) => {
            let dmarc = records.iter().find(|r| r.starts_with("v=DMARC1"));
            match dmarc {
                Some(record) => findings.push(format!("DMARC record present: {}", record)),
                None => findings.push(
                    "Missing DMARC record — domain is more vulnerable to email spoofing"
                        .to_string(),
                ),
            }
        }
        Err(_) => findings.push(
            "Missing DMARC record — domain is more vulnerable to email spoofing".to_string(),
        ),
    }
    findings
}

/// Checks each candidate subdomain for an A record. Sequential rather
/// than parallelized: DNS over UDP plus a small curated wordlist keeps
/// this fast enough without needing a rate-limiting story yet — worth
/// revisiting if the wordlist grows much larger.
pub fn enumerate_subdomains(domain: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for sub in SUBDOMAIN_WORDLIST {
        let candidate = format!("{}.{}", sub, domain);
        if let Ok(records) = dns::query(&candidate, RecordType::A) {
            if !records.is_empty() {
                findings.push(format!("{}: resolves to {}", candidate, records.join(", ")));
            }
        }
    }
    findings
}
