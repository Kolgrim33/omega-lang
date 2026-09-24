// Purpose-built HTTP vulnerability checks — Omega's equivalent of nikto's
// core job, distinct from nmap's generic NSE "vuln" category. Two checks:
// a curated list of commonly-exposed sensitive paths (admin panels,
// leaked credentials/config, backups), and a check for missing
// recommended security headers.
//
// Deliberately scoped: this is not an attempt to reach nikto's
// thousands-of-signatures database. It's a focused, maintainable set of
// high-value checks, with room to grow the path list over time.

use crate::http;
use std::time::Duration;

const COMMON_PATHS: &[(&str, &str)] = &[
    ("/admin/", "Possible admin panel"),
    ("/administrator/", "Possible admin panel"),
    ("/wp-admin/", "WordPress admin panel"),
    ("/wp-login.php", "WordPress login page"),
    ("/phpmyadmin/", "phpMyAdmin panel"),
    ("/.git/config", "Exposed git repository config"),
    ("/.git/HEAD", "Exposed git repository"),
    ("/.svn/entries", "Exposed subversion repository"),
    ("/.env", "Exposed environment file (often contains secrets)"),
    ("/.htaccess", "Exposed Apache config file"),
    ("/.htpasswd", "Exposed Apache password file"),
    ("/config.php", "Possible exposed config file"),
    ("/configuration.php", "Possible exposed config file (Joomla)"),
    ("/web.config", "Exposed IIS config file"),
    ("/backup.sql", "Possible database backup"),
    ("/backup.zip", "Possible backup archive"),
    ("/db.sql", "Possible database backup"),
    ("/database.sql", "Possible database backup"),
    ("/.DS_Store", "Exposed macOS directory metadata (can leak file listing)"),
    ("/server-status", "Apache mod_status page (can leak internal info)"),
    ("/server-info", "Apache mod_info page"),
    ("/phpinfo.php", "Exposed phpinfo() page (leaks server config)"),
    ("/info.php", "Possible exposed phpinfo() page"),
    ("/test.php", "Possible test/debug file left on server"),
    ("/console/", "Possible admin/debug console"),
    ("/actuator/", "Exposed Spring Boot Actuator"),
    ("/actuator/env", "Exposed Spring Boot environment endpoint"),
    ("/swagger.json", "Exposed API schema"),
    ("/swagger-ui.html", "Exposed API documentation UI"),
    ("/crossdomain.xml", "Flash cross-domain policy (legacy, can be overly permissive)"),
    ("/.aws/credentials", "Possible exposed AWS credentials file"),
    ("/id_rsa", "Possible exposed SSH private key"),
    ("/conf.php","just a shorter version of config ")
    
];

/// Headers whose *absence* is itself a finding.
const EXPECTED_SECURITY_HEADERS: &[&str] = &[
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
];

const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// Runs the requested checks against `host:port` and returns finding
/// lines in the same plain-string style as NSE findings, so they flow
/// through the same report/severity pipeline.
pub fn run_checks(
    host: &str,
    port: u16,
    check_paths: bool,
    check_headers: bool,
    check_waf: bool,
) -> Vec<String> {
    let timeout = Duration::from_millis(DEFAULT_TIMEOUT_MS);
    let mut findings = Vec::new();

    // A baseline request to "/" gets the server banner and, if requested,
    // doubles as the header check — no need for a second request.
    match http::get(host, port, "/", timeout) {
        Ok(resp) => {
            if let Some((_, server)) = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("Server"))
            {
                findings.push(format!(
                    "Server banner: {} (version disclosure — confirm this is not an outdated/vulnerable version)",
                    server
                ));
            }
            if check_headers {
                for expected in EXPECTED_SECURITY_HEADERS {
                    let present = resp
                        .headers
                        .iter()
                        .any(|(k, _)| k.eq_ignore_ascii_case(expected));
                    if !present {
                        findings.push(format!("Missing security header: {}", expected));
                    }
                }
            }
            if check_waf {
                for product in detect_waf(&resp.headers) {
                    findings.push(format!(
                        "Possible WAF/CDN detected: {} (interpret other findings accordingly — a blocked check may mean filtered, not necessarily safe)",
                        product
                    ));
                }
            }
        }
        Err(e) => {
            findings.push(format!("baseline request to / failed: {}", e));
            return findings; // host isn't answering HTTP — no point path-probing
        }
    }

    if check_paths {
        for (path, label) in COMMON_PATHS {
            if let Ok(resp) = http::get(host, port, path, timeout) {
                if resp.status == 200 || resp.status == 401 || resp.status == 403 {
                    findings.push(format!(
                        "{}: {} ({} {})",
                        path,
                        label,
                        resp.status,
                        status_text(resp.status)
                    ));
                }
            }
            // 404 and connection errors are the expected, uninteresting case.
        }
    }

    findings
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        _ => "",
    }
}

/// Passive WAF/CDN fingerprinting — reuses the headers already fetched
/// by the baseline request, no extra probing. Two kinds of signature:
/// a known substring within a specific header's value (e.g. "cloudflare"
/// in the Server header), or the mere presence of a vendor-specific
/// header regardless of its value.
const WAF_HEADER_VALUE_SIGNATURES: &[(&str, &str, &str)] = &[
    ("server", "cloudflare", "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("server", "sucuri", "Sucuri"),
    ("server", "big-ip", "F5 BIG-IP ASM"),
    ("server", "barracuda", "Barracuda WAF"),
    ("via", "cloudfront", "AWS CloudFront (possibly AWS WAF)"),
];

const WAF_HEADER_PRESENCE_SIGNATURES: &[(&str, &str)] = &[
    ("cf-ray", "Cloudflare"),
    ("cf-cache-status", "Cloudflare"),
    ("x-amz-cf-id", "AWS CloudFront (possibly AWS WAF)"),
    ("x-akamai-transformed", "Akamai"),
    ("x-iinfo", "Imperva/Incapsula"),
    ("x-cdn", "Incapsula/other CDN-WAF"),
    ("x-sucuri-id", "Sucuri"),
    ("x-sucuri-cache", "Sucuri"),
];

fn detect_waf(headers: &[(String, String)]) -> Vec<String> {
    let mut detected: Vec<String> = Vec::new();
    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        let value_lower = value.to_lowercase();
        for (hdr, substr, product) in WAF_HEADER_VALUE_SIGNATURES {
            if name_lower == *hdr && value_lower.contains(substr) && !detected.iter().any(|d| d == product) {
                detected.push(product.to_string());
            }
        }
        for (hdr, product) in WAF_HEADER_PRESENCE_SIGNATURES {
            if name_lower == *hdr && !detected.iter().any(|d| d == product) {
                detected.push(product.to_string());
            }
        }
    }
    detected
}
