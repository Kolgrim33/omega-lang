// CVE correlation for identified service versions.
//
// A real CVE database only serves HTTPS, and Omega deliberately doesn't
// implement TLS encryption (same reasoning as SSH and the TLS cert
// checks — hand-rolled crypto isn't something to responsibly build).
// Instead this shells out to `curl` for the actual request, the same
// pattern scan.rs already uses for `nmap` — curl handles TLS, Omega
// never has to.
//
// The NVD API returns real JSON. Rather than write a general JSON
// parser (or risk mangling a vulnerability description through fragile
// string-slicing), this only extracts CVE IDs via targeted pattern
// matching and points to the authoritative NVD page for details —
// accurate and simple, rather than a parsed summary that could subtly
// misquote something security-relevant.
//
// No hardcoded fallback CVE list: stale or misremembered vulnerability
// data would be worse than no data. If curl or NVD is unreachable, this
// says so plainly and points to manual lookup instead.

use std::process::Command;
use std::time::Duration;

/// Best-effort extraction of a full version banner for one port, via a
/// dedicated `nmap -sV` call (separate from scan.rs's own service-ID
/// path, so this doesn't need to touch or depend on its internals).
pub fn get_service_banner(ip: &str, port: u16) -> Option<String> {
    let output = Command::new("nmap")
        .arg("-sV")
        .arg("-p")
        .arg(port.to_string())
        .arg(ip)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let port_marker = format!("{}/tcp", port);
    for line in text.lines() {
        if line.contains(&port_marker) && line.contains("open") {
            let mut fields = line.split_whitespace();
            fields.next()?; // "<port>/tcp"
            fields.next()?; // "open"
            fields.next()?; // short service name (e.g. "ssh")
            let rest: Vec<&str> = fields.collect();
            if rest.is_empty() {
                return None;
            }
            return Some(rest.join(" "));
        }
    }
    None
}

/// Heuristic: finds the first token that starts with a digit and
/// contains a dot (looks like a version number, e.g. "7.2", "2.4.49"),
/// treats everything before it as the product name. Works for common
/// banners ("OpenSSH 7.2 (protocol 2.0)" -> ("OpenSSH", "7.2")) but will
/// misparse irregular ones — this is explicitly best-effort, not a
/// guaranteed-correct version parser.
pub fn extract_product_version(banner: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = banner.split_whitespace().collect();
    for (i, tok) in tokens.iter().enumerate() {
        let cleaned = tok.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if cleaned
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
            && cleaned.contains('.')
        {
            let product = tokens[..i].join(" ");
            if product.is_empty() {
                return None;
            }
            return Some((product, cleaned.to_string()));
        }
    }
    None
}

/// Queries NVD's public API (via curl) for CVEs matching "<product>
/// <version>". Returns finding strings citing CVE IDs with a direct
/// link, or Ok(empty) if none were found for this exact query. Errs if
/// curl isn't available or the request itself fails — that's a tool
/// availability/network problem, distinct from "no CVEs found."
pub fn lookup_cves(product: &str, version: &str) -> Result<Vec<String>, String> {
    if !curl_available() {
        return Err(
            "curl not found on PATH — required for HTTPS CVE lookups since Omega doesn't implement TLS encryption; install curl, or check https://nvd.nist.gov/vuln/search manually".to_string(),
        );
    }

    let query = format!("{} {}", product, version).replace(' ', "+");
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=5",
        query
    );

    let output = Command::new("curl")
        .arg("-s")
        .arg("--max-time")
        .arg("10")
        .arg(&url)
        .output()
        .map_err(|e| format!("failed to run curl: {}", e))?;

    if !output.status.success() {
        return Err("curl request failed (network issue or NVD unreachable)".to_string());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let ids = extract_cve_ids(&text);

    Ok(ids
        .into_iter()
        .take(3)
        .map(|id| {
            format!(
                "Possible known vulnerability for {} {}: {} — see https://nvd.nist.gov/vuln/detail/{}",
                product, version, id, id
            )
        })
        .collect())
}

/// Scans for `"CVE-...` occurrences directly rather than parsing the
/// surrounding JSON structure — deliberately simple, robust to minor
/// formatting/spacing differences in the response.
fn extract_cve_ids(json_text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut search_from = 0;
    while let Some(rel_pos) = json_text[search_from..].find("\"CVE-") {
        let start = search_from + rel_pos + 1; // skip the opening quote
        if let Some(end_rel) = json_text[start..].find('"') {
            let id = json_text[start..start + end_rel].to_string();
            if !ids.contains(&id) {
                ids.push(id);
            }
            search_from = start + end_rel + 1;
        } else {
            break;
        }
    }
    ids
}

fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A short pause between consecutive lookups, as a good-faith courtesy
/// toward NVD's public rate limits for un-authenticated API access —
/// not a guaranteed-compliant rate limiter, just enough to avoid
/// hammering the endpoint during a multi-host scan.
pub fn rate_limit_pause() {
    std::thread::sleep(Duration::from_millis(2000));
}
