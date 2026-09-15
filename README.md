# Omega

<img width="240" alt="omegalogo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />

Omega is a security-first programming language for cybersecurity
automation. Instead of writing Python calls into scanning libraries, you
describe the security operation you want:
set my_target = "192.168.1.0/24"

target $my_target
audit_log "engagement.jsonl"
discover hosts
scan ports { services os_detect nse_scripts "vuln" cve_lookup }
scan web { paths headers }
scan tls
scan creds
scan network
scan ptr
scan dns "example.com" { spf dmarc subdomains }

for each host {
if port 22 open {
report
}
}

export hosts to "targets.txt"
report to "findings.json"


## Install
curl -fsSL https://raw.githubusercontent.com/Kolgrim33/omega-lang/master/install.sh | sh


Downloads a prebuilt binary for Linux or macOS — no Rust or cargo
required. Then run scripts directly:
omega examples/first_milestone.omg


(Building from source is also supported — see below.)

## What this build actually does

This is a real tree-walking interpreter, not a mockup:

- **Lexer/parser** (`src/lexer.rs`, `src/parser.rs`, `src/ast.rs`) — turns
  `.omega`/`.omg` source into an AST covering `target`,
  `authorized_scope`, `discover [hosts]`, `scan ports { ... }`,
  `scan web { ... }`, `scan dns "..." { ... }`, `scan network`,
  `scan ptr`, `scan creds`, `scan tls { ... }`, `identify services`,
  `report [to "..."]`, `export hosts to "..."`, `audit_log "..."`,
  `for each host { ... }`, `if <condition> { ... }`, and
  `assessment "name" { ... }` blocks.
- **Scope enforcement** (`src/interpreter.rs`) — `authorized_scope` (or the
  first `target`, implicitly) is checked before every host is touched. A
  target outside scope is refused at runtime with
  `ERROR: target X is outside authorized scope.` instead of silently
  running.
- **Compile-time variables** (`src/vars.rs`) — `set name = "value"`
  lines are extracted before the lexer ever runs, and any `$name`
  elsewhere in the script is textually substituted with that value.
  This is NOT a runtime variable system — a value can't depend on a
  scan result, only an earlier `set` in the same script. Chosen over
  deep AST integration because several fields (e.g. port numbers) are
  parsed immediately during parsing, so a `$var` there would break
  parsing before substitution could happen; this approach needs zero
  changes to the lexer, parser, or interpreter.
- **Control flow** (`src/ast.rs`, `src/interpreter.rs`) — `for each host {
  ... }` narrows the interpreter's host list to one host per iteration
  (so every existing `scan_*` method works inside the loop with zero
  changes, since they already operate on "whatever hosts currently
  exist"), then merges results back afterward. `if port <n> open { ... }`
  and `if os contains "<text>" { ... }` are the two supported
  conditions — not a general expression language, just these two narrow,
  practical checks.
- **Real network backends** (`src/backend.rs`, `src/scan.rs`) — host
  discovery, port scanning, service identification, OS fingerprinting,
  and NSE scripts all actually run, via a `ProbeBackend` trait so new
  backends can be added without touching the interpreter:
  - if `nmap` is on PATH, Omega shells out to it (`-sn` for discovery,
    `-p`/default port set for scanning, `-sV` for service ID, `-O` for OS
    fingerprinting, `--script <category>` for NSE) and parses its output.
    OS detection checks for root privileges up front and fails with a
    clear message rather than nmap's less friendly error; NSE and OS
    scans carry timeouts (`--script-timeout`, `--host-timeout`) so a
    script category with a long internal timeout can't hang a run
    indefinitely;
  - if `nmap` isn't installed, Omega falls back to its own parallel
    TCP-connect probing plus a small built-in port/service table for
    discovery/scanning/service-ID, so the language still runs end to end
    with zero external tools. OS detection and NSE scripts have no honest
    TCP-connect equivalent, so the fallback backend reports those as
    unsupported rather than faking a result.
- **CVE correlation** (`src/cve.rs`) — the `cve_lookup` flag inside `scan
  ports { }` looks up known vulnerabilities for each identified service
  version. Shells out to `curl` for the actual HTTPS request to NVD's
  public API (Omega doesn't implement TLS encryption, so this follows
  the same pattern `nmap` shelling-out already uses). Extracts CVE IDs
  via targeted pattern matching rather than a general JSON parser, and
  links to the authoritative NVD page instead of risking a mangled
  description through fragile parsing. Product/version extraction from
  an `nmap -sV` banner is a best-effort heuristic and will misparse some
  irregular banners. No hardcoded fallback CVE list — stale security
  data would be worse than none. Runs sequentially with a pause between
  lookups, as a courtesy toward NVD's public rate limits.
- **HTTP vulnerability scanning** (`src/http.rs`, `src/webchecks.rs`) —
  `scan web { paths headers }` is Omega's purpose-built equivalent of
  nikto, distinct from nmap's generic NSE vuln category:
  - a hand-rolled, zero-dependency HTTP/1.1 client checks a curated list
    of ~30 commonly-exposed sensitive paths (`.git/config`, `.env`,
    admin panels, backup files, exposed credentials/keys) and flags
    anything that responds 200/401/403;
  - a header check flags missing recommended security headers
    (`Strict-Transport-Security`, `X-Frame-Options`,
    `X-Content-Type-Options`, `Content-Security-Policy`,
    `Referrer-Policy`);
  - runs against a host's already-discovered open web ports
    (80/8080/8000/8888/443/8443) or an explicit `port <n>`. HTTPS ports
    are currently probed as plain HTTP — TLS support isn't implemented
    for actually fetching content (see `scan tls` below for what TLS
    support does exist), and the report says so explicitly rather than
    silently misreporting an HTTPS-only host.
- **TLS certificate and protocol checks** (`src/tlscheck.rs`) — `scan
  tls` performs a partial, non-cryptographic TLS handshake: it sends a
  ClientHello, reads the plaintext ServerHello and Certificate messages
  (unencrypted for TLS 1.2 and earlier), then disconnects — no key
  exchange, encryption, or signature verification is performed, the same
  crypto-avoidance boundary as SSH being excluded from `scan creds`.
  - extracts certificate expiry, subject, and issuer via a simplified
    hand-rolled X.509 DER parser;
  - separately probes whether the server still accepts TLS 1.0/1.1, and
    whether it accepts a curated list of deliberately weak/broken cipher
    suites (NULL, EXPORT, RC4, DES, 3DES);
  - known limitation: TLS 1.3's Certificate message is itself encrypted,
    so certificate details aren't readable this way on 1.3-only servers
    (only the negotiated version/cipher are visible). This does **not**
    let `scan web` fetch real HTTPS content — that needs a full,
    encrypting TLS client, a separate and much larger feature.
- **Default credential checks** (`src/credcheck.rs`) — `scan creds` tests
  a small, curated list of well-known factory-default logins (~10 pairs,
  not a wordlist) against services already discovered open: FTP, Telnet,
  and HTTP Basic Auth. Stops at the first hit per service; HTTP checks
  only run if the baseline unauthenticated request is already rejected
  (401). SSH is deliberately excluded — a correct client needs real
  cryptographic key exchange that can't be responsibly hand-rolled
  without a dedicated crypto library. Telnet support is explicitly
  best-effort/heuristic (IAC sequences are stripped rather than properly
  negotiated, and success is guessed from prompt text).
- **DNS and email security checks** (`src/dns.rs`, `src/dnschecks.rs`) —
  `scan dns "domain" { spf dmarc subdomains }`:
  - a hand-rolled, zero-dependency DNS client (raw UDP, RFC 1035 wire
    format — no external resolver crate) checks for SPF and DMARC TXT
    records (missing either is a real, common email-spoofing exposure);
  - subdomain enumeration against a curated wordlist of ~34 common names.
    Note: this is wordlist-based, not Certificate-Transparency-based —
    real recon tools like subfinder/amass discover far more via
    crt.sh-style CT log queries, which Omega doesn't do yet;
  - `scan dns` requires `authorized_scope` to already be declared in the
    script (even though DNS lookups against a public resolver aren't
    IP-scoped) — Omega's "declare scope before anything runs" principle
    still applies at the script level.
- **Reverse DNS (PTR) lookups** (`src/dns.rs`) — `scan ptr` looks up the
  hostname for each discovered host via a PTR record query, reusing the
  same hand-rolled DNS client as `scan dns` (just a new record type, no
  new protocol work). Populates `Host.hostname`, shown in the stdout
  report. Not yet included in JSON/HTML report output.
- **Local network discovery via ARP** (`src/arp.rs`) — `scan network`
  reads the OS's own ARP table (`/proc/net/arp` on Linux, `arp -a` on
  macOS/BSD) after forcing a connection sweep to populate it, rather than
  sending raw ARP packets directly (which would need an `unsafe`,
  Linux-only raw socket outside this project's design so far). Enriches
  already-discovered hosts with MAC address and a best-effort vendor
  (small curated OUI table, ~24 common vendors — not the full IEEE
  registry), and can surface devices that answered ARP but no port scan
  at all. Known limitations: only sees the local network segment (not
  across a router), and ARP entries can go stale between the sweep and
  the read, so not every host is guaranteed a MAC on a given run.
- **Audit logging** (`src/audit.rs`) — `audit_log "path.jsonl"`, placed
  anywhere in a script, opens that file (append mode) and logs every
  subsequent statement as one JSON Lines entry: timestamp, action (e.g.
  `scan_ports`, `scan_creds`), a brief detail string, and outcome (`ok`
  or the error message). This is the accountability layer for real
  engagements — proof of exactly what was attempted and when, especially
  now that `scan creds`/`scan tls`/`scan network` are all actively
  touching real hosts. Known limitation: logs at the per-statement level,
  not per-host-within-a-scan (e.g. it won't show which specific host in
  a /24 was out of scope, or which credential pair succeeded) — that
  detail still lives in stdout/report output.
- **Structured reporting** (`src/report.rs`) — `report` with no
  destination prints to stdout as before; `report to "findings.json"` or
  `report to "findings.html"` write a hand-rolled structured report (no
  serde/templating dependency), including host MAC/vendor and
  domain-level DNS findings. Every finding — from NSE scripts, web
  checks, TLS checks, credential checks, or CVE lookups — is classified
  `high`/`medium`/`info` by severity so results are usable at scale, not
  just a wall of raw text.
- **Target-list export for tool chaining** (`src/export.rs`) — `export
  hosts to "targets.txt"` (plain `ip:port` lines) or `.csv` (`ip,port,
  service` columns), so recon results can feed into another tool instead
  of Omega being a closed loop.
- **Parallel execution** (`src/parallel.rs`) — hosts, ports, web, TLS,
  and credential checks are all probed concurrently (bounded thread pool
  built on `std::thread::scope`, no external crates), so `discover
  hosts` on a /24 doesn't mean 254 sequential connect timeouts. CVE
  lookups are a deliberate exception — sequential, to respect NVD's
  rate limits.
- **CIDR handling** (`src/ip.rs`) — hand-rolled IPv4/CIDR parsing and host
  iteration, capped at 256 hosts per target as a safety limit.

## A note on scope for active checks

`scan creds` attempts real logins (even with a tiny, well-known
credential list) and `scan tls`/`scan web`/`scan network` all actively
touch real hosts. `authorized_scope` enforcement covers all of them, but
that enforcement is only as good as the scope you actually declare —
only run these against systems you own or have explicit authorization to
test.

## Building from source
cargo build --release
cargo install --path .


No external crates are required for the core interpreter (`cve_lookup`
and `scan dns`'s HTTPS-dependent path shell out to `curl`, which is
assumed to already be on the system) — this keeps the toolchain
requirement low and avoids dependency-version surprises.

For local development, use the Makefile instead of raw `cargo`/installed
`omega` commands — it keeps you testing against what you actually just
built rather than a stale installed binary:
make run SCRIPT=examples/some_script.omg # build + run against target/debug
make test # run the test suite
make install # build --release and update the installed omega


## Writing your own scripts

Create a `.omg` (or `.omega`) file with any text editor:
nano myscript.omg


Then run it:
omega myscript.omg


## Example scripts

- `examples/first_milestone.omg` — the milestone from the design doc:
  target, discover, scan ports, identify services, report.
- `examples/assessment.omega` — the same flow wrapped in a named
  `assessment { }` block with an explicit `scan ports { ports ...
  services timeout ... }` block.
- `examples/scope_violation.omega` — demonstrates that a `target` outside
  a declared `authorized_scope` is rejected instead of scanned.
- `examples/deep_scan.omg` — OS detection and NSE `vuln` scripts against
  a single host.
- `examples/report_test.omg` — writing structured JSON and HTML reports.
- `examples/severity_test.omg` — exercises high/medium/info finding
  classification.
- `examples/web_scan.omg` — HTTP vulnerability scanning (`scan web`).
- `examples/network_scan.omg` — ARP-based local network discovery
  (`scan network`).
- `examples/creds_test.omg` — default credential checking (`scan
  creds`).
- `examples/loop_test.omg` — control flow: `for each host { if port 22
  open { ... } }`.
- `examples/vars_test.omg` — compile-time variable substitution.

## Full syntax reference
target <IP or CIDR>
authorized_scope <IP or CIDR> # optional — defaults to the target

discover hosts # "hosts" is optional

scan ports {
ports <range> # e.g. "1-1024" — optional
services # identify services on open ports
timeout <Ns> # e.g. "3s" — optional
os_detect # OS fingerprint (needs nmap + root)
nse_scripts "<category>" # e.g. "vuln" — needs nmap
cve_lookup # known CVEs for identified versions
# (needs curl; slow, respects rate limits)
}

scan web {
paths # check curated sensitive-path list
headers # check for missing security headers
port <n> # optional explicit port
}

scan tls {
port <n> # optional explicit port
} # certificate expiry/subject/issuer,
# legacy protocol + weak cipher checks

scan creds # default-credential checks:
# FTP, Telnet, HTTP Basic Auth

scan dns "domain.com" {
spf # check for SPF TXT record
dmarc # check for DMARC TXT record
subdomains # enumerate common subdomains
}

scan network # ARP-based local network discovery
scan ptr # reverse DNS (PTR) hostname lookup

identify services # standalone version of the flag above

report # print to stdout
report to "findings.json" # write structured JSON
report to "findings.html" # write styled HTML

export hosts to "targets.txt" # plain ip:port lines
export hosts to "targets.csv" # ip,port,service columns

audit_log "path.jsonl" # append-only, per-statement log of
# every action and its outcome

set name = "value" # compile-time substitution — every
# $name elsewhere becomes "value"

for each host { # iterate discovered hosts one at a
... # time; any scan/report/export
} # statement inside applies to just
# that host

if port <n> open { # narrow, specific conditions only —
... # not a general expression language
}
if os contains "<text>" {
...
}

assessment "name" { ... } # named wrapper — can contain any of the above


## Tests
cargo test


or, from the Makefile:
make test


## What's next (not built yet)

- Per-host detail in audit logging (currently logs per-statement only,
  not e.g. which specific host in a range was out of scope, or which
  credential pair succeeded).
- Including `hostname` (from `scan ptr`) in the JSON/HTML report output,
  not just stdout.
- A full, encrypting TLS client so `scan web` can fetch real HTTPS
  content (`scan tls` only reads certificate/protocol metadata from a
  partial, unencrypted handshake).
- Certificate Transparency (crt.sh-style) subdomain discovery, replacing
  or supplementing the current wordlist approach with real-world
  coverage.
- DNS zone transfer (AXFR) testing.
- A dry-run/explain mode to preview exactly what a script would do
  before it touches the network.
- SNMP and SMB-specific information-disclosure checks.
- Cookie security flags (Secure/HttpOnly/SameSite) and CORS
  misconfiguration checks in `scan web`.
- HTTP method enumeration (TRACE/PUT/DELETE) in `scan web`.
- WHOIS lookup for domains.
- An attack-surface summary section in reports, ranking findings across
  the whole engagement rather than just per-host.
- UDP scanning, nmap timing templates, and a higher (but still
  deliberate) host-count cap for larger network ranges.
- A larger OUI vendor table for `scan network` (currently ~24 curated
  entries, not the full IEEE registry).
- The `scan <ip>` one-line shorthand and `monitor network` / `when ...
  detected { }` event-driven blocks from the original design doc.
- IPv6 support in the CIDR module.
EOFcat > README.md << 'EOF'
# Omega

<img width="240" alt="omegalogo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />

Omega is a security-first programming language for cybersecurity
automation. Instead of writing Python calls into scanning libraries, you
describe the security operation you want:

set my_target = "192.168.1.0/24"

target $my_target
audit_log "engagement.jsonl"
discover hosts
scan ports { services os_detect nse_scripts "vuln" cve_lookup }
scan web { paths headers }
scan tls
scan creds
scan network
scan ptr
scan dns "example.com" { spf dmarc subdomains }

for each host {
if port 22 open {
report
}
}

export hosts to "targets.txt"
report to "findings.json"


## Install

curl -fsSL https://raw.githubusercontent.com/Kolgrim33/omega-lang/master/install.sh | sh


Downloads a prebuilt binary for Linux or macOS — no Rust or cargo
required. Then run scripts directly:

omega examples/first_milestone.omg


(Building from source is also supported — see below.)

## What this build actually does

This is a real tree-walking interpreter, not a mockup:

- **Lexer/parser** (`src/lexer.rs`, `src/parser.rs`, `src/ast.rs`) — turns
  `.omega`/`.omg` source into an AST covering `target`,
  `authorized_scope`, `discover [hosts]`, `scan ports { ... }`,
  `scan web { ... }`, `scan dns "..." { ... }`, `scan network`,
  `scan ptr`, `scan creds`, `scan tls { ... }`, `identify services`,
  `report [to "..."]`, `export hosts to "..."`, `audit_log "..."`,
  `for each host { ... }`, `if <condition> { ... }`, and
  `assessment "name" { ... }` blocks.
- **Scope enforcement** (`src/interpreter.rs`) — `authorized_scope` (or the
  first `target`, implicitly) is checked before every host is touched. A
  target outside scope is refused at runtime with
  `ERROR: target X is outside authorized scope.` instead of silently
  running.
- **Compile-time variables** (`src/vars.rs`) — `set name = "value"`
  lines are extracted before the lexer ever runs, and any `$name`
  elsewhere in the script is textually substituted with that value.
  This is NOT a runtime variable system — a value can't depend on a
  scan result, only an earlier `set` in the same script. Chosen over
  deep AST integration because several fields (e.g. port numbers) are
  parsed immediately during parsing, so a `$var` there would break
  parsing before substitution could happen; this approach needs zero
  changes to the lexer, parser, or interpreter.
- **Control flow** (`src/ast.rs`, `src/interpreter.rs`) — `for each host {
  ... }` narrows the interpreter's host list to one host per iteration
  (so every existing `scan_*` method works inside the loop with zero
  changes, since they already operate on "whatever hosts currently
  exist"), then merges results back afterward. `if port <n> open { ... }`
  and `if os contains "<text>" { ... }` are the two supported
  conditions — not a general expression language, just these two narrow,
  practical checks.
- **Real network backends** (`src/backend.rs`, `src/scan.rs`) — host
  discovery, port scanning, service identification, OS fingerprinting,
  and NSE scripts all actually run, via a `ProbeBackend` trait so new
  backends can be added without touching the interpreter:
  - if `nmap` is on PATH, Omega shells out to it (`-sn` for discovery,
    `-p`/default port set for scanning, `-sV` for service ID, `-O` for OS
    fingerprinting, `--script <category>` for NSE) and parses its output.
    OS detection checks for root privileges up front and fails with a
    clear message rather than nmap's less friendly error; NSE and OS
    scans carry timeouts (`--script-timeout`, `--host-timeout`) so a
    script category with a long internal timeout can't hang a run
    indefinitely;
  - if `nmap` isn't installed, Omega falls back to its own parallel
    TCP-connect probing plus a small built-in port/service table for
    discovery/scanning/service-ID, so the language still runs end to end
    with zero external tools. OS detection and NSE scripts have no honest
    TCP-connect equivalent, so the fallback backend reports those as
    unsupported rather than faking a result.
- **CVE correlation** (`src/cve.rs`) — the `cve_lookup` flag inside `scan
  ports { }` looks up known vulnerabilities for each identified service
  version. Shells out to `curl` for the actual HTTPS request to NVD's
  public API (Omega doesn't implement TLS encryption, so this follows
  the same pattern `nmap` shelling-out already uses). Extracts CVE IDs
  via targeted pattern matching rather than a general JSON parser, and
  links to the authoritative NVD page instead of risking a mangled
  description through fragile parsing. Product/version extraction from
  an `nmap -sV` banner is a best-effort heuristic and will misparse some
  irregular banners. No hardcoded fallback CVE list — stale security
  data would be worse than none. Runs sequentially with a pause between
  lookups, as a courtesy toward NVD's public rate limits.
- **HTTP vulnerability scanning** (`src/http.rs`, `src/webchecks.rs`) —
  `scan web { paths headers }` is Omega's purpose-built equivalent of
  nikto, distinct from nmap's generic NSE vuln category:
  - a hand-rolled, zero-dependency HTTP/1.1 client checks a curated list
    of ~30 commonly-exposed sensitive paths (`.git/config`, `.env`,
    admin panels, backup files, exposed credentials/keys) and flags
    anything that responds 200/401/403;
  - a header check flags missing recommended security headers
    (`Strict-Transport-Security`, `X-Frame-Options`,
    `X-Content-Type-Options`, `Content-Security-Policy`,
    `Referrer-Policy`);
  - runs against a host's already-discovered open web ports
    (80/8080/8000/8888/443/8443) or an explicit `port <n>`. HTTPS ports
    are currently probed as plain HTTP — TLS support isn't implemented
    for actually fetching content (see `scan tls` below for what TLS
    support does exist), and the report says so explicitly rather than
    silently misreporting an HTTPS-only host.
- **TLS certificate and protocol checks** (`src/tlscheck.rs`) — `scan
  tls` performs a partial, non-cryptographic TLS handshake: it sends a
  ClientHello, reads the plaintext ServerHello and Certificate messages
  (unencrypted for TLS 1.2 and earlier), then disconnects — no key
  exchange, encryption, or signature verification is performed, the same
  crypto-avoidance boundary as SSH being excluded from `scan creds`.
  - extracts certificate expiry, subject, and issuer via a simplified
    hand-rolled X.509 DER parser;
  - separately probes whether the server still accepts TLS 1.0/1.1, and
    whether it accepts a curated list of deliberately weak/broken cipher
    suites (NULL, EXPORT, RC4, DES, 3DES);
  - known limitation: TLS 1.3's Certificate message is itself encrypted,
    so certificate details aren't readable this way on 1.3-only servers
    (only the negotiated version/cipher are visible). This does **not**
    let `scan web` fetch real HTTPS content — that needs a full,
    encrypting TLS client, a separate and much larger feature.
- **Default credential checks** (`src/credcheck.rs`) — `scan creds` tests
  a small, curated list of well-known factory-default logins (~10 pairs,
  not a wordlist) against services already discovered open: FTP, Telnet,
  and HTTP Basic Auth. Stops at the first hit per service; HTTP checks
  only run if the baseline unauthenticated request is already rejected
  (401). SSH is deliberately excluded — a correct client needs real
  cryptographic key exchange that can't be responsibly hand-rolled
  without a dedicated crypto library. Telnet support is explicitly
  best-effort/heuristic (IAC sequences are stripped rather than properly
  negotiated, and success is guessed from prompt text).
- **DNS and email security checks** (`src/dns.rs`, `src/dnschecks.rs`) —
  `scan dns "domain" { spf dmarc subdomains }`:
  - a hand-rolled, zero-dependency DNS client (raw UDP, RFC 1035 wire
    format — no external resolver crate) checks for SPF and DMARC TXT
    records (missing either is a real, common email-spoofing exposure);
  - subdomain enumeration against a curated wordlist of ~34 common names.
    Note: this is wordlist-based, not Certificate-Transparency-based —
    real recon tools like subfinder/amass discover far more via
    crt.sh-style CT log queries, which Omega doesn't do yet;
  - `scan dns` requires `authorized_scope` to already be declared in the
    script (even though DNS lookups against a public resolver aren't
    IP-scoped) — Omega's "declare scope before anything runs" principle
    still applies at the script level.
- **Reverse DNS (PTR) lookups** (`src/dns.rs`) — `scan ptr` looks up the
  hostname for each discovered host via a PTR record query, reusing the
  same hand-rolled DNS client as `scan dns` (just a new record type, no
  new protocol work). Populates `Host.hostname`, shown in the stdout
  report. Not yet included in JSON/HTML report output.
- **Local network discovery via ARP** (`src/arp.rs`) — `scan network`
  reads the OS's own ARP table (`/proc/net/arp` on Linux, `arp -a` on
  macOS/BSD) after forcing a connection sweep to populate it, rather than
  sending raw ARP packets directly (which would need an `unsafe`,
  Linux-only raw socket outside this project's design so far). Enriches
  already-discovered hosts with MAC address and a best-effort vendor
  (small curated OUI table, ~24 common vendors — not the full IEEE
  registry), and can surface devices that answered ARP but no port scan
  at all. Known limitations: only sees the local network segment (not
  across a router), and ARP entries can go stale between the sweep and
  the read, so not every host is guaranteed a MAC on a given run.
- **Audit logging** (`src/audit.rs`) — `audit_log "path.jsonl"`, placed
  anywhere in a script, opens that file (append mode) and logs every
  subsequent statement as one JSON Lines entry: timestamp, action (e.g.
  `scan_ports`, `scan_creds`), a brief detail string, and outcome (`ok`
  or the error message). This is the accountability layer for real
  engagements — proof of exactly what was attempted and when, especially
  now that `scan creds`/`scan tls`/`scan network` are all actively
  touching real hosts. Known limitation: logs at the per-statement level,
  not per-host-within-a-scan (e.g. it won't show which specific host in
  a /24 was out of scope, or which credential pair succeeded) — that
  detail still lives in stdout/report output.
- **Structured reporting** (`src/report.rs`) — `report` with no
  destination prints to stdout as before; `report to "findings.json"` or
  `report to "findings.html"` write a hand-rolled structured report (no
  serde/templating dependency), including host MAC/vendor and
  domain-level DNS findings. Every finding — from NSE scripts, web
  checks, TLS checks, credential checks, or CVE lookups — is classified
  `high`/`medium`/`info` by severity so results are usable at scale, not
  just a wall of raw text.
- **Target-list export for tool chaining** (`src/export.rs`) — `export
  hosts to "targets.txt"` (plain `ip:port` lines) or `.csv` (`ip,port,
  service` columns), so recon results can feed into another tool instead
  of Omega being a closed loop.
- **Parallel execution** (`src/parallel.rs`) — hosts, ports, web, TLS,
  and credential checks are all probed concurrently (bounded thread pool
  built on `std::thread::scope`, no external crates), so `discover
  hosts` on a /24 doesn't mean 254 sequential connect timeouts. CVE
  lookups are a deliberate exception — sequential, to respect NVD's
  rate limits.
- **CIDR handling** (`src/ip.rs`) — hand-rolled IPv4/CIDR parsing and host
  iteration, capped at 256 hosts per target as a safety limit.

## A note on scope for active checks

`scan creds` attempts real logins (even with a tiny, well-known
credential list) and `scan tls`/`scan web`/`scan network` all actively
touch real hosts. `authorized_scope` enforcement covers all of them, but
that enforcement is only as good as the scope you actually declare —
only run these against systems you own or have explicit authorization to
test.

## Building from source

cargo build --release
cargo install --path .


No external crates are required for the core interpreter (`cve_lookup`
and `scan dns`'s HTTPS-dependent path shell out to `curl`, which is
assumed to already be on the system) — this keeps the toolchain
requirement low and avoids dependency-version surprises.

For local development, use the Makefile instead of raw `cargo`/installed
`omega` commands — it keeps you testing against what you actually just
built rather than a stale installed binary:

make run SCRIPT=examples/some_script.omg # build + run against target/debug
make test # run the test suite
make install # build --release and update the installed omega


## Writing your own scripts

Create a `.omg` (or `.omega`) file with any text editor:

nano myscript.omg


Then run it:

omega myscript.omg


## Example scripts

- `examples/first_milestone.omg` — the milestone from the design doc:
  target, discover, scan ports, identify services, report.
- `examples/assessment.omega` — the same flow wrapped in a named
  `assessment { }` block with an explicit `scan ports { ports ...
  services timeout ... }` block.
- `examples/scope_violation.omega` — demonstrates that a `target` outside
  a declared `authorized_scope` is rejected instead of scanned.
- `examples/deep_scan.omg` — OS detection and NSE `vuln` scripts against
  a single host.
- `examples/report_test.omg` — writing structured JSON and HTML reports.
- `examples/severity_test.omg` — exercises high/medium/info finding
  classification.
- `examples/web_scan.omg` — HTTP vulnerability scanning (`scan web`).
- `examples/network_scan.omg` — ARP-based local network discovery
  (`scan network`).
- `examples/creds_test.omg` — default credential checking (`scan
  creds`).
- `examples/loop_test.omg` — control flow: `for each host { if port 22
  open { ... } }`.
- `examples/vars_test.omg` — compile-time variable substitution.

## Full syntax reference

target <IP or CIDR>
authorized_scope <IP or CIDR> # optional — defaults to the target

discover hosts # "hosts" is optional

scan ports {
ports <range> # e.g. "1-1024" — optional
services # identify services on open ports
timeout <Ns> # e.g. "3s" — optional
os_detect # OS fingerprint (needs nmap + root)
nse_scripts "<category>" # e.g. "vuln" — needs nmap
cve_lookup # known CVEs for identified versions
# (needs curl; slow, respects rate limits)
}

scan web {
paths # check curated sensitive-path list
headers # check for missing security headers
port <n> # optional explicit port
}

scan tls {
port <n> # optional explicit port
} # certificate expiry/subject/issuer,
# legacy protocol + weak cipher checks

scan creds # default-credential checks:
# FTP, Telnet, HTTP Basic Auth

scan dns "domain.com" {
spf # check for SPF TXT record
dmarc # check for DMARC TXT record
subdomains # enumerate common subdomains
}

scan network # ARP-based local network discovery
scan ptr # reverse DNS (PTR) hostname lookup

identify services # standalone version of the flag above

report # print to stdout
report to "findings.json" # write structured JSON
report to "findings.html" # write styled HTML

export hosts to "targets.txt" # plain ip:port lines
export hosts to "targets.csv" # ip,port,service columns

audit_log "path.jsonl" # append-only, per-statement log of
# every action and its outcome

set name = "value" # compile-time substitution — every
# $name elsewhere becomes "value"

for each host { # iterate discovered hosts one at a
... # time; any scan/report/export
} # statement inside applies to just
# that host

if port <n> open { # narrow, specific conditions only —
... # not a general expression language
}
if os contains "<text>" {
...
}

assessment "name" { ... } # named wrapper — can contain any of the above


## Tests

cargo test


or, from the Makefile:

make test


## What's next (not built yet)

- Per-host detail in audit logging (currently logs per-statement only,
  not e.g. which specific host in a range was out of scope, or which
  credential pair succeeded).
- Including `hostname` (from `scan ptr`) in the JSON/HTML report output,
  not just stdout.
- A full, encrypting TLS client so `scan web` can fetch real HTTPS
  content (`scan tls` only reads certificate/protocol metadata from a
  partial, unencrypted handshake).
- Certificate Transparency (crt.sh-style) subdomain discovery, replacing
  or supplementing the current wordlist approach with real-world
  coverage.
- DNS zone transfer (AXFR) testing.
- A dry-run/explain mode to preview exactly what a script would do
  before it touches the network.
- SNMP and SMB-specific information-disclosure checks.
- Cookie security flags (Secure/HttpOnly/SameSite) and CORS
  misconfiguration checks in `scan web`.
- HTTP method enumeration (TRACE/PUT/DELETE) in `scan web`.
- WHOIS lookup for domains.
- An attack-surface summary section in reports, ranking findings across
  the whole engagement rather than just per-host.
- UDP scanning, nmap timing templates, and a higher (but still
  deliberate) host-count cap for larger network ranges.
- A larger OUI vendor table for `scan network` (currently ~24 curated
  entries, not the full IEEE registry).
- The `scan <ip>` one-line shorthand and `monitor network` / `when ...
  detected { }` event-driven blocks from the original design doc.
- IPv6 support in the CIDR module.
