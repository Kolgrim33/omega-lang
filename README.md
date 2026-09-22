<h1 align="center">Omega</h1>

<p align="center">
  <img width="240" alt="Omega logo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />
</p>

<p align="center">
  <strong>Omega</strong> — a programming language for cybersecurity automation.
</p>

Describe the security operation you want directly in Omega:

```omega
set target_range = "192.168.1.0/24"

target $target_range
audit_log "engagement.jsonl"
timing normal

discover hosts
scan ports { services os_detect nse_scripts "vuln" cve_lookup }
scan web { paths headers }
scan tls
scan creds
scan network
scan ptr
scan databases
scan dns "example.com" { spf dmarc subdomains }

for each host {
    if port 22 open {
        report
    }
}

export hosts to "targets.txt"
report to "findings.json"
```

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Kolgrim33/omega-lang/master/install.sh | sh
```

This downloads a prebuilt binary for Linux or macOS, so no Rust or cargo is required. Then run scripts directly:

```bash
omega examples/first_milestone.omg
```

Building from source is also supported — see below.

## What this build actually does

This is a real tree-walking interpreter, not a mockup.

The lexer and parser (`src/lexer.rs`, `src/parser.rs`, `src/ast.rs`) turn `.omega`/`.omg` source into an AST covering `target`, `authorized_scope`, `discover [hosts]`, `scan ports { ... }`, `scan web { ... }`, `scan tls { ... }`, `scan creds`, `scan dns "..." { ... }`, `scan network`, `scan ptr`, `scan databases`, `identify services`, `report [to "..."]`, `export hosts to "..."`, `audit_log "..."`, `timing <profile>`, `set name = "value"`, `for each host { ... }`, `if <condition> { ... }`, and `assessment "name" { ... }` blocks.

Scope enforcement (`src/interpreter.rs`) means `authorized_scope` (or the first target, implicitly) is checked before every host is touched. A target outside scope is refused at runtime with `ERROR: target X is outside authorized scope.` instead of silently running. This matters more than usual for Omega: `scan creds` attempts real logins (a small, curated list of well-known defaults, not a wordlist), and `scan tls`, `scan web`, `scan network`, and `scan databases` all actively touch real hosts — only run these against systems you own or have explicit authorization to test.

Compile-time variables (`src/vars.rs`) let you write `set name = "value"` anywhere in a script, and every `$name` elsewhere gets textually substituted with that value before the lexer ever runs. This is not a runtime variable system — a value can't depend on a scan result, only an earlier `set` in the same script. It was built this way deliberately: several fields (like port numbers) are parsed immediately during parsing, so a `$var` there would break parsing before any substitution could happen, and deferring that everywhere would be a much larger, riskier change than this feature needs. Because substitution happens as a pure text pass before parsing, the lexer, parser, and interpreter needed zero changes.

Control flow (`src/ast.rs`, `src/interpreter.rs`) is narrow by design. `for each host { ... }` narrows the interpreter's host list to one host per iteration — every existing `scan_*` method already operates on "whatever hosts currently exist," so nothing about them needed to change — then merges results back together afterward. `if port <n> open { ... }` and `if os contains "<text>" { ... }` are the two supported conditions; this is not a general expression language.

Real network backends (`src/backend.rs`, `src/scan.rs`) handle host discovery, port scanning, service identification, OS fingerprinting, and NSE scripts, all through a `ProbeBackend` trait so new backends can be added without touching the interpreter. If nmap is on `PATH`, Omega shells out to it — `-sn` for discovery, `-p`/a default port set for scanning, `-sV` for service ID, `-O` for OS fingerprinting, `--script <category>` for NSE — and parses its output. OS detection checks for root privileges up front and fails with a clear message rather than nmap's less friendly error, and NSE and OS scans carry timeouts (`--script-timeout`, `--host-timeout`) so a script category with a long internal timeout can't hang a run indefinitely. If nmap isn't installed, Omega falls back to its own parallel TCP-connect probing plus a small built-in port/service table for discovery, scanning, and service ID, so the language still runs end to end with zero external tools. OS detection and NSE scripts have no honest TCP-connect equivalent, so the fallback backend reports those as unsupported rather than faking a result.

CVE correlation (`src/cve.rs`) is the `cve_lookup` flag inside `scan ports { }`. It shells out to `curl` for the actual HTTPS request to NVD's public API — Omega doesn't implement TLS encryption, so this follows the same pattern nmap shelling-out already uses. Rather than write a general JSON parser (or risk mangling a vulnerability description through fragile string-slicing), it extracts CVE IDs via targeted pattern matching and links to the authoritative NVD page for details. Product/version extraction from an `nmap -sV` banner is a best-effort heuristic and will misparse some irregular banners. There's deliberately no hardcoded fallback CVE list, since stale security data would be worse than none, and lookups run sequentially with a pause between them as a courtesy toward NVD's public rate limits.

HTTP vulnerability scanning (`src/http.rs`, `src/webchecks.rs`) is what `scan web { paths headers }` does — Omega's purpose-built equivalent of nikto, distinct from nmap's generic NSE vuln category. A hand-rolled, zero-dependency HTTP/1.1 client checks a curated list of roughly 30 commonly-exposed sensitive paths (`.git/config`, `.env`, admin panels, backup files, exposed credentials and keys) and flags anything that responds 200, 401, or 403. A header check flags missing recommended security headers (`Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`). It runs against a host's already-discovered open web ports (80, 8080, 8000, 8888, 443, 8443) or an explicit `port <n>`. HTTPS ports are currently probed as plain HTTP — actually fetching content over HTTPS isn't implemented (see `scan tls` below for what TLS support does exist), and the report says so explicitly rather than silently misreporting an HTTPS-only host.

TLS certificate and protocol checks (`src/tlscheck.rs`) are what `scan tls` performs — a partial, non-cryptographic TLS handshake. It sends a ClientHello, reads the plaintext ServerHello and Certificate messages (unencrypted for TLS 1.2 and earlier), then disconnects; no key exchange, encryption, or signature verification is performed, the same crypto-avoidance boundary as SSH being excluded from `scan creds`. It extracts certificate expiry, subject, and issuer via a simplified hand-rolled X.509 DER parser, and separately probes whether the server still accepts TLS 1.0/1.1 and whether it accepts a curated list of deliberately weak or broken cipher suites (NULL, EXPORT, RC4, DES, 3DES). TLS 1.3's Certificate message is itself encrypted, so certificate details aren't readable this way on 1.3-only servers — only the negotiated version and cipher are visible. This does not let `scan web` fetch real HTTPS content; that needs a full, encrypting TLS client, a separate and much larger feature.

Default credential checks (`src/credcheck.rs`) are what `scan creds` runs — a small, curated list of well-known factory-default logins (about 10 pairs, not a wordlist) against services already discovered open: FTP, Telnet, and HTTP Basic Auth. It stops at the first hit per service, and HTTP checks only run if the baseline unauthenticated request is already rejected with a 401. SSH is deliberately excluded, since a correct client needs real cryptographic key exchange that can't be responsibly hand-rolled without a dedicated crypto library. Telnet support is explicitly best-effort: IAC sequences are stripped rather than properly negotiated, and success is guessed from prompt text.

Exposed database detection (`src/dbcheck.rs`) is what `scan databases` checks — four fixed, well-known ports probed directly on every host (Redis 6379, MongoDB 27017, Elasticsearch 9200, Memcached 11211), independent of whatever port range `scan ports` used, since all four sit above 1024 and outside most typical scans. Redis and Memcached get minimal text-protocol probes (a RESP `PING`, a `stats` command); Elasticsearch reuses the existing HTTP client, since a 200 on `GET /` with no credentials is itself the finding. MongoDB gets a hand-built `OP_QUERY {listDatabases:1}` against `admin.$cmd`, using purpose-built BSON encoding for this one fixed command rather than a general BSON library, with the response checked via byte-pattern scanning for the `databases`/`errmsg` field names rather than a full BSON decoder. An unauthenticated database of any of these four is one of the most common, highest-severity findings in real security assessments.

DNS and email security checks (`src/dns.rs`, `src/dnschecks.rs`) power `scan dns "domain" { spf dmarc subdomains }`. A hand-rolled, zero-dependency DNS client (raw UDP, RFC 1035 wire format, no external resolver crate) checks for SPF and DMARC TXT records, since missing either is a real and common email-spoofing exposure. Subdomain enumeration runs against a curated wordlist of about 34 common names — this is wordlist-based, not Certificate-Transparency-based, so real recon tools like subfinder or amass will discover far more via crt.sh-style CT log queries, which Omega doesn't do yet. `scan dns` requires `authorized_scope` to already be declared in the script, even though DNS lookups against a public resolver aren't IP-scoped, because Omega's "declare scope before anything runs" principle still applies at the script level.

Reverse DNS lookups (`src/dns.rs`) are what `scan ptr` performs, reusing the same hand-rolled DNS client as `scan dns` — just a new record type (PTR), no new protocol work. It looks up the hostname for each discovered host and populates it on the host record. This currently shows up in the stdout report only, not yet in the JSON/HTML report output.

Local network discovery via ARP (`src/arp.rs`) is what `scan network` performs: it reads the OS's own ARP table (`/proc/net/arp` on Linux, `arp -a` on macOS/BSD) after forcing a connection sweep to populate it, rather than sending raw ARP packets directly, which would need an unsafe, Linux-only raw socket outside this project's design so far. It enriches already-discovered hosts with MAC address and a best-effort vendor (a small curated OUI table of about 24 common vendors, not the full IEEE registry), and can surface devices that answered ARP but received no port scan at all. Known limitations are that it only sees the local network segment, not across a router, and that ARP entries can go stale between the sweep and the read, so not every host is guaranteed a MAC on a given run.

Audit logging (`src/audit.rs`) is turned on with `audit_log "path.jsonl"`, placed anywhere in a script. From that point on, every subsequent statement is logged as one JSON Lines entry: timestamp, action (like `scan_ports` or `scan_creds`), a brief detail string, and outcome — either `ok` or the error message. This is the accountability layer for real engagements, proof of exactly what was attempted and when, especially given how many of Omega's checks actively touch real hosts. It currently logs at the per-statement level, not per-host-within-a-scan, so it won't show which specific host in a /24 was out of scope or which credential pair succeeded — that detail still lives in stdout/report output.

Timing control (`src/parallel.rs`) is set with `timing aggressive` (the default, no delay), `timing normal` (a small pause between batches of concurrent probes), or `timing slow` (a larger pause). Since every scan type already funnels through the same parallel-map helper, this one setting throttles all of them uniformly — ports, web, TLS, credentials, network, databases — without needing separate throttling logic in each. The delay sits between batches of up to 32 concurrent items, not between every individual probe, since staggering every single one would defeat the point of running them concurrently at all.

Structured reporting (`src/report.rs`) means `report` with no destination prints to stdout as before, while `report to "findings.json"` or `report to "findings.html"` write a hand-rolled structured report with no serde or templating dependency, including host MAC/vendor and domain-level DNS findings. Every finding — from NSE scripts, web checks, TLS checks, credential checks, CVE lookups, or database checks — is classified high, medium, or info by severity so results are usable at scale rather than a wall of raw text.

Target-list export for tool chaining (`src/export.rs`) lets `export hosts to "targets.txt"` write plain `ip:port` lines, or `.csv` write `ip,port,service` columns, so recon results can feed into another tool instead of Omega being a closed loop.

Parallel execution (`src/parallel.rs`) probes hosts, ports, web, TLS, and credential checks concurrently through a bounded thread pool built on `std::thread::scope`, with no external crates, so `discover hosts` on a /24 doesn't mean 254 sequential connect timeouts. CVE lookups are a deliberate exception, running sequentially to respect NVD's rate limits.

CIDR handling (`src/ip.rs`) is hand-rolled IPv4/CIDR parsing and host iteration, capped at 256 hosts per target as a safety limit.

## Building from source

```bash
cargo build --release
cargo install --path .
```

No external crates are required for the core interpreter, which keeps the toolchain requirement low and avoids dependency-version surprises (`cve_lookup` and `scan dns`'s HTTPS-dependent paths shell out to `curl`, which is assumed to already be on the system).

For local development, use the Makefile instead of raw cargo or the installed `omega` command — it keeps you testing against what you actually just built rather than a stale installed binary:

```bash
make run SCRIPT=examples/some_script.omg  # build + run against target/debug
make test                                 # run the test suite
make install                              # build --release and update the installed omega
```

## Writing your own scripts

Create a `.omg` (or `.omega`) file with any text editor:

```bash
nano myscript.omg
```

Then run it:

```bash
omega myscript.omg
```

## Example scripts

`examples/first_milestone.omg` walks through the milestone from the design doc: target, discover, scan ports, identify services, report. `examples/assessment.omega` wraps the same flow in a named `assessment { }` block with an explicit `scan ports { ports ... services timeout ... }` block. `examples/scope_violation.omega` demonstrates that a target outside a declared `authorized_scope` is rejected instead of scanned. `examples/deep_scan.omg` runs OS detection and NSE vuln scripts against a single host. `examples/report_test.omg` writes structured JSON and HTML reports. `examples/severity_test.omg` exercises high/medium/info finding classification. `examples/web_scan.omg` runs HTTP vulnerability scanning (`scan web`). `examples/network_scan.omg` runs ARP-based local network discovery (`scan network`). `examples/creds_test.omg` runs default credential checking (`scan creds`). `examples/loop_test.omg` demonstrates control flow: `for each host { if port 22 open { ... } }`. `examples/vars_test.omg` demonstrates compile-time variable substitution.

## Full syntax reference

```omega
target <IP or CIDR>
authorized_scope <IP or CIDR>          # optional — defaults to the target

discover hosts                          # "hosts" is optional

scan ports {
    ports <range>                       # e.g. "1-1024" — optional
    services                            # identify services on open ports
    timeout <Ns>                        # e.g. "3s" — optional
    os_detect                           # OS fingerprint (needs nmap + root)
    nse_scripts "<category>"            # e.g. "vuln" — needs nmap
    cve_lookup                          # known CVEs for identified versions
                                         # (needs curl; slow, respects rate limits)
}

scan web {
    paths                               # check curated sensitive-path list
    headers                             # check for missing security headers
    port <n>                            # optional explicit port
}

scan tls {
    port <n>                            # optional explicit port
}                                        # certificate expiry/subject/issuer,
                                         # legacy protocol + weak cipher checks

scan creds                              # default-credential checks:
                                         # FTP, Telnet, HTTP Basic Auth

scan databases                          # exposed Redis/MongoDB/
                                         # Elasticsearch/Memcached checks

scan dns "domain.com" {
    spf                                 # check for SPF TXT record
    dmarc                               # check for DMARC TXT record
    subdomains                          # enumerate common subdomains
}

scan network                            # ARP-based local network discovery
scan ptr                                # reverse DNS (PTR) hostname lookup

identify services                       # standalone version of the flag above

report                                  # print to stdout
report to "findings.json"               # write structured JSON
report to "findings.html"               # write styled HTML

export hosts to "targets.txt"           # plain ip:port lines
export hosts to "targets.csv"           # ip,port,service columns

audit_log "path.jsonl"                  # append-only, per-statement log of
                                         # every action and its outcome

timing aggressive                       # no delay (default)
timing normal                           # small delay between probe batches
timing slow                             # larger delay between probe batches

set name = "value"                      # compile-time substitution — every
                                         # $name elsewhere becomes "value"

for each host {                         # iterate discovered hosts one at a
    ...                                  # time; any scan/report/export
}                                        # statement inside applies to just
                                         # that host

if port <n> open {                      # narrow, specific conditions only —
    ...                                  # not a general expression language
}
if os contains "<text>" {
    ...
}

assessment "name" { ... }               # named wrapper — can contain any of the above
```

## Tests

```bash
cargo test
```

or, from the Makefile:

```bash
make test
```

## What's next (not built yet)

Per-host detail in audit logging is still missing — it currently logs per-statement only, not which specific host in a range was out of scope or which credential pair succeeded. `scan ptr`'s hostname result isn't in the JSON/HTML report output yet, only stdout. Subdomain discovery will move toward Certificate Transparency (crt.sh-style) lookups, replacing or supplementing the current wordlist approach with real-world coverage. DNS zone transfer (AXFR) testing is on the roadmap. A full, encrypting TLS client would let `scan web` fetch real HTTPS content — `scan tls` currently only reads certificate/protocol metadata from a partial, unencrypted handshake. A dry-run/explain mode to preview exactly what a script would do before it touches the network is planned, along with SNMP and SMB-specific information-disclosure checks, cookie security flags and CORS misconfiguration checks, HTTP method enumeration, and WHOIS lookups. An attack-surface summary section in reports, ranking findings across the whole engagement rather than just per-host, is also on the list, as is UDP scanning and a higher (but still deliberate) host-count cap for larger network ranges. The OUI vendor table for `scan network` will grow beyond its current ~24 curated entries toward something closer to the full IEEE registry. Finally, the `scan <ip>` one-line shorthand and `monitor network` / `when ... detected { }` event-driven blocks from the original design doc, along with IPv6 support in the CIDR module, are still on the list.
