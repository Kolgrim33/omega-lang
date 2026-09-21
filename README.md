<h1 align="center">Omega</h1>

<p align="center">
  <img width="240" alt="Omega logo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />
</p>

<p align="center">
  <strong>Omega</strong> — a programming language for cybersecurity automation.
</p>

Describe the security operation you want directly in Omega:

```omega
target 192.168.1.0/24
discover hosts
scan ports { services os_detect nse_scripts "vuln" }
scan web { paths headers }
scan network
scan dns "example.com" { spf dmarc subdomains }
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

The lexer and parser (`src/lexer.rs`, `src/parser.rs`, `src/ast.rs`) turn `.omega`/`.omg` source into an AST covering `target`, `authorized_scope`, `discover [hosts]`, `scan ports { ... }`, `scan web { ... }`, `scan dns "..." { ... }`, `scan network`, `identify services`, `report [to "..."]`, `export hosts to "..."`, and `assessment "name" { ... }` blocks.

Scope enforcement (`src/interpreter.rs`) means `authorized_scope` (or the first target, implicitly) is checked before every host is touched. A target outside scope is refused at runtime with `ERROR: target X is outside authorized scope.` instead of silently running.

Real network backends (`src/backend.rs`, `src/scan.rs`) handle host discovery, port scanning, service identification, OS fingerprinting, and NSE scripts, all through a `ProbeBackend` trait so new backends can be added without touching the interpreter. If nmap is on `PATH`, Omega shells out to it — `-sn` for discovery, `-p`/a default port set for scanning, `-sV` for service ID, `-O` for OS fingerprinting, `--script <category>` for NSE — and parses its output. OS detection checks for root privileges up front and fails with a clear message rather than nmap's less friendly error, and NSE and OS scans carry timeouts (`--script-timeout`, `--host-timeout`) so a script category with a long internal timeout can't hang a run indefinitely. If nmap isn't installed, Omega falls back to its own parallel TCP-connect probing plus a small built-in port/service table for discovery, scanning, and service ID, so the language still runs end to end with zero external tools. OS detection and NSE scripts have no honest TCP-connect equivalent, so the fallback backend reports those as unsupported rather than faking a result.

HTTP vulnerability scanning (`src/http.rs`, `src/webchecks.rs`) is what `scan web { paths headers }` does — Omega's purpose-built equivalent of nikto, distinct from nmap's generic NSE vuln category. A hand-rolled, zero-dependency HTTP/1.1 client checks a curated list of roughly 30 commonly-exposed sensitive paths (`.git/config`, `.env`, admin panels, backup files, exposed credentials and keys) and flags anything that responds 200, 401, or 403. A header check flags missing recommended security headers (`Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Referrer-Policy`). It runs against a host's already-discovered open web ports (80, 8080, 8000, 8888, 443, 8443) or an explicit `port <n>`. HTTPS ports are currently probed as plain HTTP — TLS support isn't implemented yet, and the report says so explicitly rather than silently misreporting an HTTPS-only host.

DNS and email security checks (`src/dns.rs`, `src/dnschecks.rs`) power `scan dns "domain" { spf dmarc subdomains }`. A hand-rolled, zero-dependency DNS client (raw UDP, RFC 1035 wire format, no external resolver crate) checks for SPF and DMARC TXT records, since missing either is a real and common email-spoofing exposure. Subdomain enumeration runs against a curated wordlist of about 34 common names — this is wordlist-based, not Certificate-Transparency-based, so real recon tools like subfinder or amass will discover far more via crt.sh-style CT log queries, which Omega doesn't do yet. `scan dns` requires `authorized_scope` to already be declared in the script, even though DNS lookups against a public resolver aren't IP-scoped, because Omega's "declare scope before anything runs" principle still applies at the script level.

Local network discovery via ARP (`src/arp.rs`) is what `scan network` performs: it reads the OS's own ARP table (`/proc/net/arp` on Linux, `arp -a` on macOS/BSD) after forcing a connection sweep to populate it, rather than sending raw ARP packets directly, which would need an unsafe, Linux-only raw socket outside this project's design so far. It enriches already-discovered hosts with MAC address and a best-effort vendor (a small curated OUI table of about 24 common vendors, not the full IEEE registry), and can surface devices that answered ARP but received no port scan at all. Known limitations are that it only sees the local network segment, not across a router, and that ARP entries can go stale between the sweep and the read, so not every host is guaranteed a MAC on a given run.

Structured reporting (`src/report.rs`) means `report` with no destination prints to stdout as before, while `report to "findings.json"` or `report to "findings.html"` write a hand-rolled structured report with no serde or templating dependency, including host MAC/vendor and domain-level DNS findings. Every finding, whether from NSE scripts or web checks, is classified high, medium, or info by severity so results are usable at scale rather than a wall of raw text.

Target-list export for tool chaining (`src/export.rs`) lets `export hosts to "targets.txt"` write plain `ip:port` lines, or `.csv` write `ip,port,service` columns, so recon results can feed into another tool instead of Omega being a closed loop.

Parallel execution (`src/parallel.rs`) probes hosts, ports, and web checks concurrently through a bounded thread pool built on `std::thread::scope`, with no external crates, so `discover hosts` on a /24 doesn't mean 254 sequential connect timeouts.

CIDR handling (`src/ip.rs`) is hand-rolled IPv4/CIDR parsing and host iteration, capped at 256 hosts per target as a safety limit.

## Building from source

```bash
cargo build --release
cargo install --path .
```

No external crates are required for the core interpreter, which keeps the toolchain requirement low and avoids dependency-version surprises.

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

`examples/first_milestone.omg` walks through the milestone from the design doc: target, discover, scan ports, identify services, report. `examples/assessment.omega` wraps the same flow in a named `assessment { }` block with an explicit `scan ports { ports ... services timeout ... }` block. `examples/scope_violation.omega` demonstrates that a target outside a declared `authorized_scope` is rejected instead of scanned. `examples/deep_scan.omg` runs OS detection and NSE vuln scripts against a single host. `examples/report_test.omg` writes structured JSON and HTML reports. `examples/severity_test.omg` exercises high/medium/info finding classification. `examples/web_scan.omg` runs HTTP vulnerability scanning (`scan web`). `examples/network_scan.omg` runs ARP-based local network discovery (`scan network`).

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
}

scan web {
    paths                               # check curated sensitive-path list
    headers                             # check for missing security headers
    port <n>                            # optional explicit port
}

scan dns "domain.com" {
    spf                                 # check for SPF TXT record
    dmarc                               # check for DMARC TXT record
    subdomains                          # enumerate common subdomains
}

scan network                            # ARP-based local network discovery

identify services                       # standalone version of the flag above

report                                  # print to stdout
report to "findings.json"               # write structured JSON
report to "findings.html"               # write styled HTML

export hosts to "targets.txt"           # plain ip lines
export hosts to "targets.csv"           # ip,port,service columns

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

Audit logging is planned: an append-only record of every target touched and command run, for accountability on real engagements. Subdomain discovery will move toward Certificate Transparency (crt.sh-style) lookups, replacing or supplementing the current wordlist approach with real-world coverage. DNS zone transfer (AXFR) testing is on the roadmap, along with dedicated TLS/SSL checks — certificate expiry, weak ciphers, protocol version — with their own syntax, beyond what's reachable via raw `nse_scripts`. TLS support for `scan web` against HTTPS-only hosts is planned, as is a dry-run/explain mode to preview exactly what a script would do before it touches the network. SNMP and SMB-specific information-disclosure checks are also planned, along with UDP scanning, nmap timing templates, and a higher (but still deliberate) host-count cap for larger network ranges. The OUI vendor table for `scan network` will grow beyond its current ~24 curated entries toward something closer to the full IEEE registry. Finally, the `scan <ip>` one-line shorthand and `monitor network` / `when ... detected { }` event-driven blocks from the original design doc, along with IPv6 support in the CIDR module, are still on the list.
