# Omega

<img width="240" alt="omegalogo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />

Omega is a security-first programming language for cybersecurity
automation. Instead of writing Python calls into scanning libraries, you
describe the security operation you want:

target 192.168.1.0/24
discover hosts
scan ports { services os_detect nse_scripts "vuln" }
scan web { paths headers }
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
  `scan web { ... }`, `identify services`, `report [to "..."]`, and
  `assessment "name" { ... }` blocks.
- **Scope enforcement** (`src/interpreter.rs`) — `authorized_scope` (or the
  first `target`, implicitly) is checked before every host is touched. A
  target outside scope is refused at runtime with
  `ERROR: target X is outside authorized scope.` instead of silently
  running.
- **Real network backends** (`src/backend.rs`, `src/scan.rs`) — host
  discovery, port scanning, service identification, OS fingerprinting,
  and NSE scripts all actually run, via a `ProbeBackend` trait so new
  backends can be added without touching the interpreter:
  - if `nmap` is on PATH, Omega shells out to it (`-sn` for discovery,
    `-p`/default port set for scanning, `-sV` for service ID, `-O` for OS
    fingerprinting, `--script <category>` for NSE) and parses its output.
    OS detection checks for root privileges up front and fails with a
    clear message rather than nmap's less friendly error; NSE and OS
    scans carry timeouts so a script category with a long internal
    timeout can't hang a run indefinitely;
  - if `nmap` isn't installed, Omega falls back to its own parallel
    TCP-connect probing plus a small built-in port/service table for
    discovery/scanning/service-ID, so the language still runs end to end
    with zero external tools. OS detection and NSE scripts have no honest
    TCP-connect equivalent, so the fallback backend reports those as
    unsupported rather than faking a result.
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
    yet, and the report says so explicitly rather than silently
    misreporting an HTTPS-only host.
- **Structured reporting** (`src/report.rs`) — `report` with no
  destination prints to stdout as before; `report to "findings.json"` or
  `report to "findings.html"` write a hand-rolled structured report (no
  serde/templating dependency). Every finding — from NSE scripts or web
  checks — is classified `high`/`medium`/`info` by severity so results
  are usable at scale, not just a wall of raw text.
- **Parallel execution** (`src/parallel.rs`) — hosts, ports, and web
  checks are probed concurrently (bounded thread pool built on
  `std::thread::scope`, no external crates), so `discover hosts` on a
  /24 doesn't mean 254 sequential connect timeouts.
- **CIDR handling** (`src/ip.rs`) — hand-rolled IPv4/CIDR parsing and host
  iteration, capped at 256 hosts per target as a safety limit.

## Building from source

cargo build --release
cargo install --path .


No external crates are required for the core interpreter — this keeps
the toolchain requirement low and avoids dependency-version surprises.

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
- `examples/web_scan.omg` — HTTP vulnerability scanning (`scan web`).

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
}

scan web {
paths # check curated sensitive-path list
headers # check for missing security headers
port <n> # optional explicit port
}

identify services # standalone version of the flag above

report # print to stdout
report to "findings.json" # write structured JSON
report to "findings.html" # write styled HTML

assessment "name" { ... } # named wrapper — can contain any of the above


## Tests

cargo test


## What's next (not built yet)

- Audit logging — an append-only record of every target touched and
  command run, for accountability on real engagements.
- Dedicated TLS/SSL checks (certificate expiry, weak ciphers, protocol
  version) with their own syntax, beyond what's reachable via raw
  `nse_scripts`.
- TLS support for `scan web` against HTTPS-only hosts.
- A dry-run/explain mode to preview exactly what a script would do
  before it touches the network.
- UDP scanning, nmap timing templates, and a higher (but still
  deliberate) host-count cap for larger network ranges.
- The `scan <ip>` one-line shorthand and `monitor network` / `when ...
  detected { }` event-driven blocks from the original design doc.
- IPv6 support in the CIDR module.
