# Omega

<img width="1080" height="1080" alt="omegalogo" src="https://github.com/user-attachments/assets/ed38bd9f-303d-4278-95f0-3bc6e432bac7" />


Omega is a  security-first programming language for cybersecurity
automation. Instead of writing Python calls into scanning libraries, you
describe the security operation you want:

```
target 192.168.1.0/24

discover hosts
scan ports
identify services

report
```

## What this build actually does

This is a real tree-walking interpreter, not a mockup:

- **Lexer/parser** (`src/lexer.rs`, `src/parser.rs`, `src/ast.rs`) — turns
  `.omega` source into an AST covering `target`, `authorized_scope`,
  `discover [hosts]`, `scan ports { ... }`, `identify services`, `report`,
  and `assessment "name" { ... }` blocks.
- **Scope enforcement** (`src/interpreter.rs`) — `authorized_scope` (or the
  first `target`, implicitly) is checked before every host is touched. A
  target outside scope is refused at runtime with
  `ERROR: target X is outside authorized scope.` instead of silently
  running.
- **Real network backends** (`src/scan.rs`) — host discovery, port
  scanning, and service identification actually run:
  - if `nmap` is on PATH, Omega shells out to it (`-sn` for discovery,
    `-p`/default port set for scanning, `-sV` for service ID) and parses
    its output;
  - if `nmap` isn't installed, Omega falls back to its own parallel
    TCP-connect probing plus a small built-in port/service table, so the
    language still runs end to end with zero external tools.
- **Parallel execution** (`src/parallel.rs`) — hosts and ports are probed
  concurrently (bounded thread pool built on `std::thread::scope`, no
  external crates), so `discover hosts` on a /24 doesn't mean 254
  sequential connect timeouts.
- **CIDR handling** (`src/ip.rs`) — hand-rolled IPv4/CIDR parsing and host
  iteration, capped at 256 hosts per target as a safety limit.

## Building and running

```
cargo build
cargo run -- examples/first_milestone.omega
```

No external crates are required — this keeps the toolchain requirement
low and avoids dependency-version surprises.

## Example scripts

- `examples/first_milestone.omega` — the milestone from the design doc:
  target, discover, scan ports, identify services, report.
- `examples/assessment.omega` — the same flow wrapped in a named
  `assessment { }` block with an explicit `scan ports { ports ... services
  timeout ... }` block.
- `examples/scope_violation.omega` — demonstrates that a `target` outside
  a declared `authorized_scope` is rejected instead of scanned.

## Tests

```
cargo test
```

## What's next (not built yet)

- The `scan <ip>` one-line shorthand and `monitor network` / `when ...
  detected { }` event-driven blocks from the design doc.
- Writing reports to a file (`report to "file.txt"`) instead of stdout
  only.
- IPv6 support in the CIDR module.
- A real backend abstraction so tools beyond nmap (SSH, HTTP probes) can
  plug in the way the design doc's "under the hood" diagram describes.
