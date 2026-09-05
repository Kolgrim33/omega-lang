// Local-network ARP table discovery.
//
// Unlike every other scan in Omega, this doesn't send its own packets —
// it reads whatever ARP table the OS kernel already maintains, after a
// quick connection sweep has forced it to populate. Sending raw ARP
// requests directly would need a raw AF_PACKET socket (Linux-only, and
// needs `unsafe` libc calls with no equivalent in std), which doesn't
// fit this project's zero-dependency, no-unsafe design so far — reading
// the kernel's own table is the honest zero-dependency alternative.
//
// Known limitation: this only reveals devices on the same local network
// segment (the same L2 broadcast domain). It cannot see anything across
// a router, unlike IP-based scanning which works over any routed network
// or the internet.

use std::fs;
use std::process::Command;

pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
}

/// Reads whatever ARP entries the OS currently has cached. Call this
/// *after* attempting some traffic to the target range (a discovery
/// sweep already does this as a side effect) — an IP the OS has never
/// tried to reach won't have an ARP entry yet.
pub fn read_table() -> Vec<ArpEntry> {
    if cfg!(target_os = "linux") {
        read_table_linux()
    } else {
        read_table_via_arp_command()
    }
}

fn read_table_linux() -> Vec<ArpEntry> {
    let contents = match fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut entries = Vec::new();
    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let ip = cols[0];
        let mac = cols[3];
        if mac == "00:00:00:00:00:00" {
            continue; // incomplete entry — host never actually answered
        }
        entries.push(ArpEntry {
            ip: ip.to_string(),
            mac: mac.to_lowercase(),
        });
    }
    entries
}

/// Fallback for macOS/BSD, via the `arp` command's cache-display mode —
/// this reads the existing table, same as /proc/net/arp; it does not
/// send any packets itself.
fn read_table_via_arp_command() -> Vec<ArpEntry> {
    let output = match Command::new("arp").arg("-a").arg("-n").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    for line in text.lines() {
        // Typical line: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        let ip = line
            .split('(')
            .nth(1)
            .and_then(|s| s.split(')').next())
            .map(|s| s.to_string());
        let mac = line
            .split(" at ")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .map(|s| s.to_lowercase());
        if let (Some(ip), Some(mac)) = (ip, mac) {
            if mac.contains("incomplete") {
                continue;
            }
            entries.push(ArpEntry { ip, mac });
        }
    }
    entries
}

/// Small curated OUI (MAC vendor prefix) table — not the full IEEE
/// registry (30,000+ entries), just enough common vendors to be a useful
/// hint rather than a complete lookup.
const OUI_TABLE: &[(&str, &str)] = &[
    ("b8:27:eb", "Raspberry Pi Foundation"),
    ("dc:a6:32", "Raspberry Pi Foundation"),
    ("e4:5f:01", "Raspberry Pi Foundation"),
    ("00:1a:11", "Google"),
    ("f4:f5:d8", "Google"),
    ("3c:5a:b4", "Google"),
    ("fc:ec:da", "Amazon"),
    ("74:c2:46", "Amazon"),
    ("00:17:88", "Philips (Hue)"),
    ("00:1e:c2", "Apple"),
    ("ac:de:48", "Apple"),
    ("f0:18:98", "Apple"),
    ("00:50:56", "VMware"),
    ("08:00:27", "VirtualBox"),
    ("00:0c:29", "VMware"),
    ("18:fe:34", "Espressif (ESP32/ESP8266)"),
    ("24:0a:c4", "Espressif (ESP32/ESP8266)"),
    ("ec:fa:bc", "Espressif (ESP32/ESP8266)"),
    ("00:1b:63", "Cisco"),
    ("00:0e:8f", "Cisco"),
    ("f0:9f:c2", "Ubiquiti Networks"),
    ("24:a4:3c", "Ubiquiti Networks"),
    ("50:c7:bf", "TP-Link"),
    ("14:cc:20", "TP-Link"),
];

pub fn vendor_lookup(mac: &str) -> Option<&'static str> {
    let prefix = mac.split(':').take(3).collect::<Vec<_>>().join(":");
    OUI_TABLE
        .iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}
