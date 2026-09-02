// Minimal IPv4 + CIDR support. Deliberately hand-rolled with zero
// dependencies for the MVP; a real release would likely swap this for a
// crate like `ipnet`, but keeping this self-contained makes the language
// core easy to read end to end.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub base: u32,
    pub prefix: u8,
}

/// Safety cap on how many hosts a single `discover`/`scan` will iterate,
/// so a stray "target 0.0.0.0/0" can't make Omega try to sweep the whole
/// internet.
pub const MAX_HOSTS_PER_TARGET: usize = 256;

impl Cidr {
    pub fn parse(input: &str) -> Result<Cidr, String> {
        let (addr_part, prefix_part) = match input.split_once('/') {
            Some((a, p)) => (a, p),
            None => (input, "32"),
        };
        let base = parse_ipv4(addr_part)?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("invalid CIDR prefix in '{}'", input))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix out of range in '{}'", input));
        }
        Ok(Cidr { base, prefix })
    }

    pub fn contains(&self, ip: u32) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let mask = mask_for_prefix(self.prefix);
        (self.base & mask) == (ip & mask)
    }

    /// Host addresses in the network, in order, capped at
    /// MAX_HOSTS_PER_TARGET. For /31 and /32 this just yields the address
    /// itself (point-to-point / single host), matching how people actually
    /// write `target 192.168.1.1`.
    pub fn hosts(&self) -> Vec<u32> {
        if self.prefix >= 31 {
            return vec![self.base];
        }
        let mask = mask_for_prefix(self.prefix);
        let network = self.base & mask;
        let broadcast = network | !mask;
        let mut out = Vec::new();
        let mut addr = network + 1; // skip network address
        while addr < broadcast && out.len() < MAX_HOSTS_PER_TARGET {
            out.push(addr);
            addr += 1;
        }
        out
    }
}

fn mask_for_prefix(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

pub fn parse_ipv4(s: &str) -> Result<u32, String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4 address '{}'", s));
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p
            .parse::<u8>()
            .map_err(|_| format!("invalid IPv4 address '{}'", s))?;
    }
    Ok(u32::from_be_bytes(octets))
}

pub fn format_ipv4(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}
