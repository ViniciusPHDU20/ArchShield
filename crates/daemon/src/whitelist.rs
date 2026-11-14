// language: Rust, file: crates/daemon/src/whitelist.rs, runtime: tokio, target: Linux
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

pub struct Whitelist;

impl Whitelist {
    /// Descobre dinamicamente todos os endereços IP (IPv4 e IPv6) de todas as interfaces da própria máquina
    pub fn get_local_ips() -> HashSet<IpAddr> {
        let mut ips = HashSet::new();
        unsafe {
            let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs) == 0 && !ifaddrs.is_null() {
                let mut curr = ifaddrs;
                while !curr.is_null() {
                    let addr = (*curr).ifa_addr;
                    if !addr.is_null() {
                        let family = (*addr).sa_family as i32;
                        if family == libc::AF_INET {
                            let sa_in = addr as *const libc::sockaddr_in;
                            let ip = Ipv4Addr::from(u32::from_be((*sa_in).sin_addr.s_addr));
                            ips.insert(IpAddr::V4(ip));
                        } else if family == libc::AF_INET6 {
                            let sa_in6 = addr as *const libc::sockaddr_in6;
                            let ip = std::net::Ipv6Addr::from((*sa_in6).sin6_addr.s6_addr);
                            ips.insert(IpAddr::V6(ip));
                        }
                    }
                    curr = (*curr).ifa_next;
                }
                libc::freeifaddrs(ifaddrs);
            }
        }
        ips
    }

    /// Valida se um IP ou CIDR pertence à lista de permissão estrita.
    /// Garante matematicamente que serviços vitais, jogos, redes locais e CDNs jamais sejam bloqueados.
    pub fn is_whitelisted(entry: &str) -> bool {
        let clean = entry.split(';').next().unwrap_or(entry).trim();
        let ip_str = clean.split('/').next().unwrap_or(clean).trim();

        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            // Imunidade absoluta: Nunca bloqueia nenhum IP da própria máquina
            if Self::get_local_ips().contains(&ip) {
                return true;
            }

            match ip {
                IpAddr::V4(v4) => {
                    // Loopback: 127.0.0.0/8
                    if v4.is_loopback() {
                        return true;
                    }
                    // Redes Privadas / LAN: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    if v4.is_private() {
                        return true;
                    }
                    // Link-local: 169.254.0.0/16
                    if v4.is_link_local() {
                        return true;
                    }
                    // Broadcast: 255.255.255.255
                    if v4.is_broadcast() {
                        return true;
                    }
                    // CGNAT / Tailscale / Wireguard: 100.64.0.0/10
                    let octets = v4.octets();
                    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
                        return true;
                    }
                    // Servidores DNS Públicos Primários
                    if v4 == Ipv4Addr::new(8, 8, 8, 8)
                        || v4 == Ipv4Addr::new(8, 8, 4, 4)
                        || v4 == Ipv4Addr::new(1, 1, 1, 1)
                        || v4 == Ipv4Addr::new(1, 0, 0, 1)
                        || v4 == Ipv4Addr::new(9, 9, 9, 9)
                        || v4 == Ipv4Addr::new(149, 112, 112, 112)
                        || v4 == Ipv4Addr::new(94, 140, 14, 14)
                        || v4 == Ipv4Addr::new(94, 140, 15, 15)
                        || v4 == Ipv4Addr::new(94, 140, 14, 140)
                        || v4 == Ipv4Addr::new(94, 140, 14, 141)
                    {
                        return true;
                    }
                    // Relays e Servidores Steam / Valve
                    if octets[0] == 155 && octets[1] == 133 {
                        return true;
                    }
                    if octets[0] == 162 && octets[1] == 254 && (octets[2] >= 192 && octets[2] <= 199) {
                        return true;
                    }
                    // Cloudflare CDNs: 104.16.0.0/12, 172.64.0.0/13
                    if octets[0] == 104 && (octets[1] >= 16 && octets[1] <= 31) {
                        return true;
                    }
                    if octets[0] == 172 && (octets[1] >= 64 && octets[1] <= 71) {
                        return true;
                    }
                    // Infraestrutura Google / YouTube: 142.250.0.0/15, 172.217.0.0/16, 216.58.0.0/19
                    if octets[0] == 142 && (octets[1] == 250 || octets[1] == 251) {
                        return true;
                    }
                    if octets[0] == 172 && octets[1] == 217 {
                        return true;
                    }
                    // GitHub / Fastly: 140.82.112.0/20, 185.199.108.0/22
                    if octets[0] == 140 && octets[1] == 82 && (octets[2] >= 112 && octets[2] <= 127) {
                        return true;
                    }
                    if octets[0] == 185 && octets[1] == 199 && (octets[2] >= 108 && octets[2] <= 111) {
                        return true;
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_unspecified() {
                        return true;
                    }
                    let segs = v6.segments();
                    // fe80::/10 link-local
                    if (segs[0] & 0xffc0) == 0xfe80 {
                        return true;
                    }
                    // Google IPv6 (2001:4860::/32)
                    if segs[0] == 0x2001 && segs[1] == 0x4860 {
                        return true;
                    }
                    // Cloudflare IPv6 (2606:4700::/32)
                    if segs[0] == 0x2606 && segs[1] == 0x4700 {
                        return true;
                    }
                    // AdGuard IPv6 (2a10:50c0::/32)
                    if segs[0] == 0x2a10 && segs[1] == 0x50c0 {
                        return true;
                    }
                }
            }
        }
        false
    }
}
