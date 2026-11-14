// language: Rust, file: crates/daemon/src/dns.rs, runtime: tokio, target: Linux
use crate::state::SharedState;
use pnet_packet::Packet;
use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct DnsSniffer;

impl DnsSniffer {
    pub async fn start(state: SharedState) {
        tokio::task::spawn_blocking(move || {
            Self::run_loop(state);
        });
    }

    fn run_loop(state: SharedState) {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            warn!("⚠️ DnsSniffer: Executando sem privilégios de root, sniffing em 'lo' pode falhar.");
        }

        // Cria socket AF_PACKET SOCK_DGRAM para capturar na camada IP sem header ethernet em 'lo'
        let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, protocol) };
        if fd < 0 {
            error!("❌ Falha ao criar raw socket para DNS sniffer em lo (errno: {})", std::io::Error::last_os_error());
            return;
        }

        let lo_name = CString::new("lo").unwrap();
        let if_idx = unsafe { libc::if_nametoindex(lo_name.as_ptr()) };
        if if_idx == 0 {
            error!("❌ Interface 'lo' não encontrada.");
            unsafe { libc::close(fd) };
            return;
        }

        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_ifindex = if_idx as i32;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();

        let bind_res = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };

        if bind_res < 0 {
            error!("❌ Falha ao bindar raw socket na interface 'lo'");
            unsafe { libc::close(fd) };
            return;
        }

        info!("👁️ [DNS-SNIFFER] Escuta de telemetria DNS ativa em 'lo' (127.0.0.53:53)");

        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if n <= 0 {
                continue;
            }

            let pkt = &buf[..n as usize];
            Self::dissect_ip_packet(pkt, &state);
        }
    }

    fn dissect_ip_packet(pkt: &[u8], state: &SharedState) {
        if pkt.is_empty() {
            return;
        }

        let version = pkt[0] >> 4;
        match version {
            4 => {
                if let Some(ipv4) = pnet_packet::ipv4::Ipv4Packet::new(pkt) {
                    if ipv4.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Udp {
                        if let Some(udp) = pnet_packet::udp::UdpPacket::new(ipv4.payload()) {
                            if udp.get_source() == 53 || udp.get_destination() == 53 {
                                Self::parse_dns_payload(udp.payload(), state);
                            }
                        }
                    }
                }
            }
            6 => {
                if let Some(ipv6) = pnet_packet::ipv6::Ipv6Packet::new(pkt) {
                    if ipv6.get_next_header() == pnet_packet::ip::IpNextHeaderProtocols::Udp {
                        if let Some(udp) = pnet_packet::udp::UdpPacket::new(ipv6.payload()) {
                            if udp.get_source() == 53 || udp.get_destination() == 53 {
                                Self::parse_dns_payload(udp.payload(), state);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn parse_dns_payload(payload: &[u8], state: &SharedState) {
        if payload.len() < 12 {
            return;
        }

        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        if !is_response {
            return;
        }

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

        if qdcount == 0 || ancount == 0 {
            return;
        }

        let mut offset = 12;

        let mut first_qname = String::new();
        for i in 0..qdcount {
            if let Some((name, next_off)) = Self::parse_dns_name(payload, offset) {
                if i == 0 {
                    first_qname = name;
                }
                offset = next_off + 4;
                if offset > payload.len() {
                    return;
                }
            } else {
                return;
            }
        }

        if first_qname.is_empty() {
            return;
        }

        // Inspeção de Contrainteligência: Detecção de DNS Tunneling e Exfiltração Furtiva
        if let Some(covert) = archshield_core::analyze_dns_query(&first_qname) {
            tokio::spawn({
                let state = Arc::clone(state);
                async move {
                    state.write().await.record_covert_alert(covert);
                }
            });
        }

        for _ in 0..ancount {
            if offset >= payload.len() {
                break;
            }

            if let Some((_, next_off)) = Self::parse_dns_name(payload, offset) {
                offset = next_off;
                if offset + 10 > payload.len() {
                    break;
                }

                let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                let rdlen = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
                offset += 10;

                if offset + rdlen > payload.len() {
                    break;
                }

                let rdata = &payload[offset..offset + rdlen];
                offset += rdlen;

                if rtype == 1 && rdlen == 4 {
                    let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string();
                    let domain = first_qname.clone();
                    tokio::spawn({
                        let state = Arc::clone(state);
                        async move {
                            state.write().await.associate_ip_domain(ip, domain);
                        }
                    });
                } else if rtype == 28 && rdlen == 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(rdata);
                    let ip = Ipv6Addr::from(octets).to_string();
                    let domain = first_qname.clone();
                    tokio::spawn({
                        let state = Arc::clone(state);
                        async move {
                            state.write().await.associate_ip_domain(ip, domain);
                        }
                    });
                }
            } else {
                break;
            }
        }
    }

    fn parse_dns_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut original_next_offset = 0;
        let mut depth = 0;

        while offset < buf.len() && depth < 25 {
            let len = buf[offset] as usize;
            if len == 0 {
                if !jumped {
                    original_next_offset = offset + 1;
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if offset + 1 >= buf.len() {
                    return None;
                }
                let pointer = (((len & 0x3F) << 8) | (buf[offset + 1] as usize)) as usize;
                if !jumped {
                    original_next_offset = offset + 2;
                    jumped = true;
                }
                offset = pointer;
                depth += 1;
                continue;
            }

            offset += 1;
            if offset + len > buf.len() {
                return None;
            }

            if let Ok(label) = std::str::from_utf8(&buf[offset..offset + len]) {
                labels.push(label.to_string());
            }
            offset += len;
        }

        let next = if jumped { original_next_offset } else { offset };
        if labels.is_empty() {
            None
        } else {
            Some((labels.join("."), next))
        }
    }
}
