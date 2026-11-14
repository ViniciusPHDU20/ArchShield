// language: Rust, file: crates/daemon/src/sniffer.rs, runtime: tokio, target: Linux
use crate::config::DaemonConfig;
use crate::firewall::FirewallManager;
use crate::notify::Notifier;
use crate::sni::extract_sni;
use crate::state::SharedState;
use archshield_core::{describe_port, fingerprint_syn, IntruderEvent};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::ffi::CString;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info, warn};

pub struct PacketSniffer;

impl PacketSniffer {
    pub async fn start(config: DaemonConfig, state: SharedState) {
        tokio::task::spawn_blocking(move || {
            Self::run_loop(config, state);
        });
    }

    fn run_loop(config: DaemonConfig, state: SharedState) {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            warn!("⚠️ PacketSniffer: Não executando como root. Captura de pacotes raw pode falhar.");
        }

        let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
        if fd < 0 {
            error!("❌ Falha ao criar raw AF_PACKET socket na interface {}", config.interface);
            return;
        }

        let iface_c = match CString::new(config.interface.clone()) {
            Ok(c) => c,
            Err(_) => {
                error!("❌ Nome de interface inválido: {}", config.interface);
                unsafe { libc::close(fd) };
                return;
            }
        };

        let if_idx = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
        if if_idx == 0 {
            error!("❌ Interface {} não encontrada.", config.interface);
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
            error!("❌ Falha ao vincular socket à interface {}", config.interface);
            unsafe { libc::close(fd) };
            return;
        }

        info!("🕸️ [RAW-SNIFFER] Motor de captura e de armadilha ativo em '{}'", config.interface);

        let mut buf = [0u8; 65535];
        loop {
            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut sll_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                    &mut sll_len,
                )
            };

            if n <= 0 {
                continue;
            }

            // Descarta pacotes enviados por esta própria máquina (outbound) para a armadilha
            let is_outgoing = sll.sll_pkttype == libc::PACKET_OUTGOING;

            let frame = &buf[..n as usize];
            if let Some(eth) = EthernetPacket::new(frame) {
                if let Ok(st) = state.try_read() {
                    st.record_packet();
                }
                Self::process_ethernet(&eth, is_outgoing, &config, &state);
            }
        }
    }

    fn process_ethernet(eth: &EthernetPacket, is_outgoing: bool, config: &DaemonConfig, state: &SharedState) {
        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    let src = ipv4.get_source().to_string();
                    let dst = ipv4.get_destination().to_string();
                    let ttl = ipv4.get_ttl();
                    Self::process_transport(
                        ipv4.get_next_level_protocol(),
                        ipv4.payload(),
                        &src,
                        &dst,
                        ttl,
                        is_outgoing,
                        config,
                        state,
                    );
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                    let src = ipv6.get_source().to_string();
                    let dst = ipv6.get_destination().to_string();
                    let ttl = ipv6.get_hop_limit();
                    Self::process_transport(
                        ipv6.get_next_header(),
                        ipv6.payload(),
                        &src,
                        &dst,
                        ttl,
                        is_outgoing,
                        config,
                        state,
                    );
                }
            }
            _ => {}
        }
    }

    fn process_transport(
        proto: pnet_packet::ip::IpNextHeaderProtocol,
        payload: &[u8],
        src: &str,
        dst: &str,
        ttl: u8,
        is_outgoing: bool,
        config: &DaemonConfig,
        state: &SharedState,
    ) {
        match proto {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    let flags = tcp.get_flags();
                    let dst_port = tcp.get_destination();

                    // Armadilha e fingerprint são disparados EXCLUSIVAMENTE para conexões INCOMING (inbound)
                    if !is_outgoing && (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) == 0 {
                        if let Ok(src_ip) = src.parse::<std::net::IpAddr>() {
                            if !crate::whitelist::Whitelist::get_local_ips().contains(&src_ip) {
                                Self::handle_syn(&tcp, src, dst, dst_port, ttl, config, state);
                            }
                        }
                    }

                    // Se for tráfego TLS na porta 443 com payload, extrai SNI
                    if dst_port == 443 && !tcp.payload().is_empty() {
                        if let Some(sni) = extract_sni(tcp.payload()) {
                            let dst_ip = dst.to_string();
                            tokio::spawn({
                                let state = Arc::clone(state);
                                async move {
                                    state.write().await.associate_ip_domain(dst_ip, sni);
                                }
                            });
                        }
                    }
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(_udp) = UdpPacket::new(payload) {
                    // UDP telemetry hooks
                }
            }
            IpNextHeaderProtocols::Icmp | IpNextHeaderProtocols::Icmpv6 => {
                if !is_outgoing {
                    if let Some(covert) = archshield_core::analyze_icmp_payload(payload, src, dst) {
                        let alert_msg = format!("Canal Oculto ICMP de {} para {}: {}", src, dst, covert.summary);
                        Notifier::alert_covert(&alert_msg);
                        tokio::spawn({
                            let state = Arc::clone(state);
                            async move {
                                state.write().await.record_covert_alert(covert);
                            }
                        });
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_syn(
        tcp: &TcpPacket,
        src: &str,
        _dst: &str,
        dst_port: u16,
        ttl: u8,
        config: &DaemonConfig,
        state: &SharedState,
    ) {
        let window = tcp.get_window();
        let header_len = (tcp.get_data_offset() as usize) * 4;
        let mut options = Vec::new();

        if header_len > 20 && header_len <= tcp.packet().len() {
            let opts = &tcp.packet()[20..header_len];
            let mut i = 0;
            while i < opts.len() {
                let kind = opts[i];
                match kind {
                    0 => {
                        options.push("EOL".to_string());
                        break;
                    }
                    1 => {
                        options.push("NOP".to_string());
                        i += 1;
                    }
                    2 => {
                        options.push("MSS".to_string());
                        let len = if i + 1 < opts.len() { opts[i + 1] as usize } else { 4 };
                        i += len.max(2);
                    }
                    3 => {
                        options.push("WScale".to_string());
                        let len = if i + 1 < opts.len() { opts[i + 1] as usize } else { 3 };
                        i += len.max(2);
                    }
                    4 => {
                        options.push("SAckOK".to_string());
                        let len = if i + 1 < opts.len() { opts[i + 1] as usize } else { 2 };
                        i += len.max(2);
                    }
                    8 => {
                        options.push("Timestamp".to_string());
                        let len = if i + 1 < opts.len() { opts[i + 1] as usize } else { 10 };
                        i += len.max(2);
                    }
                    _ => {
                        let len = if i + 1 < opts.len() { opts[i + 1] as usize } else { 1 };
                        i += len.max(1);
                    }
                }
            }
        }

        let payload_len = tcp.payload().len();
        let fp = fingerprint_syn(ttl, window, &options, payload_len);
        let is_ghost_port = config.ghost_ports.contains(&dst_port);

        // Se for scanner identificado ou conexão batendo em porta fantasma da armadilha
        if fp.is_scanner || is_ghost_port {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let hours = (now / 3600) % 24;
            let mins = (now / 60) % 60;
            let secs = now % 60;
            let formatted_time = format!("{:02}:{:02}:{:02}", hours, mins, secs);

            let is_blocked = FirewallManager::is_ip_blocked(src);

            let event = IntruderEvent {
                ip: src.to_string(),
                target_port: dst_port,
                port_desc: describe_port(dst_port).to_string(),
                proto: "TCP".to_string(),
                os_family: fp.os_family.clone(),
                scanner_name: fp.scanner_name.clone(),
                is_scanner: fp.is_scanner,
                confidence: fp.confidence.clone(),
                timestamp: now,
                formatted_time,
                signature: fp.signature.clone(),
                summary: if is_ghost_port && !fp.is_scanner {
                    format!("Probe na porta fantasma {} [{}]", dst_port, describe_port(dst_port))
                } else {
                    fp.summary.clone()
                },
                is_blocked,
                country: "Local/Rede".to_string(),
                org: String::new(),
            };

            // Auto-bloqueio se for scanner agressivo identificado (Nmap, Masscan, ZMap)
            if fp.is_scanner && !is_blocked {
                FirewallManager::block_ip(src, config.dry_run);

                // Notificação filtrada: dispara popup APENAS para novos atacantes ativos isolados
                let reason = if fp.scanner_name.is_empty() {
                    "Varredura hostil ativa".to_string()
                } else {
                    format!("Scanner automatizado ({})", fp.scanner_name)
                };
                Notifier::alert_blocked_attacker(src, &reason);
            }

            tokio::spawn({
                let state = Arc::clone(state);
                async move {
                    state.write().await.record_intruder(event);
                }
            });
        }
    }
}
