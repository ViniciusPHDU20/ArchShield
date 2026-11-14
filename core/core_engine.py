"""
ArchShield PRO - Sovereign Core Engine v2.1
Features:
- Dual-flow telemetry: Inbound Silent Trap vs Outbound Process Attribution
- Passive OS & Scanner TCP Fingerprint detection (p0f/nmap heuristics)
- Dynamic AppShield Whitelist + Isolation Forest Anomaly Analysis
- Native Netfilter Blackhole synchronization
"""

import logging
import socket
import ipaddress
import re
import subprocess
import os
import time
from multiprocessing import Process, Queue
from scapy.all import sniff, IP, TCP, UDP
from core.intelligence import IntelligenceCore
from core.firewall import FirewallManager
from core.fingerprint import fingerprint_syn, describe_port
from core.conntrack import ProcessTracker
from utils.config import config

class CoreEngine:
    def __init__(self, stats_dict):
        self.packet_queue = Queue(maxsize=20000)
        self.stats = stats_dict
        self.intelligence = IntelligenceCore()
        self.firewall = FirewallManager()
        self.local_ip = self._detect_local_ip()

        # O Motor AppShield: IPs pertencentes a aplicativos protegidos no host
        self.dynamic_safe_ips = set()
        self.vital_apps = ["VESKTOP", "DISCORD", "WEBCORD", "STEAM", "STEAMWEBHELPER", "FIREFOX", "CHROME", "SPOTIFY"]

        # Redes de infraestrutura protegidas (Sem falsos positivos)
        self.infra_networks = [
            "104.16.0.0/12", "172.64.0.0/13", "198.41.128.0/17", # Cloudflare
            "162.158.0.0/15", "162.159.0.0/16",                 # Discord/Cloudflare
            "142.250.0.0/15", "172.217.0.0/16", "34.0.0.0/8",   # Google
            "140.82.112.0/20", "192.30.252.0/22",               # GitHub
            "151.101.0.0/16", "199.232.0.0/16",                 # Fastly
            "2.16.0.0/13", "23.0.0.0/11",                       # Akamai
            "155.133.0.0/16"                                    # Steam (Valve)
        ]

        # Inicializa listas no Manager compartilhado
        self.stats['trapped_intruders'] = []
        self.stats['outbound_conns'] = []
        self.stats['active_conns'] = {}
        self.stats['blocked_ips'] = FirewallManager.get_active_blocks()

    def _detect_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        logging.info(f"🛰️ CORE: Motor Sovereign v2.1 Ativo em {config.INTERFACE} (IP Local: {self.local_ip})...")
        # Arma as portas fantasma silenciosas no firewall
        self.firewall.arm_ghost_ports([21, 22, 23, 445, 3389, 8080])

        p_sniffer = Process(target=self._sniffer_loop, daemon=True)
        p_analyst = Process(target=self._analyst_loop, daemon=True)
        p_sniffer.start()
        p_analyst.start()

    def _sniffer_loop(self):
        def _on_packet(pkt):
            if IP in pkt:
                try:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    ttl = pkt[IP].ttl
                    pkt_len = len(pkt)
                    proto = "OTHER"
                    sport = 0
                    dport = 0
                    tcp_flags = ""
                    tcp_win = 0
                    tcp_options = []

                    if TCP in pkt:
                        proto = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        tcp_flags = str(pkt[TCP].flags)
                        tcp_win = pkt[TCP].window
                        tcp_options = pkt[TCP].options or []
                    elif UDP in pkt:
                        proto = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport

                    self.packet_queue.put({
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "sport": sport,
                        "dport": dport,
                        "ttl": ttl,
                        "len": pkt_len,
                        "tcp_flags": tcp_flags,
                        "tcp_win": tcp_win,
                        "tcp_options": tcp_options,
                        "is_inbound": (dst == self.local_ip)
                    }, block=False)
                except Exception:
                    pass

        sniff(iface=config.INTERFACE, filter="ip", prn=_on_packet, store=False)

    def _is_safe(self, ip: str, port: int) -> bool:
        if ip in self.dynamic_safe_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return True
            if str(addr) in config.GUARDIAN_IPS:
                return True
            if port in config.ALLOWED_PORTS:
                return True
            for net in self.infra_networks + config.GUARDIAN_NETWORKS:
                if addr in ipaddress.ip_network(net):
                    return True
        except Exception:
            pass
        return False

    def _analyst_loop(self):
        features_buffer = []
        packets_history = []
        times_history = []
        last_graph_update = 0
        local_packet_count = 0
        local_active_conns = {}
        trapped_ips = set()
        blocked_list = set(FirewallManager.get_active_blocks())

        while True:
            try:
                pkt_data = self.packet_queue.get()
                local_packet_count += 1

                if local_packet_count % 50 == 0:
                    self.stats['total_packets'] = local_packet_count

                src = pkt_data['src']
                dst = pkt_data['dst']
                proto = pkt_data['proto']
                dport = pkt_data['dport']
                is_inbound = pkt_data['is_inbound']

                # =========================================================================
                # 1. MOTOR SILENT TRAP / ARMADILHA DE INTRUSOS (INBOUND TELEMETRY)
                # =========================================================================
                if is_inbound and proto == "TCP" and "S" in pkt_data['tcp_flags'] and "A" not in pkt_data['tcp_flags']:
                    # Pacote SYN puro de entrada não solicitado: Sonda/Scan/Invasor
                    if not self._is_safe(src, dport) and src not in trapped_ips:
                        # Executa o Fingerprint passivo
                        fp = fingerprint_syn(
                            ip_ttl=pkt_data['ttl'],
                            tcp_win=pkt_data['tcp_win'],
                            tcp_options=pkt_data['tcp_options']
                        )

                        port_name = describe_port(dport)
                        logging.warning(f"🕸️ [ARMADILHA] INVASOR DESMASCARADO: {src} -> Porta {dport} ({port_name}) | OS: {fp['os_family']} | Scanner: {fp['scanner_name']}")

                        trapped_event = {
                            "ip": src,
                            "target_port": dport,
                            "port_desc": port_name,
                            "proto": proto,
                            "os_family": fp["os_family"],
                            "scanner_name": fp["scanner_name"],
                            "is_scanner": fp["is_scanner"],
                            "confidence": fp["confidence"],
                            "timestamp": time.time(),
                            "formatted_time": time.strftime("%H:%M:%S"),
                            "signature": fp["signature"],
                            "summary": fp["summary"],
                            "status": "CAPTURA_SILENCIOSA"
                        }

                        trapped_ips.add(src)
                        # Atualiza lista no Manager (mantém os últimos 50 eventos)
                        current_trapped = list(self.stats.get('trapped_intruders', []))
                        current_trapped.insert(0, trapped_event)
                        self.stats['trapped_intruders'] = current_trapped[:50]

                # =========================================================================
                # 2. MOTOR ISOLATION FOREST (ANOMALIAS DE VOLUME & FLOOD)
                # =========================================================================
                feat = [
                    pkt_data['len'],
                    1 if proto == "TCP" else 0,
                    1 if proto == "UDP" else 0,
                    pkt_data['ttl'],
                    dport
                ]

                if not self._is_safe(src, dport):
                    features_buffer.append(feat)
                    if len(features_buffer) >= config.MIN_TRAIN_SIZE and len(features_buffer) % 200 == 0:
                        self.intelligence.train(features_buffer[-1000:])
                        self.stats['ia_status'] = "ATIVA & PROTEGENDO"

                    if self.intelligence.is_fitted:
                        score = self.intelligence.predict(feat)
                        if score < -0.88:
                            if src not in blocked_list:
                                if self.firewall.block_ip(src):
                                    self.stats['anomalies'] = self.stats.get('anomalies', 0) + 1
                                    blocked_list.add(src)
                                    self.stats['blocked_ips'] = list(blocked_list)
                                    logging.warning(f"💀 [SHIELD] ANOMALIA SEVERA PURGADA: {src} (Score: {score:.2f})")

                # Conexões ativas gerais
                local_active_conns[src] = time.time()

                # =========================================================================
                # 3. CICLO DE SINCRONIZAÇÃO PERIÓDICA (A CADA 2.5 SEGUNDOS)
                # =========================================================================
                now = time.time()
                if now - last_graph_update > 2.5:
                    packets_history.append(local_packet_count)
                    times_history.append(time.strftime("%H:%M:%S", time.localtime(now)))
                    if len(packets_history) > 40:
                        packets_history.pop(0)
                        times_history.pop(0)

                    self.stats['packets_history'] = list(packets_history)
                    self.stats['times_history'] = list(times_history)

                    local_active_conns = {k: v for k, v in local_active_conns.items() if now - v < 20}
                    self.stats['active_conns'] = dict(local_active_conns)

                    # Rastreamento detalhado de conexões ativas por processo (ProcessTracker)
                    try:
                        active_sockets = ProcessTracker.get_active_connections()
                        outbound_list = []
                        new_safe_ips = set()

                        for sock in active_sockets:
                            p_name = sock['process'].upper()
                            # Se for app vital, adiciona o IP remoto à whitelist dinâmica
                            if any(vital in p_name for vital in self.vital_apps):
                                if sock['remote_ip'] not in ("*", "", "127.0.0.1", "::1"):
                                    new_safe_ips.add(sock['remote_ip'])

                            if not sock['is_loopback'] and sock['remote_ip'] not in ("*", ""):
                                outbound_list.append({
                                    "process": sock['process'],
                                    "pid": sock['pid'],
                                    "proto": sock['proto'],
                                    "local": f"{sock['local_ip']}:{sock['local_port']}",
                                    "remote": f"{sock['remote_ip']}:{sock['remote_port']}",
                                    "remote_ip": sock['remote_ip'],
                                    "state": sock['state']
                                })

                        self.dynamic_safe_ips = new_safe_ips
                        self.stats['outbound_conns'] = outbound_list[:60]
                    except Exception as e:
                        logging.error(f"Erro ao atualizar telemetria de processos: {e}")

                    # Sincroniza lista real de bloqueios do iptables
                    try:
                        current_blocks = FirewallManager.get_active_blocks()
                        self.stats['blocked_ips'] = current_blocks
                        blocked_list = set(current_blocks)
                    except Exception:
                        pass

                    last_graph_update = now

            except Exception as e:
                logging.error(f"Error Analyst Loop: {e}")
