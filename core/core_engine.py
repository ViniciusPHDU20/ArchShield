import logging
import socket
import ipaddress
import re
import subprocess
from scapy.all import sniff, IP, TCP, UDP
from multiprocessing import Process, Queue, Manager
from core.intelligence import IntelligenceCore
from core.firewall import FirewallManager
from utils.config import config
import time

class CoreEngine:
    def __init__(self, stats_dict):
        self.packet_queue = Queue(maxsize=10000)
        self.stats = stats_dict
        self.intelligence = IntelligenceCore()
        self.firewall = FirewallManager()
        
        # O Motor AppShield: IPs que pertencem a apps intocáveis
        self.dynamic_safe_ips = set()
        self.vital_apps = ["VESKTOP", "DISCORD", "WEBCORD"]
        
        self.infra_networks = [
            "104.16.0.0/12", "172.64.0.0/13", "198.41.128.0/17", # Cloudflare
            "162.158.0.0/15", "162.159.0.0/16",                 # Discord/Cloudflare
            "142.250.0.0/15", "172.217.0.0/16", "34.0.0.0/8",   # Google
            "140.82.112.0/20", "192.30.252.0/22",               # GitHub
            "151.101.0.0/16", "199.232.0.0/16",                 # Fastly
            "2.16.0.0/13", "23.0.0.0/11",                       # Akamai
            "155.133.0.0/16"                                    # Steam (Valve)
        ]

    def start(self):
        logging.info(f"🛰️ CORE: Motor AppShield v2.0.8 Ativo em {config.INTERFACE}...")
        p_sniffer = Process(target=self._sniffer_loop, daemon=True)
        p_analyst = Process(target=self._analyst_loop, daemon=True)
        p_sniffer.start()
        p_analyst.start()

    def _sniffer_loop(self):
        def _on_packet(pkt):
            if IP in pkt:
                try:
                    port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0
                    self.packet_queue.put({
                        "src": pkt[IP].src, "dst": pkt[IP].dst,
                        "len": len(pkt), "ttl": pkt[IP].ttl,
                        "proto": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER",
                        "port": port
                    }, block=False)
                except: pass
        sniff(iface=config.INTERFACE, filter="ip", prn=_on_packet, store=False)

    def _is_safe(self, ip, port):
        # 1. Blindagem Dinâmica por Nome de Aplicativo (O mais forte)
        if ip in self.dynamic_safe_ips: return True

        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback: return True
            if str(addr) in config.GUARDIAN_IPS: return True
            if port in config.ALLOWED_PORTS: return True
            
            for net in self.infra_networks + config.GUARDIAN_NETWORKS:
                if addr in ipaddress.ip_network(net): return True
        except: pass
        return False

    def _analyst_loop(self):
        features_buffer = []
        packets_history = []
        times_history = []
        last_graph_update = 0
        local_packet_count = 0
        local_active_conns = {}
        blocked_list = set()
        
        while True:
            try:
                pkt_data = self.packet_queue.get()
                local_packet_count += 1
                
                if local_packet_count % 50 == 0:
                    self.stats['total_packets'] = local_packet_count
                
                feat = [pkt_data['len'], 1 if pkt_data['proto']=="TCP" else 0, 1 if pkt_data['proto']=="UDP" else 0, pkt_data['ttl'], pkt_data['port']]
                
                if not self._is_safe(pkt_data['src'], pkt_data['port']):
                    features_buffer.append(feat)
                    if len(features_buffer) >= config.MIN_TRAIN_SIZE and len(features_buffer) % 200 == 0:
                        self.intelligence.train(features_buffer[-1000:])
                        self.stats['ia_status'] = "ATIVA & PROTEGENDO"

                    if self.intelligence.is_fitted:
                        score = self.intelligence.predict(feat)
                        if score < -0.88:
                            if pkt_data['src'] not in blocked_list:
                                if self.firewall.block_ip(pkt_data['src']):
                                    self.stats['anomalies'] = self.stats.get('anomalies', 0) + 1
                                    blocked_list.add(pkt_data['src'])
                                    self.stats['blocked_ips'] = list(blocked_list)
                                    logging.warning(f"💀 ANOMALIA BLOQUEADA: {pkt_data['src']} (Score: {score:.2f})")

                local_active_conns[pkt_data['src']] = time.time()

                now = time.time()
                if now - last_graph_update > 2.5:
                    packets_history.append(local_packet_count)
                    times_history.append(time.strftime("%H:%M:%S", time.localtime(now)))
                    if len(packets_history) > 40:
                        packets_history.pop(0); times_history.pop(0)
                    
                    self.stats['packets_history'] = list(packets_history)
                    self.stats['times_history'] = list(times_history)
                    
                    local_active_conns = {k: v for k, v in local_active_conns.items() if now - v < 20}
                    self.stats['active_conns'] = dict(local_active_conns)
                    
                    # --- MOTOR APP SHIELD (Atualiza a lista de IPs Vitais) ---
                    try:
                        result = subprocess.run(["sudo", "ss", "-tunp"], capture_output=True, text=True)
                        new_safe_ips = set()
                        for line in result.stdout.splitlines()[1:]:
                            parts = re.split(r"\s+", line)
                            if len(parts) >= 6:
                                remote = parts[5]
                                proc_raw = parts[6] if len(parts) > 6 else "-"
                                app_match = re.search(r'\"([^\"]+)\"', proc_raw)
                                if app_match:
                                    app_name = app_match.group(1).upper()
                                    if app_name in self.vital_apps and ":" in remote:
                                        ip, _ = remote.rsplit(":", 1)
                                        new_safe_ips.add(ip)
                        self.dynamic_safe_ips = new_safe_ips
                    except: pass
                    
                    last_graph_update = now
            except Exception as e:
                logging.error(f"Error Analyst Loop: {e}")
