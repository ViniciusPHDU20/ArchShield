#!/bin/bash



set -e

LOG_FILE="/var/log/archshield_update.log"
echo "=== Iniciando update ArchShield com novas funcionalidades - $(date) ===" | sudo tee "$LOG_FILE" > /dev/null

# Função para backup
backup_file() {
    if [ -f "$1" ]; then
        cp "$1" "$1.bak.$(date +%Y%m%d_%H%M%S)"
        echo "Backup de $1 criado" | sudo tee -a "$LOG_FILE" > /dev/null
    fi
}

# Verifica se é root
if [ "$EUID" -ne 0 ]; then
    echo "Rode como root: sudo $0" | sudo tee -a "$LOG_FILE" > /dev/null
    exit 1
fi

# Para serviço
systemctl stop archshield 2>/dev/null || echo "Serviço já parado" | sudo tee -a "$LOG_FILE" > /dev/null

# Backup dos arquivos
backup_file "/usr/share/archshield/templates/index.html"
backup_file "/usr/bin/archshield"

# Novo index.html com funcionalidades aprimoradas
cat << 'EOL' | sudo tee /usr/share/archshield/templates/index.html > /dev/null
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>ArchShield Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .ip-card {
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .ip-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .blocked-ip {
            border-left: 4px solid #ef4444;
            background-color: #fef2f2;
        }
        .active-ip {
            border-left: 4px solid #10b981;
            background-color: #f0fdf4;
        }
        .loading {
            opacity: 0.6;
            pointer-events: none;
        }
        .tooltip {
            position: relative;
            display: inline-block;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 200px;
            background-color: #333;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto p-4">
        <header class="mb-8">
            <h1 class="text-3xl font-bold text-gray-800 mb-2">ArchShield - Monitor de Tráfego</h1>
            <p class="text-gray-600">Dashboard de monitoramento em tempo real com controle avançado de IPs</p>
        </header>

        <!-- Gráfico de Tráfego -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4">Tráfego de Rede</h2>
            <canvas id="trafficChart" width="800" height="400"></canvas>
        </div>

        <!-- Grid de IPs -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- IPs Bloqueados -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold mb-4 text-red-600">IPs Bloqueados</h2>
                <div id="blockedIPsContainer" class="space-y-3 max-h-96 overflow-y-auto">
                    <p class="text-gray-500">Carregando...</p>
                </div>
            </div>

            <!-- IPs Ativos -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold mb-4 text-green-600">IPs Ativos</h2>
                <div id="activeIPsContainer" class="space-y-3 max-h-96 overflow-y-auto">
                    <p class="text-gray-500">Carregando...</p>
                </div>
            </div>
        </div>

        <!-- Estatísticas -->
        <div class="bg-white rounded-lg shadow-md p-6 mt-6">
            <h2 class="text-xl font-semibold mb-4">Estatísticas</h2>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="text-center">
                    <div class="text-2xl font-bold text-blue-600" id="totalPackets">0</div>
                    <div class="text-sm text-gray-600">Pacotes Capturados</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-red-600" id="blockedCount">0</div>
                    <div class="text-sm text-gray-600">IPs Bloqueados</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-green-600" id="activeCount">0</div>
                    <div class="text-sm text-gray-600">IPs Ativos</div>
                </div>
                <div class="text-center">
                    <div class="text-2xl font-bold text-purple-600" id="anomaliesCount">0</div>
                    <div class="text-sm text-gray-600">Anomalias Detectadas</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let chart;
        let ipInfoCache = {};

        // Função para buscar informações do IP
        async function getIPInfo(ip) {
            if (ipInfoCache[ip]) {
                return ipInfoCache[ip];
            }

            try {
                const response = await fetch(`/ip_info/${ip}`);
                if (response.ok) {
                    const info = await response.json();
                    ipInfoCache[ip] = info;
                    return info;
                }
            } catch (error) {
                console.error('Erro ao buscar info do IP:', error);
            }

            return {
                country: 'Desconhecido',
                city: 'Desconhecido',
                isp: 'Desconhecido',
                org: 'Desconhecido',
                threat: false
            };
        }

        // Função para criar card de IP
        async function createIPCard(ip, isBlocked = false) {
            const info = await getIPInfo(ip);
            const cardClass = isBlocked ? 'blocked-ip' : 'active-ip';
            const actionText = isBlocked ? 'Clique direito para desbloquear' : 'Clique direito para bloquear';
            const flagEmoji = info.country_code ? `https://flagcdn.com/16x12/${info.country_code.toLowerCase()}.png` : '';

            return `
                <div class="ip-card ${cardClass} p-4 rounded-lg border" data-ip="${ip}">
                    <div class="flex justify-between items-start">
                        <div class="flex-1">
                            <div class="flex items-center gap-2 mb-2">
                                <span class="font-mono font-bold text-lg">${ip}</span>
                                ${flagEmoji ? `<img src="${flagEmoji}" alt="${info.country}" class="w-4 h-3">` : ''}
                                ${info.threat ? '<span class="bg-red-500 text-white text-xs px-2 py-1 rounded">AMEAÇA</span>' : ''}
                            </div>
                            <div class="text-sm text-gray-600 space-y-1">
                                <div><strong>País:</strong> ${info.country || 'Desconhecido'}</div>
                                <div><strong>Cidade:</strong> ${info.city || 'Desconhecido'}</div>
                                <div><strong>ISP:</strong> ${info.isp || 'Desconhecido'}</div>
                                <div><strong>Organização:</strong> ${info.org || 'Desconhecido'}</div>
                            </div>
                        </div>
                        <div class="tooltip">
                            <span class="text-xs text-gray-500 cursor-help">ℹ️</span>
                            <span class="tooltiptext">${actionText}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        // Função para atualizar dashboard
        async function updateDashboard() {
            try {
                const response = await fetch('/status');
                const data = await response.json();

                // Atualiza gráfico
                const ctx = document.getElementById('trafficChart').getContext('2d');
                if (chart) {
                    chart.data.labels = data.times;
                    chart.data.datasets[0].data = data.packets;
                    chart.update('none');
                } else {
                    chart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: data.times,
                            datasets: [{
                                label: 'Pacotes Capturados',
                                data: data.packets,
                                borderColor: '#3b82f6',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                fill: true,
                                tension: 0.4
                            }]
                        },
                        options: {
                            responsive: true,
                            scales: {
                                x: { title: { display: true, text: 'Tempo (s)' } },
                                y: { title: { display: true, text: 'Pacotes' } }
                            },
                            animation: {
                                duration: 0
                            }
                        }
                    });
                }

                // Atualiza IPs bloqueados
                const blockedContainer = document.getElementById('blockedIPsContainer');
                if (data.blocked_ips.length === 0) {
                    blockedContainer.innerHTML = '<p class="text-gray-500">Nenhum IP bloqueado</p>';
                } else {
                    const blockedCards = await Promise.all(
                        data.blocked_ips.map(ip => createIPCard(ip, true))
                    );
                    blockedContainer.innerHTML = blockedCards.join('');
                }

                // Atualiza IPs ativos
                const activeContainer = document.getElementById('activeIPsContainer');
                if (data.active_ips.length === 0) {
                    activeContainer.innerHTML = '<p class="text-gray-500">Nenhum IP ativo</p>';
                } else {
                    const activeCards = await Promise.all(
                        data.active_ips.map(ip => createIPCard(ip, false))
                    );
                    activeContainer.innerHTML = activeCards.join('');
                }

                // Atualiza estatísticas
                document.getElementById('totalPackets').textContent = data.total_packets || 0;
                document.getElementById('blockedCount').textContent = data.blocked_ips.length;
                document.getElementById('activeCount').textContent = data.active_ips.length;
                document.getElementById('anomaliesCount').textContent = data.anomalies_count || 0;

                // Adiciona event listeners para clique direito
                document.querySelectorAll('.ip-card').forEach(card => {
                    card.addEventListener('contextmenu', async (e) => {
                        e.preventDefault();
                        const ip = card.dataset.ip;
                        const isBlocked = card.classList.contains('blocked-ip');
                        const action = isBlocked ? 'desbloquear' : 'bloquear';
                        
                        if (confirm(`Deseja ${action} o IP ${ip}?`)) {
                            card.classList.add('loading');
                            
                            try {
                                const endpoint = isBlocked ? '/unblock_ip' : '/block_ip';
                                const response = await fetch(endpoint, {
                                    method: 'POST',
                                    headers: {'Content-Type': 'application/json'},
                                    body: JSON.stringify({ip: ip})
                                });
                                
                                if (response.ok) {
                                    alert(`IP ${ip} ${action === 'bloquear' ? 'bloqueado' : 'desbloqueado'} com sucesso!`);
                                } else {
                                    alert(`Erro ao ${action} IP ${ip}`);
                                }
                            } catch (error) {
                                alert(`Erro: ${error.message}`);
                            } finally {
                                card.classList.remove('loading');
                            }
                        }
                    });
                });

            } catch (error) {
                console.error('Erro atualizando dashboard:', error);
            }
        }

        // Inicia atualizações
        setInterval(updateDashboard, 5000);
        updateDashboard();
    </script>
</body>
</html>
EOL

echo "index.html atualizado com novas funcionalidades" | sudo tee -a "$LOG_FILE" > /dev/null

# Novo archshield.py com funcionalidades aprimoradas
cat << 'EOL' | sudo tee /usr/bin/archshield > /dev/null
#!/usr/bin/env python3
import logging
import configparser
import os
import requests
import json
from scapy.all import sniff, IP, TCP, UDP
import time
import datetime
import subprocess
import re
from sklearn.ensemble import IsolationForest
import numpy as np
from flask import Flask, jsonify, render_template, request
from threading import Thread, Lock
import sqlite3

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.is_sniffing = False
        self.packet_data = []
        self.interface = self.get_default_interface()
        self.filter_text = "tcp or udp"
        self.traffic_data = {"time": [], "packets": []}
        self.blocked_ips = set()
        self.active_connections = {}
        self.ip_info_cache = {}
        self.anomalies_count = 0
        self.data_lock = Lock()
        
        try:
            self.config = self.load_config()
        except Exception as e:
            logging.error(f"Falha ao carregar config: {e}")
            raise
            
        self.setup_logging()
        self.setup_database()
        self.anomaly_model = IsolationForest(
            contamination=float(self.config["DEFAULT"]["anomaly_threshold"]), 
            random_state=42
        )
        self.packet_features = []
        self.allowed_services = self.load_allowed_services()
        self.allowed_ports = [int(p) for p in self.config["DEFAULT"]["allowed_ports"].split(",")]
        
        logging.info("Inicializando ArchShield com identificação de IPs...")
        self.check_rkhunter()
        Thread(target=self.start_flask, daemon=True).start()
        Thread(target=self.monitor_active_connections, daemon=True).start()
        self.start_sniffing()

    def setup_database(self):
        """Configura banco de dados SQLite para cache de informações de IP"""
        try:
            self.db_path = "/var/log/archshield_ip_cache.db"
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_info (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    org TEXT,
                    country_code TEXT,
                    threat INTEGER,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()
            logging.info("Banco de dados de cache de IPs configurado")
        except Exception as e:
            logging.error(f"Erro configurando banco de dados: {e}")

    def get_ip_info_from_db(self, ip):
        """Busca informações do IP no cache do banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # FIX: SQL Injection prevent (use parameterized query)
            cursor.execute(
                "SELECT country, city, isp, org, country_code, threat FROM ip_info WHERE ip = ?", 
                (ip,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'country': result[0],
                    'city': result[1],
                    'isp': result[2],
                    'org': result[3],
                    'country_code': result[4],
                    'threat': bool(result[5])
                }
        except Exception as e:
            logging.error(f"Erro buscando IP no cache: {e}")
        return None

    def save_ip_info_to_db(self, ip, info):
        """Salva informações do IP no cache do banco de dados"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            # FIX: SQL Injection prevent (use parameterized query)
            cursor.execute('''
                INSERT OR REPLACE INTO ip_info 
                (ip, country, city, isp, org, country_code, threat, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                ip, 
                info.get('country', ''),
                info.get('city', ''),
                info.get('isp', ''),
                info.get('org', ''),
                info.get('country_code', ''),
                int(info.get('threat', False))
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Erro salvando IP no cache: {e}")

    def get_ip_info(self, ip):
        """Busca informações detalhadas sobre um IP"""
        # Verifica se é IP privado
        if ip.startswith(('192.168.', '10.', '172.')) or ip == '127.0.0.1':
            return {
                'country': 'Local/Privado',
                'city': 'Rede Local',
                'isp': 'Rede Privada',
                'org': 'Rede Local',
                'country_code': '',
                'threat': False
            }

        # Verifica cache do banco de dados
        cached_info = self.get_ip_info_from_db(ip)
        if cached_info:
            return cached_info

        # Busca informações online
        try:
            # Usando ip-api.com (gratuito, sem necessidade de API key)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info = {
                        'country': data.get('country', 'Desconhecido'),
                        'city': data.get('city', 'Desconhecido'),
                        'isp': data.get('isp', 'Desconhecido'),
                        'org': data.get('org', 'Desconhecido'),
                        'country_code': data.get('countryCode', '').lower(),
                        'threat': self.check_threat_intelligence(ip)
                    }
                    self.save_ip_info_to_db(ip, info)
                    return info
        except Exception as e:
            logging.error(f"Erro buscando informações do IP {ip}: {e}")

        # Fallback para informações básicas
        default_info = {
            'country': 'Desconhecido',
            'city': 'Desconhecido',
            'isp': 'Desconhecido',
            'org': 'Desconhecido',
            'country_code': '',
            'threat': False
        }
        self.save_ip_info_to_db(ip, default_info)
        return default_info

    def check_threat_intelligence(self, ip):
        """Verifica se o IP está em listas de ameaças conhecidas"""
        try:
            # Lista simples de verificação de ameaças
            # Pode ser expandida com APIs de threat intelligence
            threat_indicators = [
                'tor-exit', 'proxy', 'vpn', 'malware', 'botnet'
            ]
            
            # Aqui você pode integrar com APIs de threat intelligence
            # Por enquanto, retorna False como padrão
            return False
        except:
            return False

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = "/etc/archshield.conf"
        if not os.path.exists(config_file):
            config["DEFAULT"] = {
                "interface": "eth0",
                "log_file": "/var/log/archshield.log",
                "rkhunter_log": "/var/log/rkhunter.log",
                "block_duration": "3600",
                "anomaly_threshold": "0.1",
                "allowed_ports": "80,443,22,53",
                "flask_port": "8080"
            }
            with open(config_file, "w") as f:
                config.write(f)
        config.read(config_file)
        return config

    def setup_logging(self):
        logging.basicConfig(
            filename=self.config["DEFAULT"]["log_file"],
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
            force=True
        )

    def get_default_interface(self):
        try:
            result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True)
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if match:
                interface = match.group(1)
                logging.info(f"Interface detectada: {interface}")
                return interface
            return "eth0"
        except:
            return "eth0"

    def check_rkhunter(self):
        log_file = self.config["DEFAULT"]["rkhunter_log"]
        try:
            with open(log_file, "r") as f:
                if "Hidden" in f.read():
                    logging.warning("Rootkit detectado!")
        except:
            pass

    def load_allowed_services(self):
        allowed_file = "/etc/archshield/allowed_services.txt"
        try:
            with open(allowed_file, "r") as f:
                return set(line.strip() for line in f if line.strip() and not line.startswith("#"))
        except:
            return set()

    def monitor_active_connections(self):
        while True:
            try:
                result = subprocess.run(["ss", "-tunp"], capture_output=True, text=True)
                lines = result.stdout.splitlines()[1:]
                with self.data_lock:
                    self.active_connections.clear()
                    for line in lines:
                        parts = re.split(r"\s+", line)
                        if len(parts) >= 5:
                            remote = parts[5]
                            if ":" in remote:
                                ip, _ = remote.rsplit(":", 1)
                                if not ip.startswith(('127.', '::1')):
                                    self.active_connections[ip] = time.time()
                time.sleep(5)
            except Exception as e:
                logging.error(f"Erro monitorando conexões: {e}")

    def start_flask(self):
        app = Flask(__name__, template_folder="/usr/share/archshield/templates")

        @app.route("/status")
        def status():
            with self.data_lock:
                times = [t - self.traffic_data["time"][0] if self.traffic_data["time"] else 0 
                        for t in self.traffic_data["time"]]
                active_ips = list(self.active_connections.keys())
                return jsonify({
                    "times": times,
                    "packets": self.traffic_data["packets"],
                    "blocked_ips": list(self.blocked_ips),
                    "active_ips": active_ips,
                    "total_packets": len(self.packet_data),
                    "anomalies_count": self.anomalies_count
                })

        @app.route("/ip_info/<ip>")
        def ip_info(ip):
            info = self.get_ip_info(ip)
            return jsonify(info)

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/block_ip", methods=["POST"])
        def block_ip_route():
            ip = request.json.get("ip")
            if ip:
                self.block_ip(ip, None)
                logging.info(f"Bloqueio manual: {ip}")
                return jsonify({"success": True})
            return jsonify({"success": False}), 400

        @app.route("/unblock_ip", methods=["POST"])
        def unblock_ip_route():
            ip = request.json.get("ip")
            if ip and ip in self.blocked_ips:
                self.unblock_ip(ip)
                logging.info(f"Desbloqueio manual: {ip}")
                return jsonify({"success": True})
            return jsonify({"success": False}), 400

        port = int(self.config["DEFAULT"]["flask_port"])
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    def extract_features(self, packet):
        features = [len(packet), 1 if TCP in packet else 0, 1 if UDP in packet else 0]
        if IP in packet:
            features.append(packet[IP].ttl)
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
            features.append(port)
        else:
            features += [0, 0]
        return features

    def process_packet(self, packet):
        with self.data_lock:
            if not self.is_sniffing:
                return
            try:
                src = packet[IP].src if IP in packet else "N/A"
                dst = packet[IP].dst if IP in packet else "N/A"
                proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "N/A"
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0

                features = self.extract_features(packet)
                self.packet_features.append(features)
                
                if len(self.packet_features) >= 10 and len(self.packet_features) % 10 == 0:
                    X = np.array(self.packet_features[-100:])
                    self.anomaly_model.fit(X)

                if len(self.packet_features) >= 10:
                    score = self.anomaly_model.score_samples([features])[0]
                    if score < -0.5:
                        self.anomalies_count += 1
                        self.block_ip(src, port)
                        logging.warning(f"Anomalia detectada: {src} -> {dst}:{port}")

                self.packet_data.append([
                    datetime.datetime.now().strftime("%H:%M:%S"), 
                    src, dst, proto, port, "Processado"
                ])
                self.traffic_data["time"].append(time.time())
                self.traffic_data["packets"].append(len(self.packet_data))
                
                if len(self.traffic_data["packets"]) > 100:
                    self.traffic_data["time"].pop(0)
                    self.traffic_data["packets"].pop(0)
                    
            except Exception as e:
                logging.error(f"Erro processando pacote: {e}")

    def block_ip(self, ip, port):
        if ip in self.blocked_ips or ip == "N/A" or ip.startswith(("192.168.", "127.", "10.")):
            return
        if port and port in self.allowed_ports or f"{ip}:{port}" in self.allowed_services:
            return
        try:
            duration = int(self.config["DEFAULT"]["block_duration"])
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            self.blocked_ips.add(ip)
            logging.info(f"IP bloqueado: {ip} por {duration}s")
            Thread(target=self.unblock_ip_later, args=(ip, duration), daemon=True).start()
        except Exception as e:
            logging.error(f"Falha bloqueando IP {ip}: {e}")

    def unblock_ip(self, ip):
        """Desbloqueia um IP manualmente"""
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            logging.info(f"IP desbloqueado manualmente: {ip}")
        except Exception as e:
            logging.error(f"Erro desbloqueando IP {ip}: {e}")

    def unblock_ip_later(self, ip, duration):
        time.sleep(duration)
        self.unblock_ip(ip)

    def start_sniffing(self):
        self.is_sniffing = True
        logging.info(f"Sniffando em {self.interface} com filtro '{self.filter_text}'")
        sniff(iface=self.interface, filter=self.filter_text, prn=self.process_packet, 
              store=False, stop_filter=lambda x: not self.is_sniffing)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    app = NetworkTrafficAnalyzer()
EOL

chmod 755 /usr/bin/archshield
echo "archshield.py atualizado com identificação de IPs" | sudo tee -a "$LOG_FILE" > /dev/null

# Reinicia serviço
systemctl daemon-reload
systemctl start archshield || {
    echo "Erro iniciando serviço" | sudo tee -a "$LOG_FILE" > /dev/null
    exit 1
}

echo "=== Update concluído com sucesso - $(date) ===" | sudo tee -a "$LOG_FILE" > /dev/null
echo "Dashboard atualizado com:"
echo "- Funcionalidade de desbloqueio de IPs"
echo "- Identificação detalhada de IPs (país, cidade, ISP, organização)"
echo "- Interface aprimorada com cards informativos"
echo "- Cache de informações de IP em banco SQLite"
echo "- Estatísticas em tempo real"
echo ""
echo "Acesse: http://localhost:8080"

