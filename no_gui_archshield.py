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
from flask import Flask, jsonify, render_template, request, Response
from threading import Thread, Lock
import sqlite3
import ipaddress
from functools import wraps

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
            contamination=float(self.config["DEFAULT"].get("anomaly_threshold", 0.1)), 
            random_state=42
        )
        self.packet_features = []
        self.allowed_services = self.load_allowed_services()
        self.allowed_ports = [int(p) for p in self.config["DEFAULT"]["allowed_ports"].split(",")]
        
        # FIX: Credenciais de Segurança do Dashboard
        self.dashboard_user = self.config["DEFAULT"].get("dashboard_user", "admin")
        self.dashboard_pass = self.config["DEFAULT"].get("dashboard_pass", "archshield123")
        
        logging.info("Inicializando ArchShield (Secured Core)...")
        self.check_rkhunter()
        Thread(target=self.start_flask, daemon=True).start()
        Thread(target=self.monitor_active_connections, daemon=True).start()
        self.start_sniffing()

    def check_auth(self, username, password):
        """Verifica credenciais de acesso ao dashboard"""
        return username == self.dashboard_user and password == self.dashboard_pass

    def authenticate(self):
        """Retorna uma resposta 401 que aciona o login no navegador"""
        return Response(
            'Acesso negado. Por favor, faça login.', 401,
            {'WWW-Authenticate': 'Basic realm="Login Requerido - ArchShield"'})

    def requires_auth(self, f):
        """Decorator para proteger rotas sensíveis"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not self.check_auth(auth.username, auth.password):
                return self.authenticate()
            return f(*args, **kwargs)
        return decorated

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
        except Exception as e:
            logging.error(f"Erro configurando banco de dados: {e}")

    def is_valid_ip(self, ip):
        """Valida se o formato do IP é correto para evitar injeções"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_ip_info_from_db(self, ip):
        if not self.is_valid_ip(ip): return None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT country, city, isp, org, country_code, threat FROM ip_info WHERE ip = ?", (ip,))
            result = cursor.fetchone()
            conn.close()
            if result:
                return {'country': result[0], 'city': result[1], 'isp': result[2], 'org': result[3], 'country_code': result[4], 'threat': bool(result[5])}
        except Exception as e:
            logging.error(f"Erro cache DB: {e}")
        return None

    def save_ip_info_to_db(self, ip, info):
        if not self.is_valid_ip(ip): return
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO ip_info (ip, country, city, isp, org, country_code, threat, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, info.get('country', 'Desconhecido'), info.get('city', 'Desconhecido'), info.get('isp', 'Desconhecido'), info.get('org', 'Desconhecido'), info.get('country_code', ''), int(info.get('threat', False))))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Erro salvando cache: {e}")

    def get_ip_info(self, ip):
        if not self.is_valid_ip(ip): return None
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return {'country': 'Local', 'city': 'Rede Privada', 'isp': '-', 'org': '-', 'country_code': '', 'threat': False}
        cached = self.get_ip_info_from_db(ip)
        if cached: return cached
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    info = {'country': data.get('country', 'Desconhecido'), 'city': data.get('city', 'Desconhecido'), 'isp': data.get('isp', 'Desconhecido'), 'org': data.get('org', 'Desconhecido'), 'country_code': data.get('countryCode', '').lower(), 'threat': False}
                    self.save_ip_info_to_db(ip, info)
                    return info
        except: pass
        return {'country': 'Erro', 'city': '-', 'isp': '-', 'org': '-', 'country_code': '', 'threat': False}

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = "/etc/archshield.conf"
        if not os.path.exists(config_file):
            os.makedirs("/etc/archshield", exist_ok=True)
            config["DEFAULT"] = {
                "interface": "eth0",
                "log_file": "/var/log/archshield.log",
                "rkhunter_log": "/var/log/rkhunter.log",
                "block_duration": "3600",
                "anomaly_threshold": "0.1",
                "allowed_ports": "80,443,22,53",
                "flask_port": "8080",
                "dashboard_user": "admin",
                "dashboard_pass": "archshield123"
            }
            with open(config_file, "w") as f:
                config.write(f)
        config.read(config_file)
        return config

    def setup_logging(self):
        logging.basicConfig(filename=self.config["DEFAULT"].get("log_file", "/var/log/archshield.log"), level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s", force=True)

    def get_default_interface(self):
        try:
            result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True)
            match = re.search(r"dev\s+(\S+)", result.stdout)
            return match.group(1) if match else "eth0"
        except: return "eth0"

    def check_rkhunter(self):
        log_file = self.config["DEFAULT"].get("rkhunter_log", "/var/log/rkhunter.log")
        try:
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    if "Hidden" in f.read(): logging.warning("Rootkit detectado!")
        except: pass

    def load_allowed_services(self):
        allowed_file = "/etc/archshield/allowed_services.txt"
        try:
            with open(allowed_file, "r") as f:
                return set(line.strip() for line in f if line.strip() and not line.startswith("#"))
        except: return set()

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
                                if self.is_valid_ip(ip): self.active_connections[ip] = time.time()
                time.sleep(5)
            except: pass

    def start_flask(self):
        app = Flask(__name__, template_folder="/usr/share/archshield/templates")

        @app.route("/")
        @self.requires_auth
        def index():
            return render_template("index.html")

        @app.route("/status")
        @self.requires_auth
        def status():
            with self.data_lock:
                times = [t - self.traffic_data["time"][0] if self.traffic_data["time"] else 0 for t in self.traffic_data["time"]]
                return jsonify({
                    "times": times, "packets": self.traffic_data["packets"],
                    "blocked_ips": list(self.blocked_ips), "active_ips": list(self.active_connections.keys()),
                    "total_packets": len(self.packet_data), "anomalies_count": self.anomalies_count
                })

        @app.route("/ip_info/<ip>")
        @self.requires_auth
        def ip_info(ip):
            if not self.is_valid_ip(ip): return jsonify({"error": "IP Inválido"}), 400
            return jsonify(self.get_ip_info(ip))

        @app.route("/block_ip", methods=["POST"])
        @self.requires_auth
        def block_ip_route():
            ip = request.json.get("ip")
            if ip and self.is_valid_ip(ip):
                self.block_ip(ip, None)
                return jsonify({"success": True})
            return jsonify({"success": False}), 400

        @app.route("/unblock_ip", methods=["POST"])
        @self.requires_auth
        def unblock_ip_route():
            ip = request.json.get("ip")
            if ip and self.is_valid_ip(ip) and ip in self.blocked_ips:
                self.unblock_ip(ip)
                return jsonify({"success": True})
            return jsonify({"success": False}), 400

        port = int(self.config["DEFAULT"].get("flask_port", 8080))
        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

    def extract_features(self, packet):
        try:
            features = [len(packet), 1 if TCP in packet else 0, 1 if UDP in packet else 0]
            if IP in packet:
                features.append(packet[IP].ttl)
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                features.append(port)
            else: features += [0, 0]
            return features
        except: return [0, 0, 0, 0, 0]

    def process_packet(self, packet):
        with self.data_lock:
            if not self.is_sniffing: return
            try:
                if IP not in packet: return
                src = packet[IP].src
                features = self.extract_features(packet)
                self.packet_features.append(features)
                if len(self.packet_features) >= 10 and len(self.packet_features) % 100 == 0:
                    self.anomaly_model.fit(np.array(self.packet_features[-500:]))
                if len(self.packet_features) >= 50:
                    score = self.anomaly_model.score_samples([features])[0]
                    if score < -0.5:
                        self.anomalies_count += 1
                        self.block_ip(src, None)
                self.packet_data.append([datetime.datetime.now().strftime("%H:%M:%S"), src, "OK"])
                self.traffic_data["time"].append(time.time())
                self.traffic_data["packets"].append(len(self.packet_data))
                if len(self.traffic_data["packets"]) > 100:
                    self.traffic_data["time"].pop(0)
                    self.traffic_data["packets"].pop(0)
            except: pass

    def block_ip(self, ip, port):
        if not self.is_valid_ip(ip) or ip in self.blocked_ips: return
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback: return
        if port and port in self.allowed_ports: return
        try:
            duration = int(self.config["DEFAULT"].get("block_duration", 3600))
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            self.blocked_ips.add(ip)
            logging.info(f"IP bloqueado: {ip}")
            Thread(target=self.unblock_ip_later, args=(ip, duration), daemon=True).start()
        except: pass

    def unblock_ip(self, ip):
        if not self.is_valid_ip(ip): return
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            if ip in self.blocked_ips: self.blocked_ips.remove(ip)
            logging.info(f"IP desbloqueado: {ip}")
        except: pass

    def unblock_ip_later(self, ip, duration):
        time.sleep(duration)
        self.unblock_ip(ip)

    def start_sniffing(self):
        self.is_sniffing = True
        sniff(iface=self.interface, filter=self.filter_text, prn=self.process_packet, store=False, stop_filter=lambda x: not self.is_sniffing)

if __name__ == "__main__":
    app = NetworkTrafficAnalyzer()
