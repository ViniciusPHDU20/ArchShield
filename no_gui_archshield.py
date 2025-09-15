#!/usr/bin/env python3
import logging
import configparser
import os
from scapy.all import sniff, IP, TCP, UDP
import time
import datetime
import subprocess
import re
from sklearn.ensemble import IsolationForest
import numpy as np
from flask import Flask, jsonify, render_template
from threading import Thread

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.is_sniffing = False
        self.packet_data = []
        self.interface = self.get_default_interface()
        self.filter_text = ""
        self.traffic_data = {"time": [], "packets": []}
        self.blocked_ips = set()
        try:
            self.config = self.load_config()
        except Exception as e:
            logging.error(f"Falha ao carregar config: {e}")
            raise
        self.setup_logging()
        self.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
        self.packet_features = []
        self.allowed_services = self.load_allowed_services()
        logging.info("Inicializando ArchShield (sem GUI)...")
        self.check_rkhunter()
        Thread(target=self.start_flask, daemon=True).start()
        self.start_sniffing()

    def load_config(self):
        config = configparser.ConfigParser()
        config_file = "/etc/archshield.conf"
        try:
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
                logging.info(f"Config criado: {config_file}")
            else:
                config.read(config_file)
                logging.info(f"Config lido: {config_file}")
            return config
        except Exception as e:
            logging.error(f"Erro ao carregar config: {e}")
            raise

    def setup_logging(self):
        try:
            logging.basicConfig(
                filename=self.config["DEFAULT"]["log_file"],
                level=logging.DEBUG,
                format="%(asctime)s - %(levelname)s - %(message)s",
                force=True
            )
            logging.info("Logging configurado com sucesso")
        except Exception as e:
            print(f"Erro ao configurar logging: {e}")
            raise

    def get_default_interface(self):
        try:
            result = subprocess.run(["ip", "link"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "state UP" in line and "lo:" not in line:
                    interface = line.split(":")[1].strip()
                    logging.info(f"Interface padrão detectada: {interface}")
                    return interface
            logging.warning("Nenhuma interface UP encontrada, usando config padrão")
            return self.config["DEFAULT"]["interface"]
        except Exception as e:
            logging.error(f"Erro ao detectar interface: {e}")
            return self.config["DEFAULT"]["interface"]

    def check_rkhunter(self):
        log_file = self.config["DEFAULT"]["rkhunter_log"]
        try:
            with open(log_file, "r") as f:
                log_content = f.read()
                if "Hidden file found" in log_content or "Hidden directory found" in log_content:
                    logging.warning("Rootkit detectado no log do rkhunter")
                else:
                    logging.info("Nenhum rootkit detectado no log do rkhunter")
        except Exception as e:
            logging.error(f"Falha ao ler log do rkhunter: {e}")

    def load_allowed_services(self):
        allowed_file = "/etc/archshield/allowed_services.txt"
        allowed_services = set()
        try:
            if os.path.exists(allowed_file):
                with open(allowed_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            allowed_services.add(line)
                logging.info(f"Serviços permitidos carregados de {allowed_file}")
            else:
                logging.warning(f"Arquivo de serviços permitidos não encontrado: {allowed_file}")
            return allowed_services
        except Exception as e:
            logging.error(f"Erro ao carregar serviços permitidos: {e}")
            return set()

    def start_flask(self):
        try:
            app = Flask(__name__, template_folder="/usr/share/archshield/templates")
            logging.info("Inicializando servidor Flask...")

            @app.route("/status")
            def status():
                try:
                    times = [t - self.traffic_data["time"][0] if self.traffic_data["time"] else 0 for t in self.traffic_data["time"]]
                    logging.debug("Enviando dados para /status")
                    return jsonify({
                        "times": times,
                        "packets": self.traffic_data["packets"],
                        "blocked_ips": list(self.blocked_ips)
                    })
                except Exception as e:
                    logging.error(f"Erro na rota /status: {e}")
                    return jsonify({"error": str(e)}), 500

            @app.route("/")
            def index():
                try:
                    logging.debug("Servindo index.html")
                    return render_template("index.html")
                except Exception as e:
                    logging.error(f"Erro ao servir index.html: {e}")
                    return str(e), 500

            port = int(self.config["DEFAULT"]["flask_port"])
            logging.info(f"Tentando iniciar Flask na porta {port}")
            app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
            logging.info(f"Servidor Flask iniciado na porta {port}")
        except Exception as e:
            logging.error(f"Falha ao iniciar Flask: {e}")

    def extract_features(self, packet):
        try:
            features = []
            if IP in packet:
                features.append(len(packet))
                features.append(1 if TCP in packet else 0)
                features.append(1 if UDP in packet else 0)
                features.append(packet[IP].ttl)
                port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                features.append(port)
            else:
                features.extend([0, 0, 0, 0, 0])
            logging.debug(f"Características extraídas: {features}")
            return features
        except Exception as e:
            logging.error(f"Erro ao extrair características: {e}")
            return [0, 0, 0, 0, 0]

    def process_packet(self, packet):
        if not self.is_sniffing:
            return
        try:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            src = packet[IP].src if IP in packet else "N/A"
            dst = packet[IP].dst if IP in packet else "N/A"
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "N/A"
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"

            features = self.extract_features(packet)
            self.packet_features.append(features)
            anomaly_score = self.detect_anomaly(features)
            status = "Anomalia" if anomaly_score < -0.5 else "Normal"

            if status == "Anomalia":
                self.block_ip(src, port)
                logging.warning(f"Anomalia detectada: {src} -> {dst}, Porta: {port}")

            self.packet_data.append([timestamp, src, dst, proto, port, status])
            self.traffic_data["time"].append(time.time())
            self.traffic_data["packets"].append(len(self.packet_data))
            logging.debug(f"Pacote processado: {src} -> {dst}, Porta: {port}, Status: {status}")
        except Exception as e:
            logging.error(f"Erro ao processar pacote: {e}")

    def detect_anomaly(self, features):
        try:
            if len(self.packet_features) < 10:
                logging.debug("Menos de 10 pacotes, sem detecção de anomalia")
                return 0
            X = np.array(self.packet_features)
            self.anomaly_model.fit(X)
            score = self.anomaly_model.score_samples([features])[0]
            logging.debug(f"Pontuação de anomalia: {score}")
            return score
        except Exception as e:
            logging.error(f"Erro na detecção de anomalia: {e}")
            return 0

    def block_ip(self, ip, port):
        if ip not in self.blocked_ips and ip != "N/A" and not ip.startswith(("192.168.", "127.", "10.")):
            if f"{ip}:{port}" in self.allowed_services or ip in self.allowed_services:
                logging.info(f"IP/Porta {ip}:{port} na lista de permissões. Não bloqueando.")
                return
            try:
                duration = int(self.config["DEFAULT"]["block_duration"])
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                self.blocked_ips.add(ip)
                logging.info(f"IP bloqueado: {ip} por {duration}s")
                Thread(target=self.unblock_ip_later, args=(ip, duration), daemon=True).start()
            except Exception as e:
                logging.error(f"Falha ao bloquear IP {ip}: {e}")

    def unblock_ip_later(self, ip, duration):
        try:
            time.sleep(duration)
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            self.blocked_ips.remove(ip)
            logging.info(f"IP desbloqueado: {ip}")
        except Exception as e:
            logging.error(f"Falha ao desbloquear IP {ip}: {e}")

    def start_sniffing(self):
        try:
            self.is_sniffing = True
            self.packet_data = []
            self.traffic_data = {"time": [], "packets": []}
            self.packet_features = []
            logging.info(f"Iniciando captura na interface {self.interface} com filtro \'{self.filter_text}\'")
            sniff(iface=self.interface, filter=self.filter_text, prn=self.process_packet, store=False, stop_filter=lambda x: not self.is_sniffing)
        except Exception as e:
            logging.error(f"Falha na captura: {e}")

if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
        logging.info("Iniciando aplicação ArchShield (sem GUI)...")
        app = NetworkTrafficAnalyzer()
    except Exception as e:
        logging.error(f"Erro fatal na inicialização: {e}")
        print(f"Erro fatal: {e}")
EOL



