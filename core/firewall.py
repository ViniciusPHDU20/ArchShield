import subprocess
import logging
from utils.config import config

class FirewallManager:
    @staticmethod
    def block_ip(ip: str):
        if config.DRY_RUN:
            logging.info(f"🛡️ [DRY-RUN] Simulação de bloqueio para: {ip}")
            return True
        try:
            # -I insere no topo da cadeia para prioridade máxima
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            logging.info(f"💀 [SHIELD] IP bloqueado com sucesso: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao bloquear {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip: str):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=False)
            logging.info(f"🔓 [SHIELD] IP liberado: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao desbloquear {ip}: {e}")
            return False

    @staticmethod
    def flush_all():
        """Limpeza total para emergências"""
        try:
            subprocess.run(["sudo", "iptables", "-F"], check=True)
            logging.warning("🚨 [FIREWALL] Todas as regras foram purgadas.")
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha no flush: {e}")
