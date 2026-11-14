import subprocess
import logging
import os
from utils.config import config

class FirewallManager:
    @staticmethod
    def _run_iptables(args, check=True):
        cmd = ["iptables"] if os.geteuid() == 0 else ["sudo", "iptables"]
        return subprocess.run(cmd + args, check=check, capture_output=True, text=True)

    @staticmethod
    def block_ip(ip: str):
        if config.DRY_RUN:
            logging.info(f"🛡️ [DRY-RUN] Simulação de bloqueio para: {ip}")
            return True
        try:
            # -I insere no topo da cadeia para prioridade máxima
            FirewallManager._run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            FirewallManager._run_iptables(["-I", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            logging.info(f"💀 [SHIELD] IP bloqueado com sucesso: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao bloquear {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip: str):
        try:
            FirewallManager._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            FirewallManager._run_iptables(["-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=False)
            logging.info(f"🔓 [SHIELD] IP liberado: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao desbloquear {ip}: {e}")
            return False

    @staticmethod
    def flush_all():
        """Limpeza total para emergências"""
        try:
            FirewallManager._run_iptables(["-F"], check=True)
            logging.warning("🚨 [FIREWALL] Todas as regras foram purgadas.")
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha no flush: {e}")
