"""
ArchShield PRO - Native Firewall & Blackhole Manager
Interacts directly with Linux Netfilter/iptables.
"""

import subprocess
import logging
import os
import re
from typing import List, Set
from utils.config import config

class FirewallManager:
    @staticmethod
    def _run_iptables(args, check=True):
        cmd = ["iptables"] if os.geteuid() == 0 else ["sudo", "iptables"]
        return subprocess.run(cmd + args, check=check, capture_output=True, text=True)

    @staticmethod
    def block_ip(ip: str) -> bool:
        """
        Bloqueia o IP de entrada e saída no topo da cadeia Netfilter (DROP imediato).
        """
        if config.DRY_RUN:
            logging.info(f"🛡️ [DRY-RUN] Simulação de bloqueio para: {ip}")
            return True
        try:
            # Verifica se já está bloqueado para evitar regras duplicadas
            if FirewallManager.is_ip_blocked(ip):
                return True
            FirewallManager._run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            FirewallManager._run_iptables(["-I", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            logging.info(f"💀 [SHIELD] IP bloqueado com sucesso: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao bloquear {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip: str) -> bool:
        """
        Remove todas as regras de bloqueio do IP especificado.
        """
        try:
            # Tenta remover instâncias de INPUT e OUTPUT até não restar nenhuma
            while True:
                res = FirewallManager._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                if res.returncode != 0:
                    break
            while True:
                res = FirewallManager._run_iptables(["-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=False)
                if res.returncode != 0:
                    break
            logging.info(f"🔓 [SHIELD] IP liberado: {ip}")
            return True
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha ao desbloquear {ip}: {e}")
            return False

    @staticmethod
    def is_ip_blocked(ip: str) -> bool:
        """
        Verifica diretamente na tabela do iptables se o IP já está com regra DROP.
        """
        try:
            res = FirewallManager._run_iptables(["-C", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            return res.returncode == 0
        except:
            return False

    @staticmethod
    def get_active_blocks() -> List[str]:
        """
        Lê todas as regras DROP ativas no INPUT do iptables.
        """
        blocked = set()
        try:
            res = FirewallManager._run_iptables(["-n", "-L", "INPUT"], check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "DROP" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 4 and parts[0] == "DROP":
                            src = parts[3]
                            if src not in ("0.0.0.0/0", "anywhere"):
                                blocked.add(src)
        except Exception as e:
            logging.error(f"Erro ao listar bloqueios iptables: {e}")
        return sorted(list(blocked))

    @staticmethod
    def arm_ghost_ports(ports: List[int] = None) -> bool:
        """
        Arma a 'Blackhole Trap': Descarta silenciosamente pacotes TCP SYN destinados a portas
        iscas (sem enviar TCP RST), forçando o scanner a esperar em silêncio enquanto o sniffer
        do ArchShield desmascara a identidade do invasor.
        """
        if ports is None:
            ports = [21, 22, 23, 445, 3389, 8080]
        port_list_str = ",".join(str(p) for p in ports)
        try:
            # Verifica se regra já existe
            check = FirewallManager._run_iptables(
                ["-C", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", port_list_str, "--syn", "-j", "DROP"],
                check=False
            )
            if check.returncode != 0:
                FirewallManager._run_iptables(
                    ["-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", port_list_str, "--syn", "-j", "DROP"],
                    check=False
                )
                logging.info(f"🕸️ [TRAP] Portas fantasma armadas silenciosamente em: {port_list_str}")
            return True
        except Exception as e:
            logging.warning(f"Não foi possível armar ghost ports via iptables: {e}")
            return False

    @staticmethod
    def flush_all():
        """Limpeza total para emergências"""
        try:
            FirewallManager._run_iptables(["-F"], check=True)
            logging.warning("🚨 [FIREWALL] Todas as regras foram purgadas.")
        except Exception as e:
            logging.error(f"❌ [FIREWALL] Falha no flush: {e}")
