"""
ArchShield PRO - Native Process & Socket Attribution Engine
Zero external dependencies - tracks active sockets and links them directly to PIDs and binaries.
"""

import subprocess
import re
import os
import logging
from typing import List, Dict, Any

class ProcessTracker:
    @staticmethod
    def get_active_connections() -> List[Dict[str, Any]]:
        """
        Coleta todas as conexões ativas do host mapeadas para os respectivos binários e PIDs.
        """
        connections = []
        try:
            cmd = ["ss", "-tunp", "-H"] if os.geteuid() == 0 else ["sudo", "ss", "-tunp", "-H"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            if res.returncode != 0 and os.geteuid() != 0:
                # Fallback sem sudo se sudo falhar
                res = subprocess.run(["ss", "-tunp", "-H"], capture_output=True, text=True, timeout=2)
            
            lines = res.stdout.strip().splitlines()
            for line in lines:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 5:
                    proto = parts[0].upper()
                    state = parts[1]
                    local = parts[4]
                    remote = parts[5] if len(parts) > 5 else "*:*"
                    proc_raw = parts[6] if len(parts) > 6 else ""

                    # Extrai Processo e PID
                    proc_name = "Sistema / Kernel"
                    pid = None
                    m_proc = re.search(r'\"([^\"]+)\"', proc_raw)
                    if m_proc:
                        proc_name = m_proc.group(1)
                    m_pid = re.search(r'pid=(\d+)', proc_raw)
                    if m_pid:
                        pid = int(m_pid.group(1))

                    # Separa IP e Porta de forma robusta para IPv4 e IPv6
                    local_ip, local_port = ProcessTracker._split_addr_port(local)
                    remote_ip, remote_port = ProcessTracker._split_addr_port(remote)

                    # Filtra apenas conexões relevantes (estabelecidas ou com destino remoto)
                    is_loopback = (local_ip in ("127.0.0.1", "::1", "localhost") and 
                                   remote_ip in ("127.0.0.1", "::1", "localhost", "*", ""))

                    connections.append({
                        "proto": proto,
                        "state": state,
                        "process": proc_name,
                        "pid": pid,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "is_loopback": is_loopback
                    })
        except Exception as e:
            logging.error(f"Erro ao rastrear processos via ss: {e}")

        return connections

    @staticmethod
    def _split_addr_port(addr_str: str) -> (str, str):
        if not addr_str or addr_str in ("*", "*:*"):
            return "*", "*"
        # Trata formato com interface (ex: 192.168.15.4%enp6s0:68)
        clean = addr_str.split("%")[0] if "%" in addr_str else addr_str
        
        # IPv6: [2001:...]:443
        if clean.startswith("["):
            m = re.match(r'\[([^\]]+)\](?::(\d+))?', clean)
            if m:
                return m.group(1), m.group(2) or "*"
        
        # IPv4: 1.2.3.4:443
        if ":" in clean:
            ip, port = clean.rsplit(":", 1)
            return ip, port
        
        return clean, "*"
