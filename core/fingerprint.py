"""
ArchShield PRO - Passive TCP & Scanner Fingerprint Engine
Zero external dependencies - pure passive TCP heuristics (TTL, Window, Options layout)
"""

PORT_DESCRIPTIONS = {
    21: "FTP (Exploração de Arquivos)",
    22: "SSH (Varredura de Força-Bruta)",
    23: "Telnet (Scanner IoT / Legado)",
    25: "SMTP (Relay de Spam)",
    53: "DNS (Tentativa de Recursão/Amp)",
    80: "HTTP (Varredura Web)",
    110: "POP3 (Coleta de E-mails)",
    135: "RPC / Endpoint Mapper",
    139: "NetBIOS (Varredura de Rede)",
    443: "HTTPS (Sonda SSL)",
    445: "SMB / Active Directory (WannaCry/EternalBlue Vector)",
    1433: "MS-SQL (Injeção/Força-Bruta)",
    1521: "Oracle DB (Sonda de Banco)",
    3306: "MySQL (Sonda de Credenciais)",
    3389: "RDP (Acesso Remoto Windows)",
    5432: "PostgreSQL (Sonda de Banco)",
    5900: "VNC (Acesso Gráfico Remoto)",
    6379: "Redis (Tentativa de RCE não autenticado)",
    8080: "HTTP Proxy / Web Admin",
    8443: "HTTPS Alt / Console Admin",
    9200: "Elasticsearch (Exfiltração de Dados)",
    27017: "MongoDB (Varredura de Banco Sem Senha)"
}

def describe_port(port: int) -> str:
    return PORT_DESCRIPTIONS.get(port, f"Porta Genérica {port}")

def fingerprint_syn(ip_ttl: int, tcp_win: int, tcp_options: list, payload_len: int = 0) -> dict:
    """
    Classifica a origem de um pacote SYN com base em assinaturas de rede passivas.
    """
    opt_names = []
    mss_val = 0
    wscale_val = 0
    has_sack = False
    has_ts = False
    
    for opt in tcp_options:
        name = opt[0] if isinstance(opt, tuple) else str(opt)
        opt_names.append(name)
        if name == "MSS" and isinstance(opt, tuple) and len(opt) > 1:
            try: mss_val = int(opt[1])
            except: pass
        elif name == "WScale" and isinstance(opt, tuple) and len(opt) > 1:
            try: wscale_val = int(opt[1])
            except: pass
        elif name in ("SAckOK", "SAck"):
            has_sack = True
        elif name == "Timestamp":
            has_ts = True

    # 1. Detecção de Scanners Automatizados
    # Masscan: normalmente sem opções TCP e janela de 1024
    if len(opt_names) == 0 and tcp_win == 1024:
        return {
            "os_family": "Scanner Automatizado",
            "scanner_name": "Masscan",
            "is_scanner": True,
            "confidence": "Alta (95%)",
            "signature": f"WIN:{tcp_win}|OPT:NONE|TTL:{ip_ttl}",
            "summary": "Varredura ultrarrápida Masscan detectada"
        }

    # Nmap SYN Stealth Scan (-sS): opções reduzidas, MSS=1460, janela em múltiplos de 1024 (1024, 2048, 3072, 4096)
    if tcp_win in (1024, 2048, 3072, 4096) and (len(opt_names) <= 2 or opt_names == ["MSS"]):
        return {
            "os_family": "Scanner Automatizado",
            "scanner_name": "Nmap Stealth Scanner",
            "is_scanner": True,
            "confidence": "Alta (90%)",
            "signature": f"WIN:{tcp_win}|OPT:{','.join(opt_names)}|TTL:{ip_ttl}",
            "summary": "Varredura ativa Nmap SYN Scan detectada"
        }

    # ZMap: janela de 65535 ou 54272 sem opções ou com padrões anômalos
    if tcp_win in (65535, 54272) and len(opt_names) == 0:
        return {
            "os_family": "Scanner Automatizado",
            "scanner_name": "ZMap Network Scanner",
            "is_scanner": True,
            "confidence": "Média (85%)",
            "signature": f"WIN:{tcp_win}|OPT:NONE|TTL:{ip_ttl}",
            "summary": "Varredura global ZMap detectada"
        }

    # 2. Heurística de Sistemas Operacionais
    # Windows (TTL base 128 -> recebido entre 65 e 128)
    if 64 < ip_ttl <= 128:
        os_guess = "Windows (10 / 11 / Server)"
        confidence = "Alta (85%)"
        if tcp_win in (8192, 64240, 65535, 17520):
            confidence = "Muito Alta (95%)"
        return {
            "os_family": os_guess,
            "scanner_name": "Nenhum (Cliente Interativo)",
            "is_scanner": False,
            "confidence": confidence,
            "signature": f"WIN:{tcp_win}|MSS:{mss_val}|WSCALE:{wscale_val}|TTL:{ip_ttl}",
            "summary": f"{os_guess} via TCP Window {tcp_win}"
        }

    # Linux / Android (TTL base 64 -> recebido entre 33 e 64)
    if 32 < ip_ttl <= 64:
        os_guess = "Linux Kernel (Moderno) / Android"
        confidence = "Alta (85%)"
        if has_ts and has_sack and mss_val in (1460, 1440, 1452):
            confidence = "Muito Alta (95%)"
            os_guess = "Linux Kernel 4.x - 6.x (Ubuntu/Debian/Arch)"
        return {
            "os_family": os_guess,
            "scanner_name": "Nenhum (Host Linux)",
            "is_scanner": False,
            "confidence": confidence,
            "signature": f"WIN:{tcp_win}|MSS:{mss_val}|WSCALE:{wscale_val}|TTL:{ip_ttl}",
            "summary": f"{os_guess} via TCP Stack nativo"
        }

    # BSD / macOS / iOS (TTL base 64 com janela 65535 clássica)
    if ip_ttl <= 64 and tcp_win == 65535 and "WScale" in opt_names:
        return {
            "os_family": "Apple (macOS / iOS) ou BSD",
            "scanner_name": "Nenhum (Cliente Apple/BSD)",
            "is_scanner": False,
            "confidence": "Alta (85%)",
            "signature": f"WIN:{tcp_win}|MSS:{mss_val}|TTL:{ip_ttl}",
            "summary": "Apple Darwin / BSD TCP Stack"
        }

    # Roteador / Equipamento de Rede / Solaris (TTL base 255 -> recebido entre 129 e 255)
    if 128 < ip_ttl <= 255:
        return {
            "os_family": "Equipamento de Rede / Roteador / Solaris",
            "scanner_name": "Sonda / Dispositivo de Infra",
            "is_scanner": False,
            "confidence": "Média (70%)",
            "signature": f"WIN:{tcp_win}|TTL:{ip_ttl}",
            "summary": f"Dispositivo de Rede com TTL base 255 (TTL:{ip_ttl})"
        }

    # Desconhecido / Anômalo
    return {
        "os_family": "Desconhecido / Sonda Sintética",
        "scanner_name": "Assinatura Customizada",
        "is_scanner": True,
        "confidence": "Baixa (50%)",
        "signature": f"WIN:{tcp_win}|TTL:{ip_ttl}|OPTS:{','.join(opt_names)}",
        "summary": f"Tráfego não padrão (TTL:{ip_ttl}, Win:{tcp_win})"
    }
