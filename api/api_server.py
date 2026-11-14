"""
ArchShield PRO - API & Sovereign Vault Service v2.1
Features:
- Silent Trap telemetry & Intruder unmasking
- Real-time Outbound Process Matrix (PID -> Binary -> Remote ASN)
- Passive WHOIS / BGP Deep Identity Resolver
- Netfilter Drop & Purgatory Management
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import jwt
from datetime import datetime, timedelta
from utils.config import config
from core.firewall import FirewallManager
import uvicorn
import logging
import socket
import requests
import time
import sqlite3
import subprocess
import re
from threading import Thread, Lock
import queue
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "archshield_cache.db")

app = FastAPI(title="ArchShield PRO Sovereign API", docs_url=None, redoc_url=None)
security = HTTPBearer()

stats_bridge = {}
identity_cache = {}
identity_lock = Lock()
lookup_queue = queue.Queue()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS ip_info (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            country_code TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS intruders_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            target_port INTEGER,
            port_desc TEXT,
            proto TEXT,
            os_family TEXT,
            scanner_name TEXT,
            confidence TEXT,
            country TEXT,
            org TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )''')
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Erro ao inicializar DB: {e}")

init_db()

def is_setup_required():
    return not config.ADMIN_USER or not config.ADMIN_PASS

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if is_setup_required():
        raise HTTPException(status_code=403, detail="Setup Required")
    if credentials.credentials == config.ADMIN_PASS:
        return config.ADMIN_USER
    try:
        jwt.decode(credentials.credentials, config.SECRET_KEY, algorithms=["HS256"])
        return config.ADMIN_USER
    except Exception:
        raise HTTPException(status_code=401)

def create_token(user_id: str):
    payload = {"sub": user_id, "exp": datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")

# --- MOTOR DE PERSISTÊNCIA GEOGRÁFICA ---
def save_identity_to_db(ip, identity):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''INSERT OR REPLACE INTO ip_info (ip, country, city, isp, org, country_code) 
                          VALUES (?, ?, ?, ?, ?, ?)''', 
                       (ip, identity.get('country',''), identity.get('city',''), identity.get('isp',''), identity.get('org',''), identity.get('country_code','')))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_identity_from_db(ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT country, city, isp, org, country_code FROM ip_info WHERE ip=?', (ip,))
        row = cursor.fetchone()
        conn.close()
        if row: 
            company = row[3] if row[3] and str(row[3]).strip() != "" else "Desconhecido"
            return {
                "country": row[0],
                "city": row[1],
                "isp": row[2],
                "org": row[3],
                "country_code": row[4],
                "domain": "Cached",
                "company": company,
                "status": "READY"
            }
    except Exception:
        pass
    return None

# --- RECONHECIMENTO NATIVO (WHOIS ROOT LEVEL) ---
def get_whois_identity(ip):
    company = "Empresa Oculta"
    country = "Internacional"
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=3)
        output = result.stdout
        org_matches = re.findall(r'(?i)^(?:OrgName|org-name|Organization|descr|owner):\s*(.+)', output, re.MULTILINE)
        generic_rirs = ["RIPE", "ARIN", "APNIC", "AFRINIC", "LACNIC", "RIPE Network Coordination Centre"]
        valid_orgs = [m.strip() for m in org_matches if not any(rir in m.strip() for rir in generic_rirs)]
        if valid_orgs:
            company = valid_orgs[-1]
        else:
            net_matches = re.findall(r'(?i)^(?:NetName|netname):\s*(.+)', output, re.MULTILINE)
            if net_matches:
                company = net_matches[-1].strip()
        country_matches = re.findall(r'(?i)^[Cc]ountry:\s*([A-Z]{2})', output, re.MULTILINE)
        if country_matches:
            country = country_matches[-1].upper()
    except Exception:
        pass
    return company, country

def identity_worker():
    while True:
        ip = lookup_queue.get()
        with identity_lock:
            if ip in identity_cache and identity_cache[ip].get('status') == 'READY':
                lookup_queue.task_done()
                continue
            info = identity_cache.get(ip, {"domain": "Calculando...", "company": "Aguarde...", "city": "...", "country": "Net", "country_code": "", "status": "BUSCANDO"})
        try:
            socket.setdefaulttimeout(0.5)
            info["domain"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            info["domain"] = "IP Direto"

        company, country = get_whois_identity(ip)
        info.update({
            "country": country,
            "country_code": country.lower(),
            "city": "WHOIS Lookup",
            "isp": company,
            "org": company,
            "company": company,
            "status": "READY"
        })
        save_identity_to_db(ip, info)

        with identity_lock:
            identity_cache[ip] = info
        time.sleep(0.4) 
        lookup_queue.task_done()

Thread(target=identity_worker, daemon=True).start()

def get_fast_deep_identity(ip):
    if not ip or ip in ("*", "127.0.0.1", "::1"):
        return {"domain": "Local", "company": "Host Local", "city": "Localhost", "country": "Local", "country_code": "", "status": "READY"}
    with identity_lock:
        if ip in identity_cache:
            return identity_cache[ip]
    cached = get_identity_from_db(ip)
    if cached:
        with identity_lock:
            identity_cache[ip] = cached
        return cached
    info = {"domain": "Calculando...", "company": "Infiltrando BGP...", "city": "...", "country": "...", "country_code": "", "status": "NOVO"}
    with identity_lock:
        identity_cache[ip] = info
    lookup_queue.put(ip)
    return info

# --- API ENDPOINTS ---
@app.get("/")
async def serve_dashboard():
    template_path = os.path.join(BASE_DIR, "templates", "index.html")
    if not os.path.exists(template_path):
        template_path = "/opt/archshield-pro/templates/index.html"
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail="Dashboard template not found")
    return FileResponse(template_path)

@app.get("/check_setup")
async def check_setup():
    return {"setup_required": is_setup_required()}

@app.post("/setup")
async def perform_setup(request: Request):
    if not is_setup_required():
        raise HTTPException(status_code=400, detail="Setup already completed.")
    data = await request.json()
    user = data.get("user")
    pwd = data.get("pass")
    if user and pwd:
        config.update_credentials(user, pwd)
        return {"success": True, "token": create_token(user)}
    return {"success": False}

@app.post("/api/auth/login")
async def login(request: Request):
    if is_setup_required():
        raise HTTPException(status_code=403, detail="Setup Required")
    data = await request.json()
    if data.get("user") == config.ADMIN_USER and data.get("pass") == config.ADMIN_PASS:
        return {"token": create_token(config.ADMIN_USER)}
    raise HTTPException(status_code=401)

@app.get("/status")
async def get_status(user: str = Depends(verify_token)):
    conns = stats_bridge.get('active_conns', {})
    active_list = []
    blocked_list = []
    
    # 1. Conexões gerais
    for ip, last_seen in conns.items():
        if time.time() - last_seen < 20:
            ident = get_fast_deep_identity(ip)
            status_ico = "⏳" if ident['status'] != "READY" else "✅"
            active_list.append(f"{ip} {status_ico} [{ident['company']}] | {ident['domain']}")

    # 2. Bloqueios do Netfilter
    current_blocked = list(stats_bridge.get('blocked_ips', []))
    for ip in current_blocked:
        ident = get_fast_deep_identity(ip)
        blocked_list.append({
            "ip": ip,
            "company": ident.get('company', 'Bloqueado'),
            "country": ident.get('country', 'N/A')
        })

    # 3. Invasores da Armadilha Silenciosa (Enriquecidos com WHOIS)
    raw_trapped = list(stats_bridge.get('trapped_intruders', []))
    enriched_trapped = []
    for item in raw_trapped[:35]:
        ip = item['ip']
        ident = get_fast_deep_identity(ip)
        entry = dict(item)
        entry['country'] = ident.get('country', 'Internacional')
        entry['country_code'] = ident.get('country_code', '')
        entry['org'] = ident.get('company', 'Apurando BGP...')
        entry['domain'] = ident.get('domain', 'IP Direto')
        entry['is_blocked'] = (ip in current_blocked)
        enriched_trapped.append(entry)

    # 4. Telemetria de Processos de Saída (Outbound Matrix)
    raw_outbound = list(stats_bridge.get('outbound_conns', []))
    enriched_outbound = []
    for sock in raw_outbound[:40]:
        r_ip = sock.get('remote_ip')
        ident = get_fast_deep_identity(r_ip) if r_ip and r_ip not in ("*", "") else {}
        entry = dict(sock)
        entry['org'] = ident.get('company', '')
        entry['country_code'] = ident.get('country_code', '')
        enriched_outbound.append(entry)

    return {
        "training": stats_bridge.get('ia_status') == "ATIVA & PROTEGENDO",
        "ia_status": stats_bridge.get('ia_status', "INICIALIZANDO"),
        "total_packets": stats_bridge.get('total_packets', 0),
        "anomalies": stats_bridge.get('anomalies', 0),
        "packets": stats_bridge.get('packets_history', []),
        "times": stats_bridge.get('times_history', []),
        "active_ips": active_list,
        "blocked_ips": blocked_list,
        "trapped_intruders": enriched_trapped,
        "outbound_conns": enriched_outbound,
        "trap_count": len(raw_trapped)
    }

@app.post("/block_ip")
async def block_route(request: Request, user: str = Depends(verify_token)):
    data = await request.json()
    ip = data.get("ip")
    if ip:
        FirewallManager.block_ip(ip)
        blist = list(stats_bridge.get('blocked_ips', []))
        if ip not in blist:
            blist.append(ip)
            stats_bridge['blocked_ips'] = blist
        return {"success": True}
    return {"success": False}

@app.post("/unblock_ip")
async def unblock_route(request: Request, user: str = Depends(verify_token)):
    data = await request.json()
    ip = data.get("ip")
    if ip:
        FirewallManager.unblock_ip(ip)
        blist = list(stats_bridge.get('blocked_ips', []))
        if ip in blist:
            blist.remove(ip)
            stats_bridge['blocked_ips'] = blist
        return {"success": True}
    return {"success": False}

@app.post("/api/trap/clear")
async def clear_trap(user: str = Depends(verify_token)):
    stats_bridge['trapped_intruders'] = []
    return {"success": True}

def run_api(stats_dict):
    global stats_bridge
    stats_bridge = stats_dict
    uvicorn.run(app, host="0.0.0.0", port=config.API_PORT, log_level="error")
