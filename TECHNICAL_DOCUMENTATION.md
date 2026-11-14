# 🧠 TECHNICAL DOCUMENTATION: ArchShield PRO v2.1 Architecture
*Enterprise-Grade Network Intrusion Detection, Cyber Deception & Tripwire Prevention System*

---

## 1. System Topology & IPC (Inter-Process Communication)

ArchShield PRO executes on a decoupled multi-process architecture to eliminate Python's Global Interpreter Lock (GIL) and guarantee real-time latency under heavy network load:

1. **The Sniffer Loop (Kernel Socket Layer):** Dedicated exclusively to capturing raw network frames using Scapy's `AF_PACKET` raw socket (`filter="ip"`). To guarantee zero packet loss, it extracts crucial metadata (`src`, `dst`, `proto`, `sport`, `dport`, `ttl`, `tcp_flags`, `tcp_win`, `tcp_options`) and enqueues them into an asynchronous IPC `Queue(maxsize=20000)`.
2. **The Analyst Loop (AI & Deception Core):** Consumes vectors from the queue. Evaluates inbound TCP SYN traffic through the **Passive Fingerprint Engine**, detects scanners (Nmap/Masscan/ZMap), manages the **Sliding Window Isolation Forest**, and synchronizes with Linux Netfilter.
3. **The API & Vault Server (FastAPI/Uvicorn):** Serves the sovereign command dashboard and provides secure REST endpoints. Reads state directly from shared memory (`multiprocessing.Manager.dict()`).

---

## 2. The Silent Trap: Inbound Cyber Deception (Tripwire Engine)

On a personal workstation or sovereign host, network traffic is predominantly **outbound** (user applications connecting to web/game/API servers). Unsolicited **inbound** packets touching non-public ports are inherently reconnaissance or attack vectors.

### A. The Blackhole Trap (`core/firewall.py`)
- The system arms ghost ports (e.g. 21, 22, 23, 445, 3389, 8080) with a silent Netfilter `DROP` rule.
- Unlike traditional closed ports that return `TCP RST` (revealing host presence), the scanner receives zero response.
- Scapy's raw packet socket captures the incoming SYN packet before the Netfilter drop, triggering the passive attribution pipeline.

### B. Passive TCP Fingerprinting (`core/fingerprint.py`)
Without making any outbound noise, ArchShield evaluates the raw TCP handshake characteristics:
- **Time To Live (TTL):** Discovers base operating system (Linux `64`, Windows `128`, Network gear `255`).
- **TCP Window Size & MSS:** Distinguishes interactive clients from automated scanners.
- **Scanner Signatures:**
  - `Masscan`: Window size = `1024`, zero TCP options.
  - `Nmap Stealth (-sS)`: Window size in multiples of 1024 (`1024, 2048, 3072, 4096`), reduced option sets.
  - `ZMap`: Window size `65535` or `54272`, custom flag sequences.
- **Port Profiling:** Identifies exploit vectors (WannaCry on `445`, SSH brute force on `22`, RDP on `3389`).

---

## 3. Outbound Matrix: Process & Socket Attribution (`core/conntrack.py`)

To eliminate blind spots and ensure total host visibility, the engine hooks into the Linux kernel socket tables (`ss -tunp -H`):
- Maps every active connection to its real **Process Name** and **PID** (`steam`, `vesktop`, `firefox`, `curl`).
- Dissects local and remote endpoints for both IPv4 and IPv6.
- Prevents rogue background exfiltration: if an unexpected binary establishes a connection, it surfaces instantly on the dashboard with a 1-click Netfilter ban option.

---

## 4. Native BGP / WHOIS Deep Identity Radar (`api/api_server.py`)

No third-party commercial APIs or rate limits:
- Queries the root Regional Internet Registries (ARIN, RIPE, LACNIC, APNIC, AFRINIC) via the native Linux `whois` protocol.
- Resolves Reverse DNS (`PTR`) hostnames.
- Results are persistently cached in SQLite (`data/archshield_cache.db`), eliminating redundant network overhead.

---

## 5. Machine Learning Configuration (Isolation Forest)

* **Algorithm:** `sklearn.ensemble.IsolationForest`
* **Contamination:** `0.02` (2%)
* **Feature Vector:** `[Packet_Length, is_TCP, is_UDP, TTL, Destination_Port]`
* **Sliding Window Retraining:** Trains dynamically on the host's actual network baseline. Retrains every 200 packets using the latest 1000 samples.
* **Threshold:** Packets with anomaly score `< -0.88` trigger immediate Netfilter isolation.

---

## 6. Zero-Trust Security & Vault Cryptography

- **Master Key Hashing:** Credential setup derives an HMAC-SHA256 secret key.
- **JWT Authentication:** Strict Bearer token validation on all API endpoints.
- **Dual Privilege Architecture:** Root-level kernel packet manipulation decoupled from minimal-privilege execution paths.
