# 🧠 TECHNICAL DOCUMENTATION: ArchShield PRO Architecture

## 1. System Topology & IPC (Inter-Process Communication)

ArchShield PRO abandons the limitations of Python's Global Interpreter Lock (GIL) by implementing a multi-process architecture using the `multiprocessing` library. The system is divided into three distinct execution contexts:

1. **The Sniffer Loop (High Priority):** Dedicated exclusively to capturing raw network packets using `scapy` at the IP level (`filter="ip"`). To guarantee zero packet loss during flood events, this process performs no complex calculations. It merely extracts critical dimensions (Size, Protocol, TTL, Port) and pushes them into an asynchronous `Queue`.
2. **The Analyst Loop (AI & Enforcement):** Pulls vectors from the Queue. It maintains the Sliding Window of packet features and triggers the `scikit-learn` Isolation Forest training. When a hostile vector is detected, it delegates the ban order to the `FirewallManager`.
3. **The API Server (FastAPI/Uvicorn):** Serves the dashboard and handles REST endpoints. It reads telemetry data from a thread-safe `Manager.dict()` updated atomically by the Analyst Loop.

## 2. The Identity Radar (Native BGP/Whois Engine)

Early versions of ArchShield relied on external REST APIs (e.g., ip-api.com) for geolocation and organization tracking. This proved flawed in production due to severe Rate Limiting (45 req/min) which bottlenecked the UI during intense traffic.

**The Sovereign Solution:**
The system now leverages the Linux native `whois` binary wrapped in asynchronous background threads (`lookup_queue`). 
- When an unknown IP connects, a thread spawns, executing a raw Whois query against ARIN/RIPE/LACNIC databases.
- Using Regular Expressions (`re.findall(r'(?i)^(?:OrgName...`), ArchShield extracts the `Organization` or `NetName`.
- The result is immediately cached into an SQLite database (`archshield_cache.db`), ensuring that subsequent encounters with the same IP require exactly zero network overhead.

## 3. Machine Learning Configuration (Isolation Forest)

The core defensive logic relies on Unsupervised Machine Learning. 

*   **Algorithm:** `sklearn.ensemble.IsolationForest`
*   **Contamination Factor:** `0.02` (2%). We assume that, statistically, 2% of incoming traffic in a healthy environment consists of scanners or malformed packets.
*   **Feature Vector:** `[Packet_Length, is_TCP, is_UDP, TTL, Destination_Port]`
*   **Dynamic Calibrating (Sliding Window):** The model is trained continuously. Every 100 packets (after the initial 400), the system slices the last 1000 features (`features_buffer[-1000:]`) and refits the tree.
*   **Threshold:** Only packets returning an anomaly score of `< -0.85` (Sigma-level aggression) trigger a block.

## 4. CDN Immunity and Friendly-Fire Prevention

An NIDS without context is a liability. Streaming data (Discord WebRTC) or downloading packages (GitHub/Steam) generates massive, rapid UDP/TCP bursts that the AI naturally flags as DDoS anomalies.

To prevent the system from isolating the host, ArchShield employs a **Three-Tier Whitelist**:
1. **The Guardian Layer:** Local subnets (`192.168.0.0/16`) and virtual adapters (Tailscale `100.0.0.0/8`) are hardcoded to bypass the AI entirely.
2. **The CDN Layer:** Entire `/12` and `/16` IPv4 blocks belonging to vital CDNs (Cloudflare, Fastly, Akamai) are whitelisted natively in `core_engine.py`.
3. **The App Shield (Process Hooking):** The engine executes `ss -tunp` locally. If a hostile IP is found to be attached to a trusted user-space process (e.g., `vesktop`, `chrome`), the block order is automatically voided.

## 5. Security & Cryptography

- **Master Key Hashing:** The system operates without hardcoded default passwords. On first boot, the user defines a Master Key which is passed through `hashlib.sha256` and saved in a `.env` file.
- **JWT Auth:** The FastAPI backend enforces a Zero-Trust policy on its own endpoints. The Master Key grants an HS256-signed JSON Web Token with a 24-hour lifespan. No metrics or IP data can be scraped without providing the Bearer token.
