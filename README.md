# 🛡️ ArchShield PRO: Sovereign Tripwire Edition (v2.1)

**ArchShield PRO** is an enterprise-grade Network Intrusion Detection, Cyber Deception, and Tripwire Prevention System (IDS/IPS) specifically engineered for Linux environments. It transforms personal workstations and servers into **silent defensive traps**: any unauthorized inbound scan, probe, or intrusion attempt is silently caught, unmasked, and fingerprinted before an attacker even realizes they were detected.

Unlike traditional signature-based firewalls, ArchShield PRO combines **Passive OS/Scanner Fingerprinting**, **Zero-Trust Process Attribution**, and an **Unsupervised Isolation Forest Engine** to autonomously enforce real-time blockades via Linux Netfilter (`iptables`).

---

## 🚀 Key Architectural Capabilities

- **🕸️ Silent Tripwire & Cyber Deception:**
  Arms ghost ports with silent Netfilter blackholes. Any inbound TCP SYN touching sensitive or closed ports is trapped without returning `TCP RST`. The attacker hangs in silence while ArchShield builds a full forensic dossier on them.
- **🔍 Passive OS & Scanner Fingerprinting (Zero Overhead):**
  Pure passive inspection of TCP headers (TTL, Window Size, MSS, Options layout). Identifies whether incoming probes originate from automated scanners (**Masscan**, **Nmap Stealth Scan**, **ZMap**) or interactive operating systems (**Windows**, **Linux**, **macOS/iOS**).
- **🛰️ Outbound Matrix (Process & Socket Attribution):**
  Directly hooks into Linux kernel socket tables (`ss -tunp -H`). Maps every external connection directly to its originating **Binary Name** and **PID** (`steam`, `vesktop`, `firefox`, `curl`), giving the user 100% total visibility over data leaving the host.
- **⚡ Native BGP / WHOIS Deep Identity Radar:**
  Bypasses rate-limited commercial APIs in favor of direct queries to Regional Internet Registries (ARIN, RIPE, LACNIC). Traces back remote IPs to their true Autonomous System (ASN), ISP, and country, cached persistently in SQLite (`data/archshield_cache.db`).
- **🧠 Sliding Window Isolation Forest:**
  Learns normal traffic patterns dynamically. Retrains every 200 packets using a sliding window of the last 1000 features, adapting to user workflows while catching high-aggression DDoS and anomalies (`score < -0.88`).
- **🛡️ CDN Immunity & AppShield Dynamic Whitelist:**
  Hooks into process tables to protect vital infrastructure (Cloudflare, Steam, GitHub, Fastly, Google) and running user apps (Discord, Vesktop, Spotify) against false-positive isolation.
- **👑 Sovereign Command Vault:**
  FastAPI + Tailwind CSS command center running in Dark Mode. Features real-time packet telemetry, a dedicated **Armadilha Silenciosa** intruder grid, process matrix, and 1-click Netfilter purgatory controls.

---

## 🛠️ System Requirements

- **OS:** Arch Linux (Recommended) or any modern systemd-based Linux distribution.
- **Kernel Privileges:** Root access is mandatory for raw socket sniffing and Netfilter `iptables` manipulation.
- **Dependencies:** Python 3.10+, `scapy`, `scikit-learn`, `fastapi`, `uvicorn`, `whois`, `iptables`.

---

## 🔧 Installation & Setup

### Method A: Arch Linux (AUR) - Recommended
ArchShield PRO is natively packaged for Arch Linux with an integrated systemd service.

1. **Install using yay:**
   ```bash
   yay -S archshield-pro
   ```

2. **Start the background daemon:**
   ```bash
   sudo systemctl start archshield
   ```
   *To enable on boot: `sudo systemctl enable archshield`*

3. **Or run directly in terminal for live forensic output:**
   ```bash
   sudo archshield-pro
   ```

---

### Method B: Manual Installation (Any Linux Distro)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ViniciusPHDU20/ArchShield.git
   cd ArchShield
   ```

2. **Prepare Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Initialize the Shield (Root Required):**
   ```bash
   sudo .venv/bin/python main.py
   ```

---

## ⚙️ First-Run Configuration

1. Open your browser at `http://localhost:5555`.
2. The system detects initial setup and prompts for your **Master Key**.
3. The Master Key encrypts your credentials using SHA-256 and issues HS256-signed JSON Web Tokens for API authorization.

---

## 🔒 Security Disclaimer
ArchShield PRO is an administrative host defense tool. Exercise proper care when configuring custom CIDR whitelists to avoid accidental remote SSH lockouts.
