# 🛡️ ArchShield PRO: Sovereign Edition

**ArchShield PRO** is an enterprise-grade Network Intrusion Detection and Prevention System (IDS/IPS) specifically designed for Linux environments. It leverages Deep Packet Inspection (DPI), Machine Learning, and OS-level intelligence to protect servers and personal workstations against high-volume attacks, unauthorized scanning, and malicious traffic.

Unlike traditional signature-based firewalls, ArchShield PRO uses **Behavioral Analysis** and a **Zero-Trust Intelligence Engine** to autonomously identify anomalies and enforce real-time blockades via `iptables`.

## 🚀 Key Features

- **Isolation Forest ML Engine:** Trains dynamically on your local network traffic. It learns what "normal" looks like and isolates anomalies without relying on outdated malware signatures.
- **Multiprocessing Architecture:** Built for scale. Packet sniffing, Machine Learning inference, and API handling are executed in isolated processes to prevent network bottlenecking during heavy DDoS attacks.
- **Native BGP/Whois Identity Radar:** Abandons slow and rate-limited Web APIs in favor of native `whois` queries. ArchShield traces back attacking IPs to their originating Autonomous Systems (ASN) and Organizations instantly.
- **CDN Immunity & App Shield:** Prevents "friendly fire". Vital infrastructure like Cloudflare, Fastly, GitHub, and active user-selected applications (e.g., Discord) are protected by a dynamic whitelist layer that hooks directly into the kernel's process tables (`ss -tunp`).
- **Sovereign Dashboard:** A FastAPI + React (Tailwind) command center operating on Dark Mode. Provides real-time telemetry, geographic origin tracking, and manual intervention capabilities.

## 🛠️ System Requirements

- **OS:** Arch Linux (Recommended) or any modern systemd-based Linux distribution.
- **Kernel Privileges:** Root access is mandatory for raw socket sniffing and `iptables` manipulation.
- **Dependencies:** Python 3.10+, `scapy`, `scikit-learn`, `fastapi`, `uvicorn`, `whois`.

## 🔧 Installation & Setup

### Method A: Arch Linux (AUR) - Recommended
ArchShield PRO is officially available for Arch Linux users via the AUR. It comes pre-configured as a systemd daemon.

1. **Install using yay:**
   ```bash
   yay -S archshield-pro
   ```

2. **Start the service in background:**
   ```bash
   sudo systemctl start archshield
   ```
   *To enable on boot: `sudo systemctl enable archshield`*

3. **Or run it directly in your terminal to see live logs:**
   ```bash
   sudo archshield-pro
   ```

### Method B: Manual Installation (Other Distros)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ViniciusPHDU20/ArchShield.git
   cd ArchShield
   ```

2. **Prepare the Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Initialize the Shield (Root Required):**
   ```bash
   sudo .venv/bin/python main.py
   ```

### ⚙️ First-Run Configuration:
Regardless of the installation method, you must complete the initial setup:
1. Open your browser and navigate to `http://localhost:5555`.
2. The system will detect the missing configuration and present the **Initial Setup** screen.
3. Define your Master Key. This key is used to generate secure JWTs for the API and will encrypt your session.

## 🧠 How the AI Learns (Sliding Window)
ArchShield PRO does not rely on pre-trained global datasets. Upon initialization, the system will enter a "Listening State". After capturing the first 400 packets, the Isolation Forest model compiles a local baseline. The model retrains itself every 200 packets using a sliding window of the last 1000 packets, allowing it to adapt seamlessly when you switch from casual browsing to intensive tasks like gaming or streaming.

---
**Disclaimer:** This is a powerful administrative tool. Improper configuration of the Guardian Whitelist may lock you out of your own remote servers. Use with caution.
