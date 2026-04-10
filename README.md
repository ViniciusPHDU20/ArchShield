# 🛡️ ArchShield: Advanced Network Security Dashboard

**ArchShield** is a high-performance network monitoring and anomaly detection system specifically architected for **Arch Linux**. It provides real-time traffic analysis, automated threat mitigation via `iptables`, and a responsive web-based command center.

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Arch Linux](https://img.shields.io/badge/Arch-Linux-blue.svg)](https://archlinux.org/)
[![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)](https://www.python.org/)

## 🚀 Key Capabilities

- **Real-Time Traffic Analysis**: Deep packet inspection (DPI) and traffic monitoring to identify potential threats in real-time.
- **Anomaly Detection Engine**: Intelligent heuristics to detect port scanning, DDoS attempts, and unusual connection patterns.
- **Automated Mitigation**: Instant IP blocking via native `iptables` integration when threats are identified.
- **Interactive Dashboard**: A Flask-powered web interface for visualizing active connections, traffic graphs, and manual firewall control.
- **Systemd Integration**: Operates as a background daemon for persistent protection from boot.

## 🧰 Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3 |
| **Web Interface** | Flask, HTML5, CSS3, JS |
| **Firewall Control** | `iptables` / `ebtables` |
| **System Daemon** | Systemd |
| **Data Visualization** | Chart.js / Real-time Tables |

## 🛠 Installation & Deployment

ArchShield is designed to be easily deployed on Arch Linux systems.

### Quick Install

1. Clone the repository:
   ```bash
   git clone https://github.com/ViniciusPHDU20/ArchShield.git
   cd ArchShield
   ```
2. Execute the deployment script as root:
   ```bash
   sudo ./install_archshield.sh
   ```

The script will:
- Install all necessary dependencies via `pacman`.
- Configure `/etc/archshield.conf`.
- Deploy the systemd service.
- Start the web dashboard.

## 📊 Dashboard Access

Once the service is active, the dashboard can be accessed at:
`http://localhost:5000` (or your configured port).

From the dashboard, you can:
- Monitor live throughput.
- View and manage active IP connections.
- Manually block/unblock IPs with a single click.

## ⚙️ Project Structure

- `no_gui_archshield.py`: The core detection and server engine.
- `install_archshield.sh`: Complete system installer.
- `centralize_archshield_logs.sh`: Distributed logging utility.
- `PKGBUILD`: Native Arch Linux package build script.

---
*Developed by **ViniciusPHDU20***
