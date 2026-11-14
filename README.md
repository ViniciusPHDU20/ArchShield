# 🛡️ ArchShield PRO: Sovereign Cyber Trap & Ring 0 Kernel Sentry (v2.1)

**ArchShield PRO** is a sovereign, low-level Linux Cyber Deception, Intrusion Prevention (IDS/IPS), and Ring 0 Kernel Integrity system written in **modern Rust**. It transforms personal workstations, development rigs, and production servers into **silent, self-healing defensive traps**: unauthorized scans, rogue kernel modules, DKOM ghost processes, and DNS tunneling exfiltrations are unmasked and dropped before an adversary even realizes they have been detected.

Engineered with a **0-open-port local architecture** (`/run/archshield/archshield.sock`), ArchShield PRO exposes zero network surface on `localhost`, preventing local port binding hijackings and SSRF vulnerabilities.

---

## ⚡ Core Architecture & Capabilities

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            ArchShield PRO Engine                            │
├──────────────────────┬──────────────────────┬───────────────────────────────┤
│    Ring 0 Sentry     │ Netfilter O(1) Engine│   Covert & Threat Intel       │
├──────────────────────┼──────────────────────┼───────────────────────────────┤
│ • LKM Desync Hunter  │ • nftables Hash Sets │ • Shannon Entropy DNS Sniffer │
│ • Thread-Aware DKOM  │ • CIDR Interval Sets │ • Spamhaus DROP Ingestion     │
│ • Binary SHA-256     │ • Conntrack Immunity │ • Abuse.ch Feodo Tracker      │
│ • memfd: / unlinked  │ • Ghost Port Traps   │ • AdGuard DoT System Shield   │
└──────────────────────┴──────────────────────┴───────────────────────────────┘
```

### 1. 🔬 Ring 0 Kernel LKM Rootkit Sentry & DKOM Hunter
* **Sysfs vs /proc/modules Desync Detection:** Continuously audits `/sys/module/*/initstate` against the kernel linked list exposed in `/proc/modules`. Detects rootkits executing `list_del(&THIS_MODULE->list)` (e.g., Diamorphine/Reptile derivatives).
* **Thread-Aware DKOM Ghost Process Scrutiny:** Sweeps the PID space via POSIX `kill(pid, 0)` cross-referenced with both task group directories (`/proc/[pid]`) and all constituent thread IDs (`/proc/[pid]/task/[tid]`). Zero false positives on multi-threaded runtimes (Chromium, Steam, Electron) while isolating rootkits that unlink processes from the VFS.
* **Process Binary SHA-256 Integrity:** Calculates streaming SHA-256 hashes of running binaries on active network sockets. Flags fileless malware running from `/tmp`, `/dev/shm`, `memfd:`, or unlinked `(deleted)` executables.

### 2. ⚡ Kernel-Grade Netfilter O(1) Engine (`nftables`)
* **Constant Time Drops:** Uses atomic kernel sets (`blacklist_v4`, `blacklist_v6` with `flags interval;`) in `table inet archshield`. Evaluating whether an incoming packet belongs to a blocked subnet takes constant time $O(1)$ in nanoseconds.
* **Conntrack Stateful Immunity:** Prioritizes `ct state established,related accept` before applying drop rules. All outgoing user connections (Steam, games, Discord, browser downloads) maintain uncompromised throughput and zero ping penalty.
* **Ghost Port Blackhole:** Ports 21, 22, 23, 445, 3389, and 8080 silently drop scans without emitting `TCP RST`.

### 3. 🌐 Threat Intelligence & DNS Sinkhole
* **Global Threat Feeds Ingestion:** Periodically pulls **Spamhaus DROP** (stolen cybercrime subnets) and **Abuse.ch Feodo Tracker** (active Botnet C2s), injecting thousands of malicious targets into the kernel.
* **Shannon Entropy DNS Exfiltration Hunter:** Calculates domain label entropy ($H(X) = -\sum p(x) \log_2 p(x)$) on loopback DNS telemetry. Alerts on DNS tunneling (Iodine, Cobalt Strike DNS beacons, dnscat2) when entropy exceeds $3.8\text{ bits/symbol}$.
* **AdGuard DNS over TLS (DoT):** Fully integrated with `systemd-resolved` via port 853 with strict SNI hostname authentication (`dns.adguard-dns.com`), wiping ads, trackers, and telemetry across the entire operating system.

### 4. 💾 Bounded Memory & Atomic Persistence
* **Fixed Memory Footprint:** Operates strictly within **4.5 MB to 8 MB of RAM**.
* **Ring Buffers:** Intruders buffer truncated to 500 events; alerts buffer truncated to 100 events; DNS cache capped at 2,000 entries.
* **Atomic State Recovery:** Flushes state to `/var/lib/archshield/state.json` every 10s and on shutdown (`SIGTERM`/`SIGINT`). Packet metrics and blocked adversary IPs survive reboots without amnesia.

---

## 💻 Rust Workspace Structure

* [crates/core](file:///home/viniciusphdu/WORKSPACE_CORE/3_Hacking_e_Pentest/game_hacking_e_trainers/ArchShield_PRO/crates/core): Shared models, zero-dependency streaming SHA-256, TCP SYN fingerprinting, Ring 0 sentry, and covert channel detectors.
* [crates/daemon](file:///home/viniciusphdu/WORKSPACE_CORE/3_Hacking_e_Pentest/game_hacking_e_trainers/ArchShield_PRO/crates/daemon): Tokio-based privileged background daemon (`archshield-daemon`), raw `AF_PACKET` sniffer, `nftables` manager, DNS loopback telemetry, and threat feed synchronizer.
* [crates/cli](file:///home/viniciusphdu/WORKSPACE_CORE/3_Hacking_e_Pentest/game_hacking_e_trainers/ArchShield_PRO/crates/cli): Ultra-lightweight standalone terminal control utility (`archshield-ctl`).
* [panel.py](file:///home/viniciusphdu/WORKSPACE_CORE/3_Hacking_e_Pentest/game_hacking_e_trainers/ArchShield_PRO/panel.py) & [templates/index.html](file:///home/viniciusphdu/WORKSPACE_CORE/3_Hacking_e_Pentest/game_hacking_e_trainers/ArchShield_PRO/templates/index.html): 100% offline cyberpunk desktop HUD communicating exclusively via `/run/archshield/archshield.sock`.

---

## 🚀 Quick Start & Usage

### 1. Enable Systemd Background Service (24/7 Protection)
```bash
# Install service and start on boot
sudo cp assets/archshield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now archshield

# Check operational status
sudo systemctl status archshield
```

### 2. Launch the Desktop Panel
Open via application launcher (**`Super + D`** on Hyprland/Fuzzel -> type `ArchShield`) or run directly:
```bash
archshield-panel
```

### 3. Command-Line Interface (`archshield-ctl`)
```bash
# Execute immediate Ring 0 kernel & rootkit audit
archshield-ctl audit

# Live terminal telemetry (connections, SHA-256 hashes, process attribution)
archshield-ctl watch

# Check system state and packet totals
archshield-ctl status

# Manually isolate or restore a remote IP
archshield-ctl block 203.0.113.5
archshield-ctl unblock 203.0.113.5

# Test IPC socket connectivity
archshield-ctl ping
```

---

## 🔒 Security & Privacy Guarantees

* **Zero Local Network Listening Ports:** No `0.0.0.0` or `127.0.0.1` TCP/UDP listeners. IPC is restricted to `/run/archshield/archshield.sock` (mode `0666`).
* **Zero Telemetry Leakage:** All forensic analysis, packet metrics, and kernel auditing stay local on your machine.
* **Strict Whitelist Engine:** Guaranteed immunity for local gateway/LAN, loopback, Steam/Valve, Cloudflare, Google, GitHub, and DNS infrastructure.

---

## 📜 License
GPLv3 / Proprietary Sovereign Host Defense.
