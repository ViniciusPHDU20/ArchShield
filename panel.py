#!/usr/bin/env python3
# language: Python, file: panel.py, runtime: PyQt6-WebEngine, target: Arch Linux / Hyprland
"""
ArchShield PRO - Native Sovereign 0-Port GUI Panel
Zero local TCP listening ports. Speaks strictly via UNIX Domain Socket (/run/archshield/archshield.sock).
"""

import sys
import os
import socket
import json
from PyQt6.QtCore import QUrl, QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtWebEngineWidgets import QWebEngineView

SOCKET_PATHS = [
    os.environ.get("ARCHSHIELD_SOCKET_PATH", ""),
    "/run/archshield/archshield.sock",
    "/tmp/archshield.sock"
]

def query_ipc(cmd_obj):
    raw_cmd = json.dumps(cmd_obj) + "\n"
    for sp in SOCKET_PATHS:
        if not sp or not os.path.exists(sp):
            continue
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            sock.connect(sp)
            sock.sendall(raw_cmd.encode())
            
            buf = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in chunk:
                    break
            sock.close()
            if buf:
                return json.loads(buf.decode().strip())
        except Exception:
            continue
    return None

class SovereignPanel(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ArchShield PRO - Sovereign Tripwire & Deception Panel (0 Ports)")
        self.resize(1360, 860)

        self.browser = QWebEngineView()
        self.setCentralWidget(self.browser)

        base_dir = os.path.dirname(os.path.abspath(__file__))
        html_path = os.path.join(base_dir, "templates", "index.html")
        self.browser.load(QUrl.fromLocalFile(html_path))

        self.browser.titleChanged.connect(self.on_title_changed)
        self.browser.loadFinished.connect(self.on_load_finished)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_telemetry)
        self.timer.start(1000)

    def on_load_finished(self, ok):
        if ok:
            # Ativa modo desktop nativo no frontend e atualiza imediatamente
            self.browser.page().runJavaScript("window.isNativeDesktop = true;")
            self.refresh_telemetry()

    def on_title_changed(self, title):
        if title.startswith("ARCHSHIELD_ACTION:"):
            parts = title.split(":", 2)
            action = parts[1] if len(parts) > 1 else ""
            param = parts[2] if len(parts) > 2 else ""

            if action == "block" and param:
                query_ipc({"cmd": "BlockIp", "payload": {"ip": param}})
            elif action == "unblock" and param:
                query_ipc({"cmd": "UnblockIp", "payload": {"ip": param}})
            elif action == "clear":
                query_ipc({"cmd": "ClearTrap", "payload": None})

            # Restaura título padrão
            self.browser.page().runJavaScript("document.title = 'ArchShield PRO - Sovereign Tripwire & Deception Panel (0 Ports)';")
            self.refresh_telemetry()

    def refresh_telemetry(self):
        res = query_ipc({"cmd": "GetStatus", "payload": None})
        if res and res.get("status") == "Status":
            snapshot = res.get("data", {})
            js_code = f"if (window.renderFromNative) window.renderFromNative({json.dumps(snapshot)});"
            self.browser.page().runJavaScript(js_code)

def main():
    app = QApplication(sys.argv)
    panel = SovereignPanel()
    panel.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
