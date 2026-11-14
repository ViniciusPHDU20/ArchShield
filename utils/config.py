import os
import hashlib

try:
    from dotenv import load_dotenv, set_key
except ImportError:
    def load_dotenv(dotenv_path=None):
        if not dotenv_path or not os.path.exists(dotenv_path):
            return False
        try:
            with open(dotenv_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip().strip("'\""))
            return True
        except Exception:
            return False

    def set_key(dotenv_path, key_to_set, value_to_set):
        lines = []
        key_found = False
        if os.path.exists(dotenv_path):
            try:
                with open(dotenv_path, "r") as f:
                    lines = f.readlines()
            except Exception:
                lines = []
        new_lines = []
        for line in lines:
            if line.strip().startswith(f"{key_to_set}="):
                new_lines.append(f"{key_to_set}={value_to_set}\n")
                key_found = True
            else:
                new_lines.append(line)
        if not key_found:
            new_lines.append(f"{key_to_set}={value_to_set}\n")
        with open(dotenv_path, "w") as f:
            f.writelines(new_lines)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(BASE_DIR, ".env")
load_dotenv(env_path)

def detect_default_interface():
    env_iface = os.getenv("ARCHSHIELD_INTERFACE")
    if env_iface:
        return env_iface
    try:
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except Exception:
        pass
    return "enp6s0"

class Settings:
    def __init__(self):
        self.INTERFACE = detect_default_interface()
        self.ALLOWED_PORTS = [int(p) for p in os.getenv("ARCHSHIELD_ALLOWED_PORTS", "80,443,22,53,5555,8080").split(",")]
        
        # Whitelist genérica para uso em produção (Sem expor a rede do criador)
        self.GUARDIAN_IPS = os.getenv("ARCHSHIELD_GUARDIAN_IPS", "127.0.0.1").split(",")
        self.GUARDIAN_NETWORKS = os.getenv("ARCHSHIELD_GUARDIAN_NETWORKS", "10.0.0.0/8,192.168.0.0/16").split(",")
        
        self.DRY_RUN = os.getenv("ARCHSHIELD_DRY_RUN", "False").lower() in ("true", "1", "t")
        self.BLOCK_DURATION = int(os.getenv("ARCHSHIELD_BLOCK_DURATION", "600"))
        self.CONTAMINATION = float(os.getenv("ARCHSHIELD_CONTAMINATION", "0.02"))
        self.MIN_TRAIN_SIZE = int(os.getenv("ARCHSHIELD_MIN_TRAIN_SIZE", "400"))
        self.AI_MODEL_PATH = os.path.join(BASE_DIR, "data", "brain_v2.joblib")
        
        self.API_PORT = int(os.getenv("ARCHSHIELD_API_PORT", "5555"))
        
        self.ADMIN_USER = os.getenv("ARCHSHIELD_ADMIN_USER", "")
        self.ADMIN_PASS = os.getenv("ARCHSHIELD_ADMIN_PASS", "")
        self.SECRET_KEY = hashlib.sha256(self.ADMIN_PASS.encode()).hexdigest() if self.ADMIN_PASS else "setup_required"

    def update_credentials(self, user, password):
        set_key(env_path, "ARCHSHIELD_ADMIN_USER", user)
        set_key(env_path, "ARCHSHIELD_ADMIN_PASS", password)
        self.ADMIN_USER = user
        self.ADMIN_PASS = password
        self.SECRET_KEY = hashlib.sha256(self.ADMIN_PASS.encode()).hexdigest()

config = Settings()
