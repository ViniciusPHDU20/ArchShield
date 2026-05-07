import os
import hashlib
from dotenv import load_dotenv, set_key

# Carrega variáveis do arquivo .env se existir
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
load_dotenv(env_path)

class Settings:
    def __init__(self):
        self.INTERFACE = os.getenv("ARCHSHIELD_INTERFACE", "enp7s0")
        self.ALLOWED_PORTS = [int(p) for p in os.getenv("ARCHSHIELD_ALLOWED_PORTS", "80,443,22,53,5555,8080").split(",")]
        
        # Whitelist genérica para uso em produção (Sem expor a rede do criador)
        self.GUARDIAN_IPS = os.getenv("ARCHSHIELD_GUARDIAN_IPS", "127.0.0.1").split(",")
        self.GUARDIAN_NETWORKS = os.getenv("ARCHSHIELD_GUARDIAN_NETWORKS", "10.0.0.0/8,192.168.0.0/16").split(",")
        
        self.DRY_RUN = os.getenv("ARCHSHIELD_DRY_RUN", "False").lower() in ("true", "1", "t")
        self.BLOCK_DURATION = int(os.getenv("ARCHSHIELD_BLOCK_DURATION", "600"))
        self.CONTAMINATION = float(os.getenv("ARCHSHIELD_CONTAMINATION", "0.02"))
        self.MIN_TRAIN_SIZE = int(os.getenv("ARCHSHIELD_MIN_TRAIN_SIZE", "400"))
        self.AI_MODEL_PATH = "data/brain_v2.joblib"
        
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
