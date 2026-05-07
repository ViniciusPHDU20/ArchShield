import logging
import sys
import os
from multiprocessing import Manager, Process
from core.core_engine import CoreEngine
from api.api_server import run_api
from utils.config import config

# Configuração de Logs Profissionais
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("archshield_pro.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

def main():
    if os.geteuid() != 0:
        print("❌ ERRO: O ArchShield PRO exige privilégios de ROOT para captura de pacotes.")
        sys.exit(1)

    logging.info("======================================================")
    logging.info("👑 ARCHSHIELD PRO v2.0 - SOVEREIGN EDITION")
    logging.info("======================================================")

    # Criação do Espaço de Memória Compartilhada (Manager)
    with Manager() as manager:
        stats = manager.dict()
        stats['ia_status'] = "INICIALIZANDO"
        stats['total_packets'] = 0
        stats['anomalies'] = 0
        stats['active_conns'] = {}

        # 1. Iniciar Motor Central (Captura e IA)
        engine = CoreEngine(stats)
        engine.start()

        # 2. Iniciar Servidor de API (Dashboard)
        # Rodamos na thread principal para manter o Manager vivo
        run_api(stats)

if __name__ == "__main__":
    main()
