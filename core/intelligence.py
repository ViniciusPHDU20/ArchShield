import joblib
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from utils.config import config
import os

class IntelligenceCore:
    def __init__(self):
        self.model_path = config.AI_MODEL_PATH
        self.model = self._load_model()
        self.is_fitted = False if self.model is None else True
        self.feature_history = []
        
        if self.model is None:
            # IA configurada para ser cautelosa na v2
            self.model = IsolationForest(contamination=0.01, random_state=42)
            logging.info("🧠 IA: Novo modelo inicializado (Aguardando treinamento)")

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                model = joblib.load(self.model_path)
                logging.info(f"💾 IA: Modelo carregado de {self.model_path}")
                # Verifica se o modelo carregado é válido
                if hasattr(model, "decision_function"):
                    return model
            except Exception as e:
                logging.error(f"❌ IA: Falha ao carregar modelo: {e}")
        return None

    def save_model(self):
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            logging.info(f"💾 IA: Cérebro salvo em {self.model_path}")
        except Exception as e:
            logging.error(f"❌ IA: Falha ao salvar cérebro: {e}")

    def train(self, features_list):
        if len(features_list) < config.MIN_TRAIN_SIZE:
            return False
        
        logging.info(f"⚙️ IA: Treinando com {len(features_list)} amostras...")
        data = np.array(features_list)
        self.model.fit(data)
        self.is_fitted = True
        self.save_model()
        return True

    def predict(self, features):
        if not self.is_fitted:
            return 1 
        
        score = self.model.score_samples([features])[0]
        return score
