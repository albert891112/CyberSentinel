import pickle
import os
import numpy as np
from typing import Dict, Any
from src.analysis.lexical.features import extract_features

class LexicalAnalyzer:
    def __init__(self, model_path: str = "models/lexical_rf.pkl"):
        self.model_path = model_path
        self._model = None
        self._load_model()
    
    def _load_model(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self._model = pickle.load(f)
        else:
            raise FileNotFoundError(f"Lexical model not found at {self.model_path}. Please run training script.")

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Analyzes a URL and returns a risk assessment.
        """
        features = extract_features(url)
        
        # Reshape for sklearn (1, n_features)
        X = np.array(features).reshape(1, -1)
        
        # Predict probability of being malicious (class 1)
        risk_score = float(self._model.predict_proba(X)[0][1])
        
        # Determine strictness threshold (can be tuned)
        is_dga = risk_score > 0.75
        
        return {
            "score": risk_score,
            "is_dga": is_dga,
            "features": {
                "length": features[0],
                "entropy": features[1],
                "digits": features[2],
                "special_chars": features[3],
                "consonant_cluster": features[4]
            }
        }
