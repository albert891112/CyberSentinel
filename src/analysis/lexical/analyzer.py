"""
Lexical Analyzer for Malicious URL Detection

Uses the trained Random Forest model with lexical and N-gram features
to analyze URLs and provide risk assessments.
"""

import pickle
import os
import pandas as pd
from typing import Any

from src.analysis.lexical.features import extract_features
from src.analysis.lexical.ngram_features import TrigramFeatureExtractor


class LexicalAnalyzer:
    """
    Analyzes URLs using lexical features and a trained Random Forest model.
    
    The analyzer loads the trained model, scaler, and trigram extractor, then uses
    them to predict whether a URL is malicious or benign.
    """
    
    def __init__(self, 
                 model_path: str = "models/lexical_rf.pkl",
                 trigram_path: str = "models/trigram_extractor.pkl"):
        self.model_path = model_path
        self.trigram_path = trigram_path
        self._model = None
        self._scaler = None
        self._selector = None  # SFM feature selector
        self._feature_names: list[str] = []  # Pre-SFM features 
        self._selected_features: list[str] = []  # Post-SFM features
        self._top_domains_set: set[str] = set()
        self._trigram_extractor: TrigramFeatureExtractor | None = None
        self._load_artifacts()
    
    def _load_artifacts(self) -> None:
        """Load model and associated artifacts."""
        # Load main model artifacts
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Lexical model not found at {self.model_path}. "
                "Please run the training script first."
            )
        
        with open(self.model_path, "rb") as f:
            artifacts = pickle.load(f)
        
        # Handle new format (dict with artifacts)
        if isinstance(artifacts, dict):
            self._model = artifacts["model"]
            self._scaler = artifacts.get("scaler")
            self._selector = artifacts.get("selector")  # SFM selector
            self._feature_names = artifacts.get("feature_names", [])
            self._selected_features = artifacts.get("selected_features", [])
            self._top_domains_set = artifacts.get("top_domains_set", set())
        else:
            # Legacy format - just the model (no scaler support)
            self._model = artifacts
            self._feature_names = []
            self._selected_features = []
            self._scaler = None
            self._selector = None
        
        # Load trigram extractor if available
        if os.path.exists(self.trigram_path):
            self._trigram_extractor = TrigramFeatureExtractor()
            self._trigram_extractor.load(self.trigram_path)
    
    def analyze(self, url: str) -> dict[str, Any]:
        """
        Analyzes a URL and returns a risk assessment.
        
        Args:
            url: The URL string to analyze.
            
        Returns:
            Dictionary containing:
            - score: Risk score (0-1, higher = more likely malicious)
            - is_malicious: Boolean indicating if URL is classified as malicious
            - prediction: String prediction ("Benign" or "Malicious")
            - features: Subset of extracted features for transparency
        """
        # 1. Extract lexical features
        features = extract_features(url, top_domains=self._top_domains_set)
        
        # 2. Extract trigram features if extractor is available
        if self._trigram_extractor and self._trigram_extractor.top_trigrams:
            trigram_feats = self._trigram_extractor.transform(url)
            features.update(trigram_feats)
        
        # 3. Create raw feature DataFrame
        feat_df = pd.DataFrame([features])
        
        # 4. Align with training features (Filter correlated features)
        # Use pre-SFM feature_names if available
        if self._feature_names:
            feat_df = feat_df.reindex(columns=self._feature_names, fill_value=0)
        
        # 5. Apply SFM Feature Selection (if selector exists)
        if self._selector:
            try:
                feat_selected = self._selector.transform(feat_df)
                # Use selected_features for column names
                if self._selected_features:
                    feat_df = pd.DataFrame(feat_selected, columns=self._selected_features)
                else:
                    feat_df = pd.DataFrame(feat_selected)
            except Exception as e:
                print(f"[!] SFM selection failed: {e}. Using filtered features.")
        
        # 6. Apply Scaling (if scaler exists)
        if self._scaler:
            try:
                feat_scaled = self._scaler.transform(feat_df)
            except Exception as e:
                print(f"[!] Scaling failed: {e}. Using unscaled features.")
                feat_scaled = feat_df
        else:
            feat_scaled = feat_df
        
        # 6. Predict probability of being malicious (class 1)
        risk_score = float(self._model.predict_proba(feat_scaled)[0][1])
        
        # Determine classification (threshold 0.5)
        is_malicious = risk_score > 0.5
        prediction = "Malicious" if is_malicious else "Benign"
        
        return {
            "score": risk_score,
            "is_malicious": is_malicious,
            "prediction": prediction,
            "features": {
                "url_length": features.get("url_length", 0),
                "url_entropy": features.get("url_entropy", 0),
                "domain_length": features.get("domain_length", 0),
                "has_sensitive_keyword": features.get("has_sensitive_keyword", 0),
                "has_suspicious_extension": features.get("has_suspicious_extension", 0),
                "suspicious_tld": features.get("suspicious_tld", 0),
                "subdomain_levels": features.get("subdomain_levels", 0),
            }
        }
    
    def batch_analyze(self, urls: list[str]) -> list[dict[str, Any]]:
        """
        Analyze multiple URLs.
        
        Args:
            urls: List of URL strings to analyze.
            
        Returns:
            List of analysis results for each URL.
        """
        return [self.analyze(url) for url in urls]
