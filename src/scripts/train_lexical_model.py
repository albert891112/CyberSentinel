import pickle
import numpy as np
import os
import random
import string
from sklearn.ensemble import RandomForestClassifier
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from src.analysis.lexical.features import extract_features

MODEL_PATH = "models/lexical_rf.pkl"

def generate_dga_domain(length=None):
    """Generates a synthetic DGA-like domain."""
    if length is None:
        length = random.randint(10, 25)
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".com"

def generate_benign_domain():
    """Returns a synthetic 'benign' domain from a small list + variations."""
    # In a real scenario, we'd load a top-1m list.
    roots = ["google", "facebook", "amazon", "apple", "microsoft", "netflix", "openai", "github", "stackoverflow", "wikipedia"]
    tlds = [".com", ".org", ".net", ".io"]
    root = random.choice(roots)
    if random.random() > 0.8:
        root += random.choice(string.digits) # slight variation
    return root + random.choice(tlds)

def train_model():
    print("[*] Generating training data...")
    X = []
    y = []

    # Generate 1000 benign samples
    for _ in range(1000):
        domain = generate_benign_domain()
        X.append(extract_features(domain))
        y.append(0) # 0 = Benign

    # Generate 1000 DGA samples
    for _ in range(1000):
        domain = generate_dga_domain()
        X.append(extract_features(domain))
        y.append(1) # 1 = Malicious

    print(f"[*] Training Random Forest on {len(X)} samples...")
    clf = RandomForestClassifier(n_estimators=50, max_depth=5, random_state=42)
    clf.fit(X, y)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    
    print(f"[+] Model saved to {MODEL_PATH}")
    
    # Validation
    test_good = "google.com"
    test_bad = "xkyz1234abcqwe.com"
    
    print(f"Validation:")
    print(f"  {test_good}: {clf.predict_proba([extract_features(test_good)])[0][1]:.4f} (Expected Low)")
    print(f"  {test_bad}:  {clf.predict_proba([extract_features(test_bad)])[0][1]:.4f} (Expected High)")

if __name__ == "__main__":
    train_model()
