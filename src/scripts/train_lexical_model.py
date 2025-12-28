"""
Lexical Feature-based Malicious URL Detection Model Training Script

Based on the paper:
"Using Lexical Features for Malicious URL Detection - A Machine Learning Approach"
https://arxiv.org/pdf/1910.06277

This script:
1. Downloads PhishTank (malicious) and Tranco (benign) datasets
2. Implements 23 lexical features from Table 1 of the paper
3. Trains a Random Forest classifier with paper-recommended parameters
"""

import pickle
import pandas as pd
import numpy as np
import requests
import io
import tldextract
import zipfile
import re
import os
import sys
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_PATH = "models/lexical_rf.pkl"

# ==========================================
# Part 1: Feature Engineering
# Implements 23 Lexical Features from Table 1
# ==========================================


class URLFeatureExtractor:
    """
    Extracts lexical features from URLs for malicious URL detection.
    Features are based on Table 1 of the referenced paper.
    """

    def __init__(self, top_domains_set):
        self.top_domains = top_domains_set
        # Common suspicious TLDs (can be expanded)
        self.suspicious_tlds = {
            "xyz",
            "top",
            "club",
            "win",
            "gq",
            "cn",
            "site",
            "online",
            "live",
            "info",
            "loan",
            "work",
        }

    def get_features(self, url):
        """
        Extract all 23 lexical features from a URL.

        Args:
            url: The URL string to analyze

        Returns:
            Dictionary of feature names to values
        """
        # Ensure URL has scheme for proper parsing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        ext = tldextract.extract(url)

        # Extract URL components
        primary_domain = ext.domain
        tld = ext.suffix
        subdomain = ext.subdomain
        path = parsed.path
        query = parsed.query

        features = {}

        # --- 1. URL String Features ---
        features["url_length"] = len(url)
        features["semicolon_count"] = url.count(";")
        features["underscore_count"] = url.count("_")
        features["qmark_count"] = url.count("?")
        features["equal_count"] = url.count("=")
        features["ampersand_count"] = url.count("&")

        digits = sum(c.isdigit() for c in url)
        letters = sum(c.isalpha() for c in url)
        features["digit_letter_ratio"] = digits / letters if letters > 0 else 0

        # --- 2. Top Level Domain Features ---
        features["tld_suspicious"] = 1 if tld in self.suspicious_tlds else 0

        # --- 3. Primary Domain Features ---
        # Check for IP address pattern
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        features["domain_has_ip"] = 1 if re.search(ip_pattern, primary_domain) else 0
        features["domain_length"] = len(primary_domain)
        features["domain_digits"] = sum(c.isdigit() for c in primary_domain)
        features["domain_non_alnum"] = sum(not c.isalnum() for c in primary_domain)
        features["domain_hyphens"] = primary_domain.count("-")
        features["domain_at_symbol"] = primary_domain.count("@")
        # Check if domain is in top domains list (Tranco/Alexa replacement)
        full_domain = primary_domain + "." + tld if tld else primary_domain
        features["domain_in_top_list"] = 1 if full_domain in self.top_domains else 0

        # --- 4. Subdomain Features ---
        features["subdomain_dots"] = subdomain.count(".")
        features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0

        # --- 5. Path Features ---
        features["path_double_slash"] = path.count("//")
        clean_path = path.strip("/")
        features["path_subdirs"] = len(clean_path.split("/")) if clean_path else 0
        features["path_percent20"] = 1 if "%20" in path else 0

        path_parts = clean_path.split("/")
        features["path_upper_dirs"] = sum(
            1 for p in path_parts if any(c.isupper() for c in p)
        )
        features["path_single_char_dirs"] = sum(1 for p in path_parts if len(p) == 1)
        features["path_special_chars"] = sum(
            not c.isalnum() and c not in ["/", "."] for c in path
        )
        features["path_zeroes"] = path.count("0")

        path_upper = sum(c.isupper() for c in path)
        path_lower = sum(c.islower() for c in path)
        features["path_upper_lower_ratio"] = (
            path_upper / path_lower if path_lower > 0 else 0
        )

        # --- 6. Query Features ---
        features["query_length"] = len(query)
        features["query_count"] = len(query.split("&")) if query else 0

        return features


# ==========================================
# Part 2: Data Preparation
# ==========================================
def load_data(malicious_sample_size=100000, benign_sample_size=100000):
    """
    Downloads and prepares training data from PhishTank and Tranco.

    Args:
        malicious_sample_size: Number of malicious URLs to sample
        benign_sample_size: Number of benign URLs to sample

    Returns:
        Tuple of (malicious_urls, benign_urls, top_domains_set)
    """
    print("[*] Loading datasets...")

    # 1. Load PhishTank from local CSV (Malicious URLs)
    phish_csv_path = "data/Malicious_url/verified_online.csv"
    try:
        print(f"    Loading PhishTank data from {phish_csv_path}...")
        phish_df = pd.read_csv(phish_csv_path)
        available_phish = len(phish_df)
        sample_size = min(malicious_sample_size, available_phish)
        malicious_urls = phish_df["url"].sample(n=sample_size, random_state=42).tolist()
        print(f"    PhishTank data loaded: {len(malicious_urls)} URLs")
    except Exception as e:
        print(f"[!] Failed to load PhishTank from {phish_csv_path}: {e}")
        return None, None, None

    # 2. Download Tranco (Benign URLs)
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        print("    Downloading Tranco data...")
        r = requests.get(tranco_url)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        # Tranco CSV has no header: column 1 = rank, column 2 = domain
        tranco_df = pd.read_csv(
            z.open("top-1m.csv"), header=None, names=["rank", "domain"]
        )

        # Build Top Domain Set for feature engineering (Top 100k)
        top_domains_set = set(tranco_df["domain"].head(100000).tolist())

        # Extract benign URLs (add http:// prefix for consistency)
        sample_size = min(benign_sample_size, len(tranco_df))
        benign_urls = [
            "http://" + d for d in tranco_df["domain"].head(sample_size).tolist()
        ]
        print(f"    Tranco data loaded: {len(benign_urls)} URLs")

    except Exception as e:
        print(f"[!] Failed to download Tranco: {e}")
        return None, None, None

    return malicious_urls, benign_urls, top_domains_set


# ==========================================
# Part 3: Main Training Flow
# ==========================================


def train_model():
    """
    Main training function that follows the paper methodology:
    - 60:40 train/test split
    - Random Forest with max_depth=20
    """
    # 1. Load data
    result = load_data()
    if result[0] is None:
        print("[!] Failed to load data. Exiting.")
        return

    malicious_urls, benign_urls, top_domains_set = result

    # 2. Initialize feature extractor
    extractor = URLFeatureExtractor(top_domains_set)

    data = []
    labels = []

    print("[*] Extracting features (this may take a few minutes)...")

    # Process malicious URLs
    success_count = 0
    for url in malicious_urls:
        try:
            feats = extractor.get_features(url)
            data.append(feats)
            labels.append(1)  # 1 = Malicious
            success_count += 1
        except Exception as e:
            continue
    print(f"    Malicious URLs processed: {success_count}")

    # Process benign URLs
    success_count = 0
    for url in benign_urls:
        try:
            feats = extractor.get_features(url)
            data.append(feats)
            labels.append(0)  # 0 = Benign
            success_count += 1
        except Exception as e:
            continue
    print(f"    Benign URLs processed: {success_count}")

    # Convert to DataFrame
    df = pd.DataFrame(data)
    y = np.array(labels)

    print(f"[*] Feature matrix shape: {df.shape}")

    # 3. Split data (60:40 as per paper)
    X_train, X_test, y_train, y_test = train_test_split(
        df, y, test_size=0.4, random_state=42
    )

    # 4. Build and train Random Forest model
    # Paper recommends max_depth around 20 for best accuracy/FNR balance
    rf_model = RandomForestClassifier(
        n_estimators=100, max_depth=20, random_state=42, n_jobs=-1  # Use all CPU cores
    )

    print("[*] Training Random Forest model...")
    rf_model.fit(X_train, y_train)

    # 5. Evaluate model
    y_pred = rf_model.predict(X_test)

    print("\n" + "=" * 50)
    print("MODEL EVALUATION RESULTS")
    print("=" * 50)
    print(f"限制深度的準確率：{rf_model.score(X_test, y_test):.2%}")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # Show feature importance
    feature_importance = pd.DataFrame(
        {"feature": df.columns, "importance": rf_model.feature_importances_}
    ).sort_values("importance", ascending=False)

    print("\n" + "=" * 50)
    print("TOP 10 MOST IMPORTANT FEATURES")
    print("=" * 50)
    print(feature_importance.head(10).to_string(index=False))

    # 6. Save model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(rf_model, f)

    print(f"\n[+] Model saved to {MODEL_PATH}")

    # 7. Validation with sample URLs
    print("\n" + "=" * 50)
    print("SAMPLE PREDICTIONS")
    print("=" * 50)

    test_urls = [
        ("google.com", "Expected: Benign"),
        ("xkyz1234abcqwe.com", "Expected: Malicious"),
        ("secure-login-bank.xyz/account/verify", "Expected: Malicious"),
    ]

    for url, expected in test_urls:
        try:
            feats = extractor.get_features(url)
            feat_df = pd.DataFrame([feats])
            prob = rf_model.predict_proba(feat_df)[0][1]
            pred = "Malicious" if prob > 0.5 else "Benign"
            print(f"  {url}")
            print(f"    Prediction: {pred} (confidence: {prob:.4f})")
            print(f"    {expected}")
            print()
        except Exception as e:
            print(f"  {url}: Error - {e}")


if __name__ == "__main__":
    train_model()
