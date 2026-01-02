"""
Lexical Feature-based Malicious URL Detection Model Training Script

Enhanced based on literature review:
- Multiple data sources (PhishTank, Kaggle, Tranco)
- 26+ lexical features including entropy, keywords, extensions
- N-gram/Trigram features (top 500)
- SMOTE for data balancing
- Correlation-based feature selection
- 70:30 train/test split
- Random Forest with n_estimators=100, max_depth=20
"""

import pickle
import pandas as pd
import numpy as np
import requests
import io
import zipfile
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    accuracy_score, 
    confusion_matrix,
    f1_score
)

# Import unified feature extractor and N-gram module
from src.analysis.lexical.features import extract_features
from src.analysis.lexical.ngram_features import TrigramFeatureExtractor

MODEL_PATH = "models/lexical_rf.pkl"
TRIGRAM_PATH = "models/trigram_extractor.pkl"
TOP_DOMAINS_PATH = "models/top_domains.pkl"

# ==========================================
# Part 1: Data Loading
# ==========================================

def load_phishtank_data(path: str = "data/Malicious_url/verified_online.csv", 
                        sample_size: int = 100000) -> list[str] | None:
    """Load malicious URLs from PhishTank CSV."""
    try:
        print(f"    Loading PhishTank data from {path}...")
        df = pd.read_csv(path)
        available = len(df)
        n = min(sample_size, available)
        urls = df["url"].sample(n=n, random_state=42).tolist()
        print(f"    PhishTank loaded: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"[!] Failed to load PhishTank: {e}")
        return None


def load_kaggle_data(path: str = "data/malicious_phish.csv") -> tuple[list[str], list[str]] | None:
    """
    Load Kaggle malicious URLs dataset.
    Dataset: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    Columns: 'url', 'type' (benign, defacement, phishing, malware)
    """
    try:
        if not os.path.exists(path):
            print(f"    Kaggle dataset not found at {path}, skipping...")
            return None
        print(f"    Loading Kaggle data from {path}...")
        df = pd.read_csv(path)
        malicious = df[df['type'] != 'benign']['url'].tolist()
        benign = df[df['type'] == 'benign']['url'].tolist()
        print(f"    Kaggle loaded: {len(malicious)} malicious, {len(benign)} benign")
        return malicious, benign
    except Exception as e:
        print(f"[!] Failed to load Kaggle data: {e}")
        return None


def load_fireeye_data(path: str = "data/fireeye_urls.csv") -> tuple[list[str], list[str]] | None:
    """
    Load FireEye combined dataset.
    Based on FireEye research methodology with ~5M URLs.
    Expected format: CSV with 'url' and 'label' columns (0=benign, 1=malicious)
    
    Sources include: OpenPhish, Alexa whitelist, FireEye malware intelligence
    Target ratio: 60% benign / 40% malicious
    """
    try:
        if not os.path.exists(path):
            print(f"    FireEye dataset not found at {path}, skipping...")
            return None
        print(f"    Loading FireEye data from {path}...")
        df = pd.read_csv(path)
        
        # Handle different column naming conventions
        if 'label' in df.columns:
            malicious = df[df['label'] == 1]['url'].tolist()
            benign = df[df['label'] == 0]['url'].tolist()
        elif 'type' in df.columns:
            malicious = df[df['type'] == 'malicious']['url'].tolist()
            benign = df[df['type'] == 'benign']['url'].tolist()
        elif 'is_malicious' in df.columns:
            malicious = df[df['is_malicious']]['url'].tolist()
            benign = df[~df['is_malicious']]['url'].tolist()
        else:
            print("    [!] Unknown column format in FireEye dataset")
            return None
            
        print(f"    FireEye loaded: {len(malicious)} malicious, {len(benign)} benign")
        return malicious, benign
    except Exception as e:
        print(f"[!] Failed to load FireEye data: {e}")
        return None


def load_tranco_data(sample_size: int = 100000) -> tuple[list[str], set[str]] | None:
    """
    Download Tranco top 1M domains (benign URLs).
    Returns tuple of (benign_urls, top_domains_set for feature engineering).
    """
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        print("    Downloading Tranco data...")
        r = requests.get(tranco_url, timeout=60)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        df = pd.read_csv(z.open("top-1m.csv"), header=None, names=["rank", "domain"])
        
        # Build top domains set for feature engineering
        top_domains_set = set(df["domain"].head(100000).tolist())
        
        # Extract benign URLs
        n = min(sample_size, len(df))
        benign_urls = ["http://" + d for d in df["domain"].head(n).tolist()]
        print(f"    Tranco loaded: {len(benign_urls)} URLs")
        
        return benign_urls, top_domains_set
    except Exception as e:
        print(f"[!] Failed to download Tranco: {e}")
        return None


def load_all_data(malicious_sample: int = 100000, 
                  benign_sample: int = 100000,
                  target_ratio: tuple[float, float] = (0.6, 0.4)) -> tuple[list[str], list[str], set[str]] | None:
    """
    Load data from all available sources.
    
    Args:
        malicious_sample: Target number of malicious URLs
        benign_sample: Target number of benign URLs
        target_ratio: Target ratio (benign, malicious) - default 60/40 per FireEye methodology
    
    Returns (malicious_urls, benign_urls, top_domains_set).
    """
    print("[*] Loading datasets from multiple sources...")
    print(f"    Target ratio: {target_ratio[0]:.0%} benign / {target_ratio[1]:.0%} malicious")
    
    malicious_urls: list[str] = []
    benign_urls: list[str] = []
    top_domains_set: set[str] = set()
    
    # 1. PhishTank (malicious)
    phish_urls = load_phishtank_data(sample_size=malicious_sample)
    if phish_urls:
        malicious_urls.extend(phish_urls)
    
    # 2. Kaggle (mixed)
    kaggle_result = load_kaggle_data()
    if kaggle_result:
        kaggle_mal, kaggle_ben = kaggle_result
        malicious_urls.extend(kaggle_mal[:malicious_sample // 2])
        benign_urls.extend(kaggle_ben[:benign_sample // 2])
    
    # 3. FireEye (mixed - 60/40 ratio)
    fireeye_result = load_fireeye_data()
    if fireeye_result:
        fireeye_mal, fireeye_ben = fireeye_result
        malicious_urls.extend(fireeye_mal[:malicious_sample // 2])
        benign_urls.extend(fireeye_ben[:benign_sample // 2])
    
    # 4. Tranco (benign)
    tranco_result = load_tranco_data(sample_size=benign_sample)
    if tranco_result:
        tranco_urls, top_domains_set = tranco_result
        benign_urls.extend(tranco_urls)
    
    if not malicious_urls or not benign_urls:
        print("[!] Failed to load sufficient data.")
        return None
    
    # Remove duplicates
    malicious_urls = list(set(malicious_urls))
    benign_urls = list(set(benign_urls))
    
    print(f"[*] Total loaded: {len(malicious_urls)} malicious, {len(benign_urls)} benign")
    
    return malicious_urls, benign_urls, top_domains_set


# ==========================================
# Part 2: Feature Engineering
# ==========================================

def extract_all_features(urls: list[str], 
                         labels: list[int],
                         trigram_extractor: TrigramFeatureExtractor | None = None,
                         fit_trigrams: bool = False) -> tuple[pd.DataFrame, np.ndarray, TrigramFeatureExtractor]:
    """
    Extract lexical and N-gram features from URLs.
    
    Args:
        urls: List of URL strings
        labels: Corresponding labels (0=benign, 1=malicious)
        trigram_extractor: Pre-fitted extractor or None to create new
        fit_trigrams: Whether to fit the trigram extractor on this data
    
    Returns:
        (feature_dataframe, labels_array, trigram_extractor)
    """
    print("[*] Extracting features (this may take a few minutes)...")
    
    # Initialize trigram extractor if needed
    if trigram_extractor is None:
        trigram_extractor = TrigramFeatureExtractor(top_k=500)
    
    # Fit trigrams on all URLs if requested
    if fit_trigrams:
        print("    Fitting trigram extractor...")
        trigram_extractor.fit(urls)
    
    data = []
    valid_labels = []
    
    for i, (url, label) in enumerate(zip(urls, labels)):
        try:
            # Extract lexical features
            feats = extract_features(url)
            
            # Extract trigram features
            if trigram_extractor.top_trigrams:
                trigram_feats = trigram_extractor.transform(url)
                feats.update(trigram_feats)
            
            data.append(feats)
            valid_labels.append(label)
            
            if (i + 1) % 10000 == 0:
                print(f"    Processed {i + 1}/{len(urls)} URLs...")
                
        except Exception:
            continue
    
    print(f"    Successfully extracted features for {len(data)} URLs")
    
    df = pd.DataFrame(data)
    y = np.array(valid_labels)
    
    return df, y, trigram_extractor


# ==========================================
# Part 3: Feature Selection
# ==========================================

def remove_correlated_features(df: pd.DataFrame, threshold: float = 0.75) -> pd.DataFrame:
    """
    Remove highly correlated features to reduce redundancy.
    
    Args:
        df: Feature DataFrame
        threshold: Correlation threshold (default 0.75)
    
    Returns:
        DataFrame with correlated features removed
    """
    print(f"[*] Removing features with correlation > {threshold}...")
    
    # Calculate correlation matrix
    corr_matrix = df.corr().abs()
    
    # Select upper triangle of correlation matrix
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    
    # Find features with high correlation
    to_drop = [column for column in upper.columns if any(upper[column] > threshold)]
    
    print(f"    Dropping {len(to_drop)} highly correlated features")
    
    return df.drop(columns=to_drop)


# ==========================================
# Part 4: Data Balancing
# ==========================================

def balance_data_smote(X: pd.DataFrame, y: np.ndarray) -> tuple[pd.DataFrame, np.ndarray]:
    """
    Balance dataset using SMOTE (Synthetic Minority Over-sampling Technique).
    
    Args:
        X: Feature DataFrame
        y: Labels array
    
    Returns:
        Balanced (X, y) tuple
    """
    try:
        from imblearn.over_sampling import SMOTE
        
        print("[*] Balancing data with SMOTE...")
        
        # Check class distribution
        unique, counts = np.unique(y, return_counts=True)
        print(f"    Before SMOTE: {dict(zip(unique, counts))}")
        
        # Apply SMOTE if classes are imbalanced
        if counts[0] != counts[1]:
            smote = SMOTE(random_state=42)
            X_resampled, y_resampled = smote.fit_resample(X, y)
            
            unique, counts = np.unique(y_resampled, return_counts=True)
            print(f"    After SMOTE: {dict(zip(unique, counts))}")
            
            return pd.DataFrame(X_resampled, columns=X.columns), y_resampled
        else:
            print("    Data already balanced, skipping SMOTE")
            return X, y
            
    except ImportError:
        print("[!] imbalanced-learn not installed. Skipping SMOTE.")
        print("    Install with: uv add imbalanced-learn")
        return X, y


# ==========================================
# Part 5: Main Training Flow
# ==========================================

def train_model():
    """
    Main training function following literature recommendations:
    - 70:30 train/test split (per paper)
    - Random Forest with n_estimators=100, max_depth=20
    - Feature selection via correlation analysis
    - SMOTE for data balancing
    """
    # 1. Load data from all sources
    result = load_all_data()
    if result is None:
        print("[!] Failed to load data. Exiting.")
        return
    
    malicious_urls, benign_urls, top_domains_set = result
    
    # 2. Prepare URLs and labels
    all_urls = malicious_urls + benign_urls
    all_labels = [1] * len(malicious_urls) + [0] * len(benign_urls)
    
    # 3. Extract features (lexical + N-gram)
    df, y, trigram_extractor = extract_all_features(
        all_urls, all_labels, fit_trigrams=True
    )
    
    print(f"[*] Initial feature matrix shape: {df.shape}")
    
    # 4. Feature selection - remove highly correlated features
    df_filtered = remove_correlated_features(df, threshold=0.75)
    print(f"[*] After correlation filter: {df_filtered.shape}")
    
    # 5. Split data (70:30 as per literature)
    X_train, X_test, y_train, y_test = train_test_split(
        df_filtered, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # 6. Balance training data with SMOTE
    X_train_balanced, y_train_balanced = balance_data_smote(X_train, y_train)
    
    # 7. Train Random Forest model
    print("[*] Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"  # Additional class weighting
    )
    rf_model.fit(X_train_balanced, y_train_balanced)
    
    # 8. Evaluate model
    y_pred = rf_model.predict(X_test)
    
    print("\n" + "=" * 60)
    print("MODEL EVALUATION RESULTS")
    print("=" * 60)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f} ({accuracy:.2%})")
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print("\nConfusion Matrix:")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")
    
    # False Negative Rate (critical for security)
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    print(f"\nFalse Negative Rate (FNR): {fnr:.4f} ({fnr:.2%})")
    print(f"  Target: < 1% | Status: {'✓ PASS' if fnr < 0.01 else '✗ NEEDS IMPROVEMENT'}")
    
    # F1 Score
    f1 = f1_score(y_test, y_pred)
    print(f"\nF1 Score: {f1:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
    
    # Feature Importance
    feature_importance = pd.DataFrame({
        "feature": df_filtered.columns,
        "importance": rf_model.feature_importances_
    }).sort_values("importance", ascending=False)
    
    print("\n" + "=" * 60)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("=" * 60)
    print(feature_importance.head(15).to_string(index=False))
    
    # 9. Save model artifacts
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    
    # Save model with feature names for consistent inference
    artifacts = {
        "model": rf_model,
        "feature_names": list(df_filtered.columns),
        "top_domains_set": top_domains_set
    }
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(artifacts, f)
    print(f"\n[+] Model saved to {MODEL_PATH}")
    
    # Save trigram extractor
    trigram_extractor.save(TRIGRAM_PATH)
    print(f"[+] Trigram extractor saved to {TRIGRAM_PATH}")
    
    # 10. Validation with sample URLs
    print("\n" + "=" * 60)
    print("SAMPLE PREDICTIONS")
    print("=" * 60)
    
    test_urls = [
        ("google.com", "Expected: Benign"),
        ("facebook.com", "Expected: Benign"),
        ("xkyz1234abcqwe.com", "Expected: Malicious"),
        ("secure-login-bank.xyz/account/verify", "Expected: Malicious"),
        ("paypal-update.com/login.php", "Expected: Malicious"),
    ]
    
    for url, expected in test_urls:
        try:
            feats = extract_features(url)
            if trigram_extractor.top_trigrams:
                feats.update(trigram_extractor.transform(url))
            
            # Align features with training columns
            feat_df = pd.DataFrame([feats])
            feat_df = feat_df.reindex(columns=df_filtered.columns, fill_value=0)
            
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
