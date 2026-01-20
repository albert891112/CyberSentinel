"""
Lexical Feature-based Malicious URL Detection Model Training Script

Docker-Optimized Version:
- URL-based data loading (PhishTank, Kaggle via kagglehub, Tranco)
- Scheduled daily retraining at 00:00
- Multiprocessing feature extraction for speed
- Memory management (GC)
- NaN/Inf handling for numerical stability

Environment Variables:
- RUN_IMMEDIATELY: Run training immediately on startup (default: true)
"""

import pickle
import pandas as pd
import numpy as np
import requests
import io
import zipfile
import os
import gc
import time
from datetime import datetime, timedelta
from functools import partial
from concurrent.futures import ProcessPoolExecutor

import kagglehub
from kagglehub import KaggleDatasetAdapter

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
    f1_score,
)

# Import local modules
from features import extract_features
from ngram_features import TrigramFeatureExtractor

MODEL_PATH = "models/lexical_rf.pkl"
TRIGRAM_PATH = "models/trigram_extractor.pkl"

# Data source URLs
PHISHTANK_URL = "http://data.staging.phishtank.com/data/online-valid.csv"
KAGGLE_DATASET = "moutasmtamimi/malicious-url-detection-dataset-enhanced-2026"


def strip_protocol(url: str) -> str:
    """Remove http:// or https:// prefix from URL."""
    if url.startswith("https://"):
        return url[8:]
    elif url.startswith("http://"):
        return url[7:]
    return url


# ==========================================
# Part 1: Data Loading
# ==========================================


def load_phishtank_data(sample_size: int = 100000) -> list[str] | None:
    """Load malicious URLs from PhishTank."""
    try:
        print(f"    Fetching PhishTank data from {PHISHTANK_URL}...")
        response = requests.get(PHISHTANK_URL, timeout=120)
        response.raise_for_status()
        
        df = pd.read_csv(io.StringIO(response.text))
        available = len(df)
        n = min(sample_size, available)
        urls = df["url"].sample(n=n, random_state=42).tolist()
        print(f"    PhishTank loaded: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"[!] Failed to load PhishTank: {e}")
        return None


def load_kaggle_data() -> tuple[list[str], list[str]] | None:
    """Load Kaggle malicious URLs dataset via kagglehub."""
    try:
        print(f"    Loading Kaggle dataset: {KAGGLE_DATASET}...")
        
        df = kagglehub.load_dataset(
            KaggleDatasetAdapter.PANDAS,
            KAGGLE_DATASET,
            "",  # Load default file
        )
        
        # Handle different column naming conventions
        if "type" in df.columns:
            malicious = df[df["type"] != "benign"]["url"].tolist()
            benign = df[df["type"] == "benign"]["url"].tolist()
        elif "label" in df.columns:
            malicious = df[df["label"] == 1]["url"].tolist()
            benign = df[df["label"] == 0]["url"].tolist()
        elif "is_malicious" in df.columns:
            malicious = df[df["is_malicious"]]["url"].tolist()
            benign = df[~df["is_malicious"]]["url"].tolist()
        else:
            print("    [!] Unknown column format in Kaggle dataset")
            print(f"    Available columns: {df.columns.tolist()}")
            return None
            
        print(f"    Kaggle loaded: {len(malicious)} malicious, {len(benign)} benign")
        return malicious, benign
    except Exception as e:
        print(f"[!] Failed to load Kaggle data: {e}")
        return None


def load_tranco_data(sample_size: int = 100000) -> tuple[list[str], set[str]] | None:
    """Download Tranco top 1M domains (benign URLs)."""
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        print("    Downloading Tranco data...")
        r = requests.get(tranco_url, timeout=60)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        df = pd.read_csv(z.open("top-1m.csv"), header=None, names=["rank", "domain"])

        # Build top domains set for feature engineering
        top_domains_set = set(df["domain"].head(100000).tolist())

        # Extract benign URLs (no protocol prefix)
        n = min(sample_size, len(df))
        benign_urls = df["domain"].head(n).tolist()
        print(f"    Tranco loaded: {len(benign_urls)} URLs")

        return benign_urls, top_domains_set
    except Exception as e:
        print(f"[!] Failed to download Tranco: {e}")
        return None


def load_all_data(
    malicious_sample: int = 100000, benign_sample: int = 150000
) -> tuple[list[str], list[str], set[str]] | None:
    """Load data from all available sources with fallback logic."""
    print("[*] Loading datasets from multiple sources...")

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
        malicious_urls.extend(kaggle_mal[: malicious_sample])
        benign_urls.extend(kaggle_ben[: benign_sample])

    # 3. Tranco (benign) - Always available from public URL
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

    print(
        f"[*] Total loaded: {len(malicious_urls)} malicious, {len(benign_urls)} benign"
    )

    return malicious_urls, benign_urls, top_domains_set


# ==========================================
# Part 2: Feature Engineering & Parallelism
# ==========================================


def _process_chunk(
    chunk_urls: list[str],
    top_domains: set[str],
    trigram_extractor: TrigramFeatureExtractor,
) -> list[dict]:
    """Helper function to process a batch of URLs in a separate process."""
    data = []
    for url in chunk_urls:
        try:
            # Pass top_domains for reputation check
            feats = extract_features(url, top_domains=top_domains)

            # Trigrams (Transform only - fitting happens in main process)
            if trigram_extractor.top_trigrams:
                feats.update(trigram_extractor.transform(url))

            data.append(feats)
        except Exception:
            continue
    return data


def extract_features_parallel(
    urls: list[str],
    trigram_extractor: TrigramFeatureExtractor,
    top_domains: set[str],
    fit_trigrams: bool = False,
) -> pd.DataFrame:
    """
    Extract features using multiprocessing for performance.
    Handles Fitting (Main Process) vs Transform (Parallel).
    Also performs numerical cleaning (NaN/Inf).
    """
    # 1. Fit if needed (Must be done in main process before forking)
    if fit_trigrams:
        print("    [Scaling] Fitting Trigram Extractor (Main Process)...")
        trigram_extractor.fit(urls)

    # 2. Parallel Extraction
    print(f"    [Parallel] Extracting features for {len(urls)} URLs...")

    # Logic to split work
    n_workers = max(1, (os.cpu_count() or 1) - 1)
    if len(urls) < 1000:
        n_workers = 1  # Don't spin up processes for small data

    chunk_size = max(1, len(urls) // n_workers)
    chunks = [urls[i : i + chunk_size] for i in range(0, len(urls), chunk_size)]

    # Bind arguments for worker
    func = partial(
        _process_chunk, top_domains=top_domains, trigram_extractor=trigram_extractor
    )

    results = []
    if n_workers > 1:
        with ProcessPoolExecutor(max_workers=n_workers) as executor:
            for i, chunk_res in enumerate(executor.map(func, chunks)):
                results.extend(chunk_res)
                if (i + 1) % 2 == 0:
                    print(
                        f"      Processed {min((i+1)*chunk_size, len(urls))}/{len(urls)}..."
                    )
    else:
        # Fallback for single process
        results = _process_chunk(urls, top_domains, trigram_extractor)

    # 3. Create DataFrame and Clean
    df = pd.DataFrame(results)

    # Clean NaN and Infinite values for numerical stability
    df = df.replace([np.inf, -np.inf], 0).fillna(0)

    return df


def balance_data_smote(
    X: pd.DataFrame, y: np.ndarray
) -> tuple[pd.DataFrame, np.ndarray]:
    """Balance dataset using SMOTE on training data only."""
    try:
        from imblearn.over_sampling import SMOTE

        print("[*] Balancing data with SMOTE...")

        unique, counts = np.unique(y, return_counts=True)
        print(f"    Before SMOTE: {dict(zip(unique, counts))}")

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
        return X, y


# ==========================================
# Part 3: Main Training Flow
# ==========================================


def train_model():
    """
    Production-Grade Training Pipeline
    """
    print(f"\n{'='*60}")
    print(f"TRAINING STARTED AT: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # 1. Load data
    result = load_all_data()
    if result is None:
        print("[!] Training aborted: No data available.")
        return
    malicious_urls, benign_urls, top_domains_set = result

    all_urls = np.array(malicious_urls + benign_urls)
    all_labels = np.array([1] * len(malicious_urls) + [0] * len(benign_urls))

    # Memory management: Clean up raw lists immediately
    print(f"    [Memory] Cleaning up raw lists...")
    del malicious_urls, benign_urls
    gc.collect()

    # -----------------------------------------------------------------
    # CRITICAL FIX: Split BEFORE Feature Engineering & Selection
    # -----------------------------------------------------------------
    print("[*] Splitting data (70/30) BEFORE feature extraction...")
    X_train_urls, X_test_urls, y_train, y_test = train_test_split(
        all_urls, all_labels, test_size=0.3, random_state=42, stratify=all_labels
    )

    # Memory management: Source array no longer needed
    del all_urls, all_labels
    gc.collect()

    # 2. Extract Features (Fit Trigram ONLY on Train)
    # Joshi et al. (2019) Table 3: 1000 trigrams gives optimal FNR (0.38%)
    trigram_extractor = TrigramFeatureExtractor(top_k=1000)

    print(f"[*] Processing Training Set ({len(X_train_urls)} URLs)...")
    X_train_df = extract_features_parallel(
        list(X_train_urls), trigram_extractor, top_domains_set, fit_trigrams=True
    )

    print(f"[*] Processing Test Set ({len(X_test_urls)} URLs)...")
    # Test set: Transform ONLY, NO FIT
    X_test_df = extract_features_parallel(
        list(X_test_urls), trigram_extractor, top_domains_set, fit_trigrams=False
    )

    # Align Test columns to Train
    X_test_df = X_test_df.reindex(columns=X_train_df.columns, fill_value=0)

    # -----------------------------------------------------------------
    # CRITICAL FIX: Feature Selection on TRAIN only
    # -----------------------------------------------------------------
    print("[*] Selecting features based on Training Set correlation...")
    corr_matrix = X_train_df.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [column for column in upper.columns if any(upper[column] > 0.75)]

    print(f"    Dropping {len(to_drop)} correlated features.")
    X_train_filtered = X_train_df.drop(columns=to_drop)
    X_test_filtered = X_test_df.drop(columns=to_drop)

    # -----------------------------------------------------------------
    # ADVANCED FEATURE SELECTION (SFM)
    # Based on Abdul Hamid et al., SFM significantly improves performance
    # by removing noisy N-grams that correlation analysis misses.
    # -----------------------------------------------------------------
    print("[*] Applying SelectFromModel (SFM) for robust feature selection...")

    # Use a lightweight RF for selection to avoid overfitting before main training
    selector = SelectFromModel(
        RandomForestClassifier(
            n_estimators=50, max_depth=10, random_state=42, n_jobs=-1
        ),
        threshold="mean",  # Select features with importance > mean importance
    )

    # Fit selector on the filtered (uncorrelated) training data
    selector.fit(X_train_filtered, y_train)

    # Transform both Train and Test
    X_train_selected = pd.DataFrame(
        selector.transform(X_train_filtered),
        columns=X_train_filtered.columns[selector.get_support()],
    )
    X_test_selected = pd.DataFrame(
        selector.transform(X_test_filtered),
        columns=X_test_filtered.columns[selector.get_support()],
    )

    print(
        f"    Features reduced from {X_train_filtered.shape[1]} to {X_train_selected.shape[1]} via SFM."
    )

    # -----------------------------------------------------------------
    # CRITICAL FIX: Min-Max Scaling (per Literature)
    # -----------------------------------------------------------------
    print("[*] Applying Min-Max Scaling (0-1)...")
    scaler = MinMaxScaler()

    # Fit on Train, Transform on Train & Test (using selected features)
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train_selected), columns=X_train_selected.columns
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test_selected), columns=X_test_selected.columns
    )

    # 4. SMOTE Balancing
    X_train_final, y_train_final = balance_data_smote(X_train_scaled, y_train)

    # 5. Train Model
    print(f"[*] Training Random Forest on {len(X_train_final)} samples...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    rf_model.fit(X_train_final, y_train_final)

    # 6. Evaluate
    print("\n" + "=" * 60)
    print("MODEL EVALUATION RESULTS")
    print("=" * 60)

    y_pred = rf_model.predict(X_test_scaled)

    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    f1 = f1_score(y_test, y_pred)

    print(f"Accuracy: {accuracy:.4f} ({accuracy:.2%})")
    print("\nConfusion Matrix:")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")
    print(f"\nFalse Negative Rate (FNR): {fnr:.4f} ({fnr:.2%})")
    print(
        f"  Target: < 1% | Status: {'✓ PASS' if fnr < 0.01 else '✗ NEEDS IMPROVEMENT'}"
    )
    print(f"F1 Score: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # Feature Importance (based on selected features after SFM)
    feature_importance = pd.DataFrame(
        {
            "feature": X_train_selected.columns,
            "importance": rf_model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)

    print("\nTOP 15 MOST IMPORTANT FEATURES:")
    print(feature_importance.head(15).to_string(index=False))

    # 7. Save model artifacts
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    artifacts = {
        "model": rf_model,
        "scaler": scaler,
        "selector": selector,  # Added for inference-time feature selection
        "feature_names": list(X_train_filtered.columns),  # Pre-SFM features
        "selected_features": list(X_train_selected.columns),  # Final features used
        "dropped_features": to_drop,
        "top_domains_set": top_domains_set,
    }

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(artifacts, f)
    print(f"\n[+] Model saved to {MODEL_PATH}")

    trigram_extractor.save(TRIGRAM_PATH)
    print(f"[+] Trigram extractor saved to {TRIGRAM_PATH}")
    
    print(f"\n{'='*60}")
    print(f"TRAINING COMPLETED AT: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")


def schedule_loop():
    """
    Run training on a schedule: every day at 00:00.
    Uses a while loop to continuously check and wait for the next scheduled run.
    """
    print("[*] Starting scheduled training loop...")
    print("[*] Training will run every day at 00:00")
    
    while True:
        now = datetime.now()
        
        # Calculate next run time (00:00 next day)
        next_run = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if now >= next_run:
            next_run += timedelta(days=1)
        
        # Calculate sleep duration
        sleep_seconds = (next_run - now).total_seconds()
        
        print(f"[*] Current time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Next training scheduled at: {next_run.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Sleeping for {sleep_seconds/3600:.2f} hours...")
        
        # Sleep until next scheduled time
        time.sleep(sleep_seconds)
        
        # Run training
        try:
            train_model()
        except Exception as e:
            print(f"[!] Training failed with error: {e}")
            print("[*] Will retry at next scheduled time...")


if __name__ == "__main__":
    # Windows support for multiprocessing
    from multiprocessing import freeze_support
    freeze_support()
    
    # Check if we should run immediately
    run_immediately = os.environ.get("RUN_IMMEDIATELY", "true").lower() == "true"
    
    if run_immediately:
        print("[*] RUN_IMMEDIATELY=true, starting initial training...")
        try:
            train_model()
        except Exception as e:
            print(f"[!] Initial training failed: {e}")
    
    # Start the scheduling loop
    schedule_loop()
