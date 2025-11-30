# train_model.py
import os
import re
import math
import joblib
import logging
from collections import Counter, defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils import resample

from core.features import extract_features_from_file, PRIMARY_FEATURES  # Import primary features

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = "dataset"
MODEL_PATH = "models/malware_pipeline.pkl"
RANDOM_STATE = 42


def shannon_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        counts = Counter(data)
        probs = [c / len(data) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs if p > 0)
    except Exception:
        return 0.0


def extract_printable_strings(file_path, min_len=4):
    try:
        with open(file_path, "rb") as f:
            raw = f.read().decode("latin1")
        return re.findall(r'[\x20-\x7E]{%d,}' % min_len, raw)
    except Exception:
        return []


def vectorize(feats, file_path):
    """
    Build numeric vector for a sample.
    - Count occurrences of PRIMARY_FEATURES from combined keys
    - Add derived features: file size, entropy, num_strings, num_imports, num_functions
    """
    combined = []

    # Flatten features into a list for counting primary features
    for key in ["HTTP", "FTP", "SMTP", "DNS",
                "os.system", "subprocess", "eval", "exec",
                "open", "socket", "shutil", "ctypes", "getenv"]:
        if key in feats:
            combined.extend([key] * feats.get(key, 0))

    # Count functions and imports (optional)
    funcs = feats.get("functions", [])
    imports = feats.get("imports", [])
    combined.extend(funcs)
    combined.extend(imports)

    # Vectorize primary features
    counts = [combined.count(f) for f in PRIMARY_FEATURES]

    # Derived numeric features
    try:
        file_size = os.path.getsize(file_path)
    except Exception:
        file_size = 0

    entropy = shannon_entropy(file_path)

    # Number of strings
    num_strings = len(feats.get("strings", [])) or len(extract_printable_strings(file_path))

    # Number of imports / functions
    num_imports = len(imports)
    num_functions = len(funcs)
    num_params = sum(len(p) for p in feats.get("params", {}).values()) if feats.get("params") else 0

    # Final vector
    return counts + [file_size, entropy, num_strings, num_imports, num_functions, num_params]


def main():
    X = []
    y = []

    logging.info("[+] Scanning dataset: %s", BASE_DIR)
    if not os.path.isdir(BASE_DIR):
        logging.error("[!] Dataset folder not found")
        return

    for family in os.listdir(BASE_DIR):
        family_dir = os.path.join(BASE_DIR, family)
        if not os.path.isdir(family_dir):
            continue
        for fname in os.listdir(family_dir):
            file_path = os.path.join(family_dir, fname)
            try:
                feats = extract_features_from_file(file_path)
                if not feats or not isinstance(feats, dict):
                    continue
                vec = vectorize(feats, file_path)
                X.append(vec)
                y.append(family)
            except Exception as e:
                logging.warning("[!] Skipped %s: %s", file_path, e)

    if not X:
        logging.error("[!] No valid features found")
        return

    X = np.array(X)
    y = np.array(y)
    logging.info("[+] Collected %d samples across %d classes", len(y), len(set(y)))

    # --- Balance classes ---
    by_label = defaultdict(list)
    for xv, label in zip(X, y):
        by_label[label].append(xv)

    max_count = max(len(lst) for lst in by_label.values())
    X_balanced, y_balanced = [], []
    for label, items in by_label.items():
        items_res = resample(items, replace=True, n_samples=max_count, random_state=RANDOM_STATE) \
            if len(items) < max_count else items
        X_balanced.extend(items_res)
        y_balanced.extend([label] * len(items_res))

    X = np.array(X_balanced)
    y_str = np.array(y_balanced)
    logging.info("[+] Balanced dataset to %d per class (total %d)", max_count, len(y_str))

    # Encode and scale
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_str)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    logging.info("[+] Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_test_names = label_encoder.inverse_transform(y_test)
    y_pred_names = label_encoder.inverse_transform(y_pred)
    logging.info("\n" + classification_report(y_test_names, y_pred_names))
    cm = confusion_matrix(y_test_names, y_pred_names, labels=label_encoder.classes_)
    logging.info("[+] Confusion matrix:\n%s", cm)

    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(model, X_scaled, y, cv=cv, scoring="accuracy", n_jobs=-1)
    logging.info("[+] 5-fold CV accuracy: %.4f ± %.4f", scores.mean(), scores.std())

    # Save pipeline
    os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "label_encoder": label_encoder}, MODEL_PATH)
    logging.info("[+] Saved pipeline to %s", MODEL_PATH)

    # Save PRIMARY_FEATURES for later use
    import json
    features_path = os.path.join(os.path.dirname(MODEL_PATH), "primary_features.json")
    with open(features_path, "w") as f:
        json.dump(PRIMARY_FEATURES, f)
    logging.info("[+] Saved PRIMARY_FEATURES to %s", features_path)


if __name__ == "__main__":
    main()
