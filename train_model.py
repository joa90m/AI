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

from core.features import extract_features_from_file


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --- Configurable ---
BASE_DIR = "dataset"
MODEL_PATH = "models/malware_pipeline.pkl"
PRIMARY_FEATURES = [
    'HTTP', 'FTP', 'SMTP', 'DNS',
    'os.system', 'subprocess', 'eval', 'exec', 'open',
    'socket', 'shutil', 'ctypes', 'getenv'
]
RANDOM_STATE = 42
# --------------------

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
        strings = re.findall(r'[\x20-\x7E]{%d,}' % min_len, raw)
        return strings
    except Exception:
        return []

def vectorize(feats, file_path):
    """
    Build a numeric feature vector for a single sample.
    - Counts occurrences of PRIMARY_FEATURES in combined lists (protocols/permissions/files/strings/imports)
    - Adds file_size, entropy, num_strings, num_imports
    """
    combined = []
    for key in ("protocols", "permissions", "files", "strings", "imports"):
        v = feats.get(key, [])
        if isinstance(v, list):
            combined += [str(x) for x in v]
        elif isinstance(v, (str, int)):
            combined.append(str(v))

    counts = [combined.count(f) for f in PRIMARY_FEATURES]

    try:
        file_size = os.path.getsize(file_path)
    except Exception:
        file_size = 0

    entropy = shannon_entropy(file_path)

    # prefer strings from extractor; fallback to scanning file
    if isinstance(feats.get("strings"), list) and feats.get("strings"):
        num_strings = len(feats.get("strings"))
    else:
        num_strings = len(extract_printable_strings(file_path))

    imports = feats.get("imports", [])
    num_imports = len(imports) if isinstance(imports, list) else 0

    # final vector: primary counts + derived numeric features
    return counts + [file_size, entropy, num_strings, num_imports]

def main():
    X = []
    y = []
    sample_paths = []

    logging.info("[+] Scanning dataset directory: %s", BASE_DIR)
    if not os.path.isdir(BASE_DIR):
        logging.error("[!] dataset folder not found: %s", BASE_DIR)
        return

    for family in os.listdir(BASE_DIR):
        family_dir = os.path.join(BASE_DIR, family)
        if not os.path.isdir(family_dir):
            continue
        for fname in os.listdir(family_dir):
            file_path = os.path.join(family_dir, fname)
            try:
                feats = extract_features_from_file(file_path)
                if not feats or not isinstance(feats, dict) or feats.get("unsupported", False):
                    logging.debug("[ ] Unsupported or empty features for %s", file_path)
                    continue
                vec = vectorize(feats, file_path)
                X.append(vec)
                y.append(family)
                sample_paths.append(file_path)
            except Exception as e:
                logging.warning("[!] Skipped %s due to error: %s", file_path, e)

    if not X:
        logging.error("[!] No valid features found. Ensure 'extract_features_from_file' returns supported dicts.")
        return

    X = np.array(X)
    y = np.array(y)
    logging.info("[+] Collected %d samples across %d classes", len(y), len(set(y)))

    # --- Balance classes by oversampling minority classes to match the largest class ---
    by_label = defaultdict(list)
    for xv, label in zip(X, y):
        by_label[label].append(xv)

    max_count = max(len(lst) for lst in by_label.values())
    X_balanced = []
    y_balanced = []
    for label, items in by_label.items():
        if len(items) < max_count:
            items_res = resample(items, replace=True, n_samples=max_count, random_state=RANDOM_STATE)
        else:
            items_res = items
        X_balanced.extend(items_res)
        y_balanced.extend([label] * len(items_res))

    X = np.array(X_balanced)
    y_str = np.array(y_balanced)
    logging.info("[+] Balanced dataset to %d samples per class (total %d)", max_count, len(y_str))

    # Encode labels and scale features
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_str)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
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
    logging.info("[+] Confusion matrix (rows=true, cols=pred):\n%s", cm)

    # cross-validation (stratified)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scores = cross_val_score(model, X_scaled, y, cv=cv, scoring="accuracy", n_jobs=-1)
    logging.info("[+] 5-fold CV accuracy: %.4f ± %.4f", scores.mean(), scores.std())

    # Save pipeline (model + scaler + label encoder)
    os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "label_encoder": label_encoder}, MODEL_PATH)
    logging.info("[+] Saved pipeline to %s", MODEL_PATH)

    # Example: how to load and use model (low-confidence handling)
    logging.info("[+] Example prediction on test set with low-confidence threshold")
    probs = model.predict_proba(X_test)
    thresh = 0.5
    for i in range(min(5, len(X_test))):
        prob = probs[i]
        pred_idx = prob.argmax()
        pred_label = label_encoder.inverse_transform([pred_idx])[0]
        confidence = prob[pred_idx]
        if confidence < thresh:
            logging.info("Sample %d -> Prediction: Unknown (low confidence %.2f)", i, confidence)
        else:
            logging.info("Sample %d -> Prediction: %s (confidence %.2f)", i, pred_label, confidence)

if __name__ == "__main__":
    main()
# Save PRIMARY_FEATURES for classifier.py
import json
features_path = os.path.join(os.path.dirname(MODEL_PATH), "primary_features.json")
with open(features_path, "w") as f:
    json.dump(PRIMARY_FEATURES, f)
logging.info("[+] Saved PRIMARY_FEATURES to %s", features_path)
