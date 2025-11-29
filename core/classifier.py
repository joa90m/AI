# core/classifier.py

import joblib
import os
import json
from core.utils import shannon_entropy, extract_printable_strings

MODEL_PATH = os.path.join(os.path.dirname(__file__), '../models/malware_pipeline.pkl')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '../models/primary_features.json')

# Load model/scaler/encoder
try:
    pipeline = joblib.load(MODEL_PATH)
    model = pipeline["model"]
    scaler = pipeline["scaler"]
    label_encoder = pipeline["label_encoder"]
except Exception:
    model = None
    scaler = None
    label_encoder = None

# Load features used during training
try:
    with open(FEATURES_PATH, "r") as f:
        all_features = json.load(f)
except Exception:
    all_features = []
    print("[!] Warning: Could not load primary_features.json. Feature mismatch may occur.")

def extract_vector(features, file_path):
    """
    Create the same feature vector layout as training (train_model.vectorize).
    """
    combined = []
    for key in ("protocols", "permissions", "files", "strings", "imports"):
        v = features.get(key, [])
        if isinstance(v, list):
            combined += [str(x) for x in v]
        elif isinstance(v, (str, int)):
            combined.append(str(v))

    counts = [combined.count(f) for f in all_features]

    try:
        file_size = os.path.getsize(file_path)
    except Exception:
        file_size = 0

    entropy = shannon_entropy(file_path)

    # prefer strings from extractor; fallback to scanning file
    if isinstance(features.get("strings"), list) and features.get("strings"):
        num_strings = len(features.get("strings"))
    else:
        num_strings = len(extract_printable_strings(file_path))

    imports = features.get("imports", [])
    num_imports = len(imports) if isinstance(imports, list) else 0

    return counts + [file_size, entropy, num_strings, num_imports]

def predict_family(features, file_path):
    if model is None or scaler is None or label_encoder is None:
        return "Unknown (Model not loaded)"
    try:
        vector = extract_vector(features, file_path)
        vector_scaled = scaler.transform([vector])
        return label_encoder.inverse_transform(model.predict(vector_scaled))[0]
    except Exception as e:
        print(f"[!] Prediction error: {e}")
        return "Unknown (Prediction error)"

def predict_proba(features, file_path):
    if model is None or scaler is None:
        return 0.0
    try:
        vector = extract_vector(features, file_path)
        vector_scaled = scaler.transform([vector])
        return max(model.predict_proba(vector_scaled)[0])
    except Exception as e:
        print(f"[!] Probability prediction error: {e}")
        return 0.0
