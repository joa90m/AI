import argparse
from core.features import extract_features_from_file
from core.classifier import predict_family, predict_proba
from core.parser import extract_functions
from core.deobfuscator import explain_code
from core.report_generator import generate_json_report
from core.utils import get_sha256

def format_features(raw_features):
    """
    Convert raw extracted features into a dictionary compatible with classifier.
    Ensures all keys exist and sets are converted to lists.
    """
    feature_dict = {}

    if not isinstance(raw_features, dict):
        # If it's a set or list, wrap it as a dictionary under a default key
        raw_features = {"strings": list(raw_features)}

    for key in ("protocols", "permissions", "files", "strings", "imports"):
        value = raw_features.get(key, [])
        # Convert sets to lists
        if isinstance(value, set):
            value = list(value)
        feature_dict[key] = value

    return feature_dict


def predict(file_path):
    print(f"[+] Analyzing {file_path}")

    # Step 1: Extract features
    raw_features = extract_features_from_file(file_path)
    if not raw_features:
        print("[!] No features extracted. Unsupported or binary-only file.")
        raw_features = {}  # fallback to empty
    features = format_features(raw_features)

    # Step 2: Model prediction
    family = predict_family(features, file_path)
    confidence = predict_proba(features, file_path)

    # Step 3: Extract code functions & explanations if file is Python
    try:
        with open(file_path, "r", errors="ignore") as f:
            code = f.read()
            functions = extract_functions(code)
            explanation = explain_code(code)
    except Exception:
        functions = []
        explanation = "Binary executable – static code explanation not available."


    # Step 4: SHA256
    sha256 = get_sha256(file_path)

    # Step 5: Generate report
    generate_json_report(file_path, features, functions, explanation, family, confidence, sha256)

    print(f"[+] Predicted Malware Family: {family} (Confidence: {confidence:.2f})")
    print("[+] JSON Report generated.")

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware analyzer")
    parser.add_argument("--file", required=True, help="Path to malware sample file")
    args = parser.parse_args()
    predict(args.file)
