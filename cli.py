import argparse
import json
from core.features import extract_features_from_file
from core.classifier import predict_family, predict_proba
from core.parser import extract_functions
from core.deobfuscator import explain_code
from core.report_generator import generate_json_report
from core.utils import get_sha256

def predict(file_path):
    print(f"[+] Analyzing {file_path}")
    features = extract_features_from_file(file_path)

    if not features:
        print("[!] No features extracted. Unsupported or binary-only file.")
        return

    family = predict_family(features, file_path)
    confidence = predict_proba(features, file_path)

    try:
        with open(file_path, "r", errors="ignore") as f:
            code = f.read()
            functions = extract_functions(code)
            explanation = explain_code(code)
    except Exception:
        functions = []
        explanation = "Binary file – no readable Python source code."

    sha256 = get_sha256(file_path)
    generate_json_report(file_path, features, functions, explanation, family, confidence, sha256)
    print(f"[+] Predicted Malware Family: {family} (Confidence: {confidence:.2f})")
    print("[+] JSON Report generated.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="Path to malware sample file")
    args = parser.parse_args()
    predict(args.file)
