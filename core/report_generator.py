# core/report_generator.py

import os
import json

def generate_json_report(file_path, features, functions, explanation, family, confidence, sha256):
    base_name = os.path.basename(file_path)
    report_path = f"reports/{base_name}_report.json"
    os.makedirs("reports", exist_ok=True)

    report = {
        "file": file_path,
        "sha256": sha256,
        "predicted_family": family,
        "confidence": round(confidence, 2),
        "features": features,
        "functions": functions,
        "explanation": explanation,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"[+] Report written to: {report_path}") 