# core/report_generator.py

import os
import json
from core.behavior_summary import generate_human_readable_summary

def sanitize(obj):
    if obj is ...:
        return "..."
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    if isinstance(obj, set):
        return [sanitize(x) for x in obj]
    return obj

def generate_json_report(file_path, features, functions, explanation, family, confidence, sha256):
    base = os.path.basename(file_path)
    out = f"reports/{base}_report.json"
    os.makedirs("reports", exist_ok=True)

    summary = generate_human_readable_summary(features)

    report = {
        "file": file_path,
        "sha256": sha256,
        "prediction": {
            "malware_family": family,
            "confidence": round(confidence, 2)
        },
        "summary": {
            "predicted_family": family,
            "confidence": round(confidence, 2),
            "likely_behaviors": summary["likely_behaviors"],
            "risk_level": summary["risk_level"]
        },
        "technical_details": {
            "features_extracted": sanitize(features),
            "functions_found": sanitize(functions),
            "explanation": explanation
        }
    }

    with open(out, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Report written to: {out}")
