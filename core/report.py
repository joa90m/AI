def generate_report(file_path, features, family_prediction):
    report = f"""
==== Malware Report for {file_path} ====

🔍 Predicted Malware Family: {family_prediction}

📡 Protocols Detected:
{', '.join(features.get('protocols', []))}

📂 Files Accessed or Transferred:
{', '.join(features.get('files', []))}

🔐 Permissions or System Accesses:
{', '.join(features.get('permissions', []))}

🧠 Functions Used:
{', '.join(features.get('functions', []))}

📄 Code Summary:
{features.get('summary', 'No summary available.')}

----------------------------------------
"""
    with open("report.txt", "w") as f:
        f.write(report)
    print("[+] Report generated: report.txt")
