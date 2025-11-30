# behavior_summary.py
def summarize_strings(strings):
    indicators = {
        "http": "Uses HTTP communication",
        "https": "Uses HTTPS communication",
        "ftp": "Performs FTP transfers",
        "cmd.exe": "Executes system commands",
        "powershell": "Runs PowerShell operations",
        "socket": "Opens raw network sockets",
        ".exe": "Drops or loads executable files",
        ".dll": "Loads dynamic-link libraries",
        "temp": "Writes files in temporary directories"
    }

    summary = []
    combined = " ".join(s.lower() for s in strings)

    for key, meaning in indicators.items():
        if key in combined:
            summary.append(meaning)

    return summary


def summarize_imports(imports):
    behaviors = []

    for imp in imports:
        i = imp.lower()
        if "ws2_32" in i:
            behaviors.append("Networking operations via Winsock")
        if "winhttp" in i or "wininet" in i:
            behaviors.append("HTTP/HTTPS communication")
        if "advapi" in i:
            behaviors.append("Registry or privilege operations")
        if "kernel32" in i:
            behaviors.append("File/process/memory manipulation")
        if "crypt" in i:
            behaviors.append("Encryption or decryption functionality")

    return behaviors


def summarize_assembly(instructions):
    behaviors = []
    for ins in instructions:
        ins = ins.lower()

        if "call" in ins:
            behaviors.append("Performs function calls")
        if "mov" in ins and "esp" in ins:
            behaviors.append("Manipulates the stack frame")
        if "socket" in ins:
            behaviors.append("Creates a network socket")
        if "connect" in ins:
            behaviors.append("Attempts network connection")
        if "open" in ins:
            behaviors.append("Opens a file or resource")
        if "read" in ins:
            behaviors.append("Reads data")
        if "write" in ins:
            behaviors.append("Writes data")
        if "exec" in ins:
            behaviors.append("Executes a command")

    return behaviors


def generate_human_readable_summary(features):
    summary = []
    summary += summarize_strings(features.get("strings", []))
    summary += summarize_imports(features.get("imports", []))
    summary += summarize_assembly(features.get("assembly", []))

    # Remove duplicates
    summary = list(sorted(set(summary)))

    return summary
# core/behavior_summary.py

def generate_human_readable_summary(features):
    behaviors = []
    permissions = features.get("permissions", [])
    imports = features.get("imports", [])
    protocols = features.get("protocols", [])
    strings = features.get("strings", [])

    # ---------------------------
    # 1. Network Indicators
    # ---------------------------
    if "HTTP" in protocols or any("http" in s.lower() for s in strings):
        behaviors.append("Communicates over HTTP (possible C2 traffic)")

    if "DNS" in protocols:
        behaviors.append("Uses DNS resolution (possible domain generation or beaconing)")

    if "FTP" in protocols:
        behaviors.append("Uses FTP (possible data exfiltration)")

    # ---------------------------
    # 2. Suspicious Imports
    # ---------------------------
    suspicious_imports_map = {
        "socket": "Network communication capabilities",
        "subprocess": "Can execute system commands",
        "os.system": "Executes OS commands",
        "ctypes": "May access low-level system APIs",
        "shutil": "Can modify or delete files",
        "requests": "Performs HTTP requests",
    }

    for imp in imports:
        for key, desc in suspicious_imports_map.items():
            if key.lower() in imp.lower():
                behaviors.append(desc)

    # ---------------------------
    # 3. Strings Indicating Malicious Intent
    # ---------------------------
    for s in strings:
        low = s.lower()
        if "password" in low:
            behaviors.append("Attempts to steal or handle passwords")
        if "cmd.exe" in low or "powershell" in low:
            behaviors.append("Executes system shell commands")
        if "key" in low and "log" in low:
            behaviors.append("Possible keylogging activity")
        if "http://" in low or "https://" in low:
            behaviors.append("Connects to a remote URL")

    # ---------------------------
    # 4. Permissions (Android / App malware)
    # ---------------------------
    if "READ_SMS" in permissions:
        behaviors.append("Reads SMS messages")
    if "READ_CONTACTS" in permissions:
        behaviors.append("Reads contact list")
    if "WRITE_EXTERNAL_STORAGE" in permissions:
        behaviors.append("Modifies external storage")

    # ---------------------------
    # Clean Up
    # ---------------------------
    if not behaviors:
        behaviors = ["No obvious malicious behavior detected from static analysis."]

    # Risk scoring
    risk = "Low"
    if len(behaviors) >= 3:
        risk = "Medium"
    if len(behaviors) >= 6:
        risk = "High"

    return {
        "likely_behaviors": behaviors,
        "risk_level": risk
    }
