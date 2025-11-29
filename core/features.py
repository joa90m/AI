# Updated features.py
import os
import re
from .parser import extract_python_features, extract_functions
from .archive_tools import extract_from_archive
from .binary_tools import extract_binary_features

def extract_features_from_file(file_path):
    ext = os.path.splitext(file_path)[-1].lower()

    if ext == ".py":
        try:
            with open(file_path, "r", errors="ignore") as f:
                code = f.read()
                features = extract_python_features(code)
                features['functions'] = extract_functions(code)
                return features
        except Exception:
            return {}

    elif ext == ".zip":
        return extract_from_archive(file_path)

    elif ext in [".exe", ".elf", ".msi"]:
        return extract_features_from_binary(file_path)

    return {}

def extract_features_from_binary(path):
    features = {
        'HTTP': 0, 'FTP': 0, 'SMTP': 0, 'DNS': 0,
        'os.system': 0, 'subprocess': 0, 'eval': 0, 'exec': 0,
        'open': 0, 'socket': 0, 'shutil': 0, 'ctypes': 0, 'getenv': 0,
    }
    try:
        with open(path, 'rb') as f:
            content = f.read().decode(errors='ignore')
            for k in features:
                features[k] = len(re.findall(re.escape(k), content, re.IGNORECASE))
    except Exception:
        pass
    return features
