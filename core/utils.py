# core/utils.py
import os
import re
import math
import hashlib
from collections import Counter

def shannon_entropy(file_path):
    """Calculate Shannon entropy of a file."""
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
    """Extract printable strings from a binary file."""
    try:
        with open(file_path, "rb") as f:
            raw = f.read().decode("latin1", errors="ignore")
        return re.findall(rf'[\x20-\x7E]{{{min_len},}}', raw)
    except Exception:
        return []

def get_sha256(file_path):
    """Return the SHA-256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None
