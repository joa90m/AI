# core/binary_tools.py
import lief

def extract_binary_features(file_path):
    try:
        binary = lief.parse(file_path)
        features = {
            "symbols": len(binary.symbols) if binary.has_symbols else 0,
            "imports": len(binary.imports),
            "sections": len(binary.sections),
        }
    except Exception:
        features = {}
    return features
