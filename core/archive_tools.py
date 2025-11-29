import os
import zipfile
import tempfile

def extract_from_archive(zip_path):
    from .features import extract_features_from_file  # ✅ move import inside

    features = {}
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmp_dir)
            for root, _, files in os.walk(tmp_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    sub_feat = extract_features_from_file(full_path)
                    for k, v in sub_feat.items():
                        features[k] = features.get(k, 0) + v
        except Exception:
            pass
    return features
