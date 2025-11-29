import requests
import os

# Your MalwareBazaar API key
API_KEY = "5b6fb802916b9962f5223738b258612e12047ab65ad12c62"  # Replace with your real key

# Settings
MALWARE_FAMILY = "GOBackdoor"  # Change to your desired family
DOWNLOAD_COUNT = 50              # Number of samples to fetch
SAVE_DIR = "backdoor_samples"     # Folder to store samples

# Create save folder
os.makedirs(SAVE_DIR, exist_ok=True)

BASE_URL = "https://mb-api.abuse.ch/api/v1/"
HEADERS = {"Auth-Key": API_KEY}

# Step 1: Fetch hashes for the given malware family
print(f"[+] Fetching hashes for malware family: {MALWARE_FAMILY}")
search_payload = {
    "query": "get_taginfo",
    "tag": MALWARE_FAMILY
}
response = requests.post(BASE_URL, headers=HEADERS, data=search_payload)
data = response.json()

if data.get("query_status") != "ok":
    print("[-] Failed to fetch data. Response:", data)
    exit()

hashes = [entry["sha256_hash"] for entry in data["data"]][:DOWNLOAD_COUNT]
print(f"[+] Found {len(hashes)} hashes. Starting download...")

# Step 2: Download each sample
for i, sha256 in enumerate(hashes, start=1):
    download_payload = {
        "query": "get_file",
        "sha256_hash": sha256
    }
    r = requests.post(BASE_URL, headers=HEADERS, data=download_payload)

    if r.status_code == 200 and r.content:
        file_path = os.path.join(SAVE_DIR, f"{sha256}.zip")
        with open(file_path, "wb") as f:
            f.write(r.content)
        print(f"[{i}/{len(hashes)}] Downloaded: {sha256}")
    else:
        print(f"[-] Failed to download {sha256}")

print("[+] Download complete.")
