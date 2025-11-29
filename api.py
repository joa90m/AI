import requests

api_key = "5b6fb802916b9962f5223738b258612e12047ab65ad12c62"
url = "https://mb-api.abuse.ch/api/v1/"
headers = {"Auth-Key": api_key}
data = {"query": "get_recent", "selector": "time"}

response = requests.post(url, headers=headers, data=data)
result = response.json()

if "data" in result:
    print(f"Total submissions fetched: {len(result['data'])}")
else:
    print("No data returned:", result)
