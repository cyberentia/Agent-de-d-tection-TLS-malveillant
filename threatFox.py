import requests
import json

payload = {
    "query": "get_iocs",
    "search_term": "eb1d94daa7e0344597e756a1fb6e7054"
}

try:
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=5,
        verify=False  # ⚠️ uniquement pour debug, pas en prod
    )
    print(r.json())
except Exception as e:
    print(f"Erreur : {e}")
