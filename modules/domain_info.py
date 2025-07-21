import requests
from config import API_KEY, BASE_DOMAIN

def get_domain_info():
    url = f"https://api.securitytrails.com/v1/domain/{BASE_DOMAIN}"
    headers = {
        "apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return {
            "domain": data.get("hostname"),
            "created": data.get("created"),
            "expires": data.get("expires"),
            "registrar": data.get("registrar", {}).get("name"),
            "nameservers": data.get("current_dns", {}).get("ns", {}).get("values", []),
        }
    else:
        print(f"[!] Error fetching domain info: {response.status_code}")
        return None