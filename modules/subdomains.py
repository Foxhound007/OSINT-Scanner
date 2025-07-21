import requests
from config import API_KEY, BASE_DOMAIN

def get_subdomains():
    url = f"https://api.securitytrails.com/v1/domain/{BASE_DOMAIN}/subdomains"
    headers = {
        "apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        subdomains = data.get("subdomains", [])
        full_domains = [f"{sub}.{BASE_DOMAIN}" for sub in subdomains]
        return full_domains
    else:
        print(f"[!] Error fetching subdomains: {response.status_code}")
        return []