import requests
from config import HIBP_API_KEY, BASE_DOMAIN

def check_domain_breaches():
    url = f"https://haveibeenpwned.com/api/v3/breaches"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "ExternalRiskAuditTool/1.0"
    }
    params = {
        "domain": BASE_DOMAIN
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        if not data:
            return []
        return [f"{entry['Name']} ({entry['BreachDate']})" for entry in data]
    elif response.status_code == 404:
        return []  # No breaches found
    elif response.status_code == 403:
        return ["❗ Forbidden: Make sure the domain is verified with HIBP."]
    elif response.status_code == 401:
        return ["❗ Unauthorized: Invalid API key."]
    else:
        return [f"❗ Error: {response.status_code}"]