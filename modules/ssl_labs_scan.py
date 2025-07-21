import requests
import time


def run_ssl_labs_scan(domain="gcb.bank"):
    print(f"Submitting {domain} to SSL Labs...")

    base_url = "https://api.ssllabs.com/api/v3/analyze"
    params = {
        "host": domain,
        "publish": "off",
        "all": "done",
        "fromCache": "on"
    }

    try:
        # Start scan
        response = requests.get(base_url, params=params)
        data = response.json()

        # Poll until status is READY
        while data.get("status") in ["DNS", "IN_PROGRESS", "STARTING"]:
            print(f"Waiting for scan to complete... (status: {data.get('status')})")
            time.sleep(5)
            response = requests.get(base_url, params=params)
            data = response.json()

        if data.get("status") != "READY":
            return ["❗ SSL Labs scan did not complete successfully."]

        endpoint = data["endpoints"][0]
        details = endpoint.get("details", {})

        output = []

        # Grade
        output.append(f"Grade: {endpoint.get('grade', 'N/A')}")

        # TLS versions
        protocols = details.get("protocols", [])
        version_list = [proto["name"] for proto in protocols if "name" in proto]
        output.append(f"TLS Versions: {', '.join(version_list) or 'None detected'}")

        # Certificate summary
        cert = details.get("cert", {})
        if cert:
            output.append(f"Certificate Subject: {cert.get('subject', 'Unknown')}")
            output.append(f"Issuer: {cert.get('issuerLabel', 'Unknown')}")
            expiry_days = int(cert.get('notAfter', 0) / 86400)
            output.append(f"Expires In: {expiry_days} days")

        # Basic vulnerability flags
        if details.get("heartbleed", False):
            output.append("❌ Vulnerable to Heartbleed")
        if details.get("supportsRc4", False):
            output.append("⚠️ RC4 Supported")
        if details.get("rc4Only", False):
            output.append("❌ Only RC4 Supported")

        return output

    except Exception as e:
        return [f"❗ Error during SSL Labs scan: {e}"]