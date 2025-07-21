import requests
import time
import re
from datetime import datetime

# --- Risk Rules ---
RISKY_SUBSTRINGS = ['dev', 'test', 'staging', 'vpn', 'qa', 'secure', 'login']
SAFE_ISSUERS = ['Amazon', 'DigiCert', 'GoDaddy', 'Entrust']
WILDCARD_PATTERN = r"^\*\."
LETSE = "Let's Encrypt"

# --- Helpers ---
def risk_level(risks):
    if "🔓 Let's Encrypt" in risks or "🃏 Wildcard" in risks:
        return "Medium" if len(risks) == 1 else "High"
    if "🐾 Suspicious Subdomain" in risks:
        return "Medium"
    if "❗ Expired" in risks:
        return "Medium"
    return "Low" if risks else "None"


def get_certificates(domain="gcb.bank"):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    output = []
    discovered_subdomains = set()
    attempts = 3

    for attempt in range(attempts):
        try:
            print(f"[crt.sh] Attempt {attempt + 1} of {attempts}...")
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                return [f"❗ crt.sh query failed: HTTP {response.status_code}"]

            data = response.json()
            if not data:
                return ["✅ No certificates found in crt.sh for this domain."]

            seen = set()
            for cert in data:
                name_value = cert.get("name_value", "")
                issuer = cert.get("issuer_name", "Unknown")
                not_after = cert.get("not_after")  # Unix timestamp

                entry = (name_value, issuer)
                if entry in seen:
                    continue
                seen.add(entry)

                # Track discovered subdomains
                for line in name_value.split("\n"):
                    discovered_subdomains.add(line.strip())

                # --- RISK CHECKS ---
                risk_flags = []

                if re.match(WILDCARD_PATTERN, name_value):
                    risk_flags.append("🃏 Wildcard")

                if any(keyword in name_value.lower() for keyword in RISKY_SUBSTRINGS):
                    risk_flags.append("🐾 Suspicious Subdomain")

                if LETSE in issuer:
                    risk_flags.append("🔓 Let's Encrypt")

                if not any(known in issuer for known in SAFE_ISSUERS):
                    risk_flags.append("❓ Unrecognized Issuer")

                # Expired cert
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
                        if expiry < datetime.utcnow():
                            risk_flags.append("❗ Expired")
                    except:
                        pass

                # --- Output Section ---
                output.append(f"🔹 Domain: {name_value}")
                output.append(f"    Issuer: {issuer}")
                if not_after:
                    output.append(f"    Expiry: {not_after}")

                if risk_flags:
                    output.append(f"    ⚠️  Risks: {', '.join(risk_flags)}")
                    output.append(f"    🧠 Risk Level: {risk_level(risk_flags)}\n")
                else:
                    output.append("    ✅ No obvious risk flags\n")

            return output, sorted(discovered_subdomains)

        except requests.exceptions.ReadTimeout:
            output.append(f"[crt.sh] Timeout on attempt {attempt + 1}. Retrying...\n")
            time.sleep(3)

        except Exception as e:
            return [f"❗ Error querying crt.sh: {e}"], []

    output.append("❗ crt.sh failed after 3 attempts due to repeated timeouts.")
    return output, []