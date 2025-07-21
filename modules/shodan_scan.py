import shodan
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("SHODAN_API_KEY")

def search_shodan(domain="gcb.bank"):
    output = []

    try:
        api = shodan.Shodan(API_KEY)

        query = f"ssl:{domain}"  # can also try hostname:{domain}
        results = api.search(query)

        output.append(f"Found {results['total']} result(s) for {domain} on Shodan:\n")

        for match in results["matches"][:5]:  # limit to top 5
            ip = match.get("ip_str", "N/A")
            port = match.get("port", "N/A")
            org = match.get("org", "Unknown")
            data = match.get("data", "").strip().split("\n")[0]  # first line of banner

            output.append(f"🔹 {ip}:{port} - {org}")
            output.append(f"    Banner: {data}\n")

        return output

    except shodan.APIError as e:
        return [f"❗ Shodan API Error: {e}"]
    except Exception as ex:
        return [f"❗ General Error: {ex}"]