from modules.domain_info import get_domain_info
from modules.subdomains import get_subdomains
from modules.dns_records import get_dns_records
from modules.breaches import check_domain_breaches
from modules.ssl_cert import get_ssl_certificate
from modules.ssl_labs_scan import run_ssl_labs_scan
from modules.shodan_scan import search_shodan
from modules.crt_sh_cert_log import get_certificates

def main():
    print("🔍 External Risk Report - Georgia Community Bank")

    # Domain Info
    domain_info = get_domain_info()
    if domain_info:
        print("\n--- Domain Info ---")
        for key, value in domain_info.items():
            print(f"{key.title()}: {value}")

    # Subdomains
    subdomains = get_subdomains()
    print("\n--- Subdomains ---")
    for sub in subdomains:
        print(f"• {sub}")

    # DNS Records
    dns = get_dns_records()
    print("\n--- DNS Records ---")
    for rtype, entries in dns.items():
        if rtype in ["SPF_Evaluation", "DMARC_Evaluation"]:
            continue  # skip, print separately below
        print(f"{rtype} Records:")
        for entry in entries:
            print(f"  - {entry}")

    print("\n--- Email Security Evaluation ---")
    print(f"SPF:   {dns.get('SPF_Evaluation')}")
    print(f"DMARC: {dns.get('DMARC_Evaluation')}")

    # Check Breaches
    print("\n--- Breach Exposure ---")
    breaches = check_domain_breaches()
    if breaches:
        for b in breaches:
            print(f"  - {b}")
    else:
        print("✅ No known breaches tied to this domain.")

    # SSL Certificate Analysis
    print("\n--- SSL Certificate ---")
    cert = get_ssl_certificate()
    if "error" in cert:
        print(f"❗ Error fetching SSL cert: {cert['error']}")
    else:
        print(f"Issuer: {cert['issuer'].get('organizationName', 'Unknown')}")
        print(f"Subject: {cert['subject'].get('commonName', 'Unknown')}")
        print(f"Valid From: {cert['notBefore']}")
        print(f"Valid Until: {cert['notAfter']}")
        print(f"Expired: {'✅ No' if not cert['expired'] else '❌ Yes'}")
        print(f"SANs:")
        for san in cert['san']:
            print(f"  - {san}")

    # SSL Labs Summary
    print("\n--- SSL Labs External TLS Summary ---")
    ssl_labs_results = run_ssl_labs_scan()
    for line in ssl_labs_results:
     print(line)

    # Shodan Exposure Scan
    print("\n--- Shodan Exposure Scan ---")
    shodan_results = search_shodan()
    for line in shodan_results:
        print(line)

    # Certificate Transparency Log
    print("\n--- Certificate Transparency Log (crt.sh) ---")
    cert_log, subdomains = get_certificates()
    for line in cert_log:
     print(line)

    print("\n--- Extracted Subdomains ---")
    for sub in subdomains:
     print(f"  - {sub}")

if __name__ == "__main__":
    main()