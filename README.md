# 🕵️ OSINT External Risk Scanner

A lightweight Python-based OSINT (Open Source Intelligence) scanner designed to collect, evaluate, and summarize external cybersecurity risks for an organization or domain. Ideal for use in interviews, assessments, or pre-engagement reconnaissance.

---

## 🔧 Features

- ✅ **Domain Intelligence** – WHOIS info, registrar metadata, DNS records  
- 🌐 **Subdomain Discovery** – via crt.sh, Certificate Transparency, and passive sources  
- 📩 **Email Security Check** – SPF and DMARC analysis  
- 🔐 **SSL Certificate Health** – active certs via SSL Labs API, expiration, SANs  
- 📜 **Certificate Transparency Logs** – full historical cert footprint from crt.sh  
- 🔎 **Shodan Exposure Lookup** – exposed services, IPs, open ports  
- 🚨 **Breach Check** – known leaks from public data breach sources  
- 🧠 **Risk Summary Output** – actionable, human-readable reporting with icons and risk levels

---

## 🧪 Example Output

```
Domain: domain.com
SPF: ✅ Enforced
DMARC: ❌ Missing
SSL Grade: ✅ A+ (Valid through 2026)
Shodan Ports: ⚠️ FTP, HTTPS exposed via foreign IPs
Expired Certs: ⚠️ Found for legacy subdomains
Risk: Medium–High due to exposure and missing DMARC
```

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/osint-risk-scanner.git
cd osint-risk-scanner
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python osint_scan.py --domain domain.com
```

Optional flags:

- `--save` → Save output to a `.docx` or `.pdf` summary  
- `--verbose` → Print debug and error information  
- `--shodan-key YOUR_API_KEY` → Enable Shodan enumeration  
- `--ssl-labs` → Include full SSL Labs grading  

---

## 🧩 Modules

| Module            | Description                                               |
|-------------------|-----------------------------------------------------------|
| `dns_scanner.py`  | Retrieves A, MX, NS, TXT records with timeout handling     |
| `cert_scanner.py` | Queries SSL Labs & parses Certificate Transparency logs   |
| `email_check.py`  | Analyzes SPF & DMARC policies from DNS TXT records        |
| `breach_check.py` | Looks up domain presence in known public data breaches    |
| `shodan_lookup.py`| Queries Shodan API for exposed services & banners         |
| `report_writer.py`| Generates printable risk summaries in DOCX/PDF            |

---

## ✅ Output Format

All results are organized into:
- **DNS & Email Security**
- **SSL/TLS & Certificate Health**
- **Shodan Exposure**
- **Breach History**
- **Risk Table & Recommendations**

Icons (✅, ❌, ⚠️) help highlight severity at a glance.

---

## 🧠 Use Cases
  
- Red team recon starter  
- Risk reports for client onboarding  
- Audit prep or compliance snapshot

---

## 📌 Roadmap

- [ ] Add JSON/HTML report export  
- [ ] Add optional port scan module  
- [ ] Add scoring system per domain  
- [ ] Add DNSSEC + CSP header checks  

---

## 📄 License

MIT License © 2025 Charles Gaughf
