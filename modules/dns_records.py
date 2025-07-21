import dns.resolver

def get_dns_records(domain="gcb.bank"):
    record_types = ['A', 'MX', 'NS', 'TXT']
    results = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except Exception as e:
            results[rtype] = [f"[!] No {rtype} records or error: {e}"]

    # Add SPF & DMARC Analysis
    analysis = evaluate_email_security(results.get("TXT", []))
    results["SPF_Evaluation"] = analysis.get("spf")
    results["DMARC_Evaluation"] = analysis.get("dmarc")

    return results


def evaluate_email_security(txt_records):
    spf_result = "❌ SPF record not found"
    dmarc_result = "❌ DMARC record not found"

    for record in txt_records:
        record = record.strip('"')  # Clean quotes

        # SPF check
        if record.lower().startswith("v=spf1"):
            if "~all" in record:
                spf_result = "⚠️ Weak SPF policy (~all)"
            elif "-all" in record:
                spf_result = "✅ Strong SPF policy (-all)"
            else:
                spf_result = "⚠️ SPF present, but final mechanism unclear"

        # DMARC check
        if record.lower().startswith("v=dmarc1"):
            if "p=none" in record.lower():
                dmarc_result = "⚠️ DMARC policy is 'none' (monitor only)"
            elif "p=quarantine" in record.lower():
                dmarc_result = "✅ DMARC policy: quarantine"
            elif "p=reject" in record.lower():
                dmarc_result = "✅ DMARC policy: reject"
            else:
                dmarc_result = "⚠️ DMARC found but policy unclear"

    return {"spf": spf_result, "dmarc": dmarc_result}