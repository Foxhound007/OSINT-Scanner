import ssl
import socket
from datetime import datetime

def get_ssl_certificate(domain="gcb.bank", port=443):
    context = ssl.create_default_context()
    cert_data = {}

    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        cert_data['subject'] = dict(x[0] for x in cert['subject'])
        cert_data['issuer'] = dict(x[0] for x in cert['issuer'])
        cert_data['notBefore'] = cert['notBefore']
        cert_data['notAfter'] = cert['notAfter']
        cert_data['san'] = [x[1] for x in cert.get('subjectAltName', [])]
        cert_data['expired'] = datetime.utcnow() > datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

    except Exception as e:
        cert_data['error'] = str(e)

    return cert_data