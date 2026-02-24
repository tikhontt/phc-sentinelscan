import ssl
import socket
from datetime import datetime

def check_ssl(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Извлекаем дату истечения
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.utcnow()).days
                
                return {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "expiry_date": cert['notAfter'],
                    "days_left": days_left,
                    "is_valid": days_left > 0
                }
    except Exception as e:
        return {"error": str(e)}
