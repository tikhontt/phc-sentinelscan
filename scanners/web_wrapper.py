import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_headers(ip, port):
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"
    try:
        response = requests.get(url, timeout=3, verify=False)
        h = response.headers
        return {
            "Content-Security-Policy": h.get("Content-Security-Policy", "MISSING"),
            "Strict-Transport-Security": h.get("Strict-Transport-Security", "MISSING"),
            "X-Frame-Options": h.get("X-Frame-Options", "MISSING")
        }
    except:
        return {"error": "Connection failed"}