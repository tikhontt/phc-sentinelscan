import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_headers(ip, port, max_size=2 * 1024 * 1024): # Лимит 2 МБ на всякий случай
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{ip}:{port}"
    
    try:
        with requests.get(url, timeout=5, verify=False, stream=True) as response: #nosec
            
            cl = response.headers.get('Content-Length')
            if cl and int(cl) > max_size:
                return {"error": f"Payload too large ({cl} bytes)"}

            h = response.headers
            
            return {
                "Content-Security-Policy": h.get("Content-Security-Policy", "MISSING"),
                "Strict-Transport-Security": h.get("Strict-Transport-Security", "MISSING"),
                "X-Frame-Options": h.get("X-Frame-Options", "MISSING"),
                "Server": h.get("Server", "Hidden")
            }
            
    except requests.exceptions.Timeout:
        return {"error": "Timeout: Server is too slow"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Connection failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
