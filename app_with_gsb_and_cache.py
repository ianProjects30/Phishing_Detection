"""
app_with_gsb_and_cache.py
Flask app that checks URL reachability and queries Google Safe Browsing.
Requires: pip install flask requests
Create a local config.py with: GSB_API_KEY = "YOUR_KEY"
"""

import os
import socket
import sqlite3
import time
import json
from urllib.parse import urlparse

import requests
from flask import Flask, request, render_template_string, jsonify

# ----- Configuration / Key loading -----
# Preferred: put your key in config.py (local file, not checked into VCS)
try:
    import config  # config.GSB_API_KEY expected
    GSB_API_KEY = getattr(config, "GSB_API_KEY", None)
except Exception:
    GSB_API_KEY = None

# If you prefer runtime prompt (uncomment below) - not recommended for automated servers
# if not GSB_API_KEY:
#     GSB_API_KEY = input("Enter Google Safe Browsing API key: ").strip()

# ----- App & DB setup -----
app = Flask(__name__)
DB_PATH = "url_check_cache.db"
CACHE_TTL_SECONDS = 24 * 3600  # 24 hours

# Private IP prefixes for SSRF protection
PRIVATE_PREFIXES = (
    "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "0."
)

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
    CREATE TABLE IF NOT EXISTS checks (
        url TEXT PRIMARY KEY,
        result_json TEXT,
        last_checked INTEGER
    )
    """)
    con.commit()
    con.close()

init_db()

# ----- Utility functions -----
def is_private_hostname(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return False
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)

def normalize_url(url: str) -> str:
    # Add scheme if missing
    parsed = urlparse(url if urlparse(url).scheme else ("http://" + url))
    return parsed.geturl()

# ----- Caching helpers -----
def get_cached_result(url: str):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT result_json, last_checked FROM checks WHERE url = ?", (url,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    result_json, last_checked = row
    age = time.time() - last_checked
    if age > CACHE_TTL_SECONDS:
        return None
    try:
        return json.loads(result_json)
    except Exception:
        return None

def set_cached_result(url: str, result: dict):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT INTO checks (url, result_json, last_checked)
        VALUES (?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET result_json=excluded.result_json, last_checked=excluded.last_checked
    """, (url, json.dumps(result), int(time.time())))
    con.commit()
    con.close()

# ----- Reachability check -----
def check_url_status(url: str, timeout=8):
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {"reachable": False, "detail": "invalid_hostname"}

    if is_private_hostname(host):
        return {"reachable": False, "detail": "hostname_resolves_to_private_ip (blocked for SSRF protection)"}

    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "URLChecker/1.0"})
        # Consider the site reachable even if status >= 400 (403, 404, etc.)
        return {
            "reachable": True,
            "http_status": resp.status_code,
            "reason": resp.reason,
            "final_url": resp.url,
        }
    except requests.exceptions.Timeout:
        return {"reachable": False, "detail": "timeout"}
    except requests.exceptions.SSLError:
        return {"reachable": False, "detail": "ssl_error"}
    except requests.exceptions.ConnectionError as e:
        return {"reachable": False, "detail": f"connection_error: {str(e)}"}
    except Exception as e:
        return {"reachable": False, "detail": str(e)}

# ----- Google Safe Browsing check -----
def phishing_check_gsb(url: str):
    api_key = GSB_API_KEY
    if not api_key:
        return {"label": "unknown", "confidence": 0.0, "source": "GoogleSafeBrowsing", "detail": "no_api_key_configured"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "urlchecker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=6)
        resp.raise_for_status()
        data = resp.json()
        if data.get("matches"):
            types = [m.get("threatType") for m in data.get("matches", [])]
            return {"label": "phishing", "confidence": 1.0, "source": "GoogleSafeBrowsing", "threat_types": types}
        else:
            return {"label": "safe", "confidence": 0.95, "source": "GoogleSafeBrowsing"}
    except requests.exceptions.HTTPError as e:
        # Response body may contain useful info (e.g. invalid key)
        body = ""
        try:
            body = resp.text
        except Exception:
            body = "<unavailable>"
        return {"label": "unknown", "confidence": 0.0, "source": "GoogleSafeBrowsing", "detail": f"HTTPError: {e}, body: {body}"}
    except Exception as e:
        return {"label": "unknown", "confidence": 0.0, "source": "GoogleSafeBrowsing", "detail": str(e)}

# ----- Combined top-level check (with caching) -----
def perform_check(url: str, use_cache: bool = True):
    url_norm = normalize_url(url)

    if use_cache:
        cached = get_cached_result(url_norm)
        if cached:
            # annotate that this is cached
            cached["_cached"] = True
            return cached

    status = check_url_status(url_norm)
    # If unreachable due to SSRF or invalid host, skip GSB call
    phishing = {"label": "unknown", "confidence": 0.0, "source": "none", "detail": "skipped"}
    if status.get("reachable", False):
        phishing = phishing_check_gsb(url_norm)
    else:
        phishing = {"label": "unknown", "confidence": 0.0, "source": "none", "detail": status.get("detail")}

    final_verdict = "Unknown"
    if phishing.get("label") == "phishing":
        final_verdict = "Reported Phishing"
    elif phishing.get("label") == "safe":
        final_verdict = "Not reported by GSB"
    else:
        final_verdict = "Unknown"

    result = {
        "url": url_norm,
        "status_check": status,
        "phishing_check": phishing,
        "final_verdict": final_verdict,
        "checked_at": int(time.time())
    }

    # Cache only if we actually called GSB or we want to cache unreachable too
    set_cached_result(url_norm, result)
    return result

# ----- Simple UI page -----
PAGE = """
<!doctype html>
<title>URL Health & Phish Checker</title>
<h2>Enter a URL to check</h2>
<form method="get" action="/check">
  <input name="q" style="width:520px" placeholder="https://example.com"/>
  <button type="submit">Check</button>
</form>
<p style="color:gray">Note: results are cached for 24 hours. Keep your API key private (config.py).</p>
{% if result %}
  <h3>Result for {{ url }}</h3>
  <pre>{{ result | tojson(indent=2) }}</pre>
{% endif %}
"""

# ----- Routes -----
@app.route("/")
def home():
    return render_template_string(PAGE)

@app.route("/check")
def check():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template_string(PAGE, result=None)
    res = perform_check(q, use_cache=True)
    return render_template_string(PAGE, result=res, url=q)

@app.route("/api/check")
def api_check():
    q = request.args.get("url", "").strip()
    if not q:
        return jsonify({"error": "url parameter required"}), 400
    # allow bypassing cache ?bypass_cache=1
    bypass = request.args.get("bypass_cache", "0") == "1"
    res = perform_check(q, use_cache=not bypass)
    return jsonify(res)

# ----- Run -----
if __name__ == "__main__":
    # Helpful dev-time warning
    if not GSB_API_KEY:
        print("WARNING: No Google Safe Browsing API key found. Put your key in config.py as GSB_API_KEY = '...'.")
    app.run(debug=True, host="0.0.0.0", port=5000)
