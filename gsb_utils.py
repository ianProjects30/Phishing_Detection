import os, time, json, sqlite3, requests
from urllib.parse import urlparse

try:
    import config
    GSB_API_KEY = getattr(config, "GSB_API_KEY", None)
except Exception:
    GSB_API_KEY = os.environ.get("GSB_API_KEY")

DB_PATH = "gsb_cache.db"
CACHE_TTL = 24 * 3600

def _init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS cache (url TEXT PRIMARY KEY, json TEXT, checked_at INTEGER)""")
    con.commit()
    con.close()
_init_db()

def _get_cached(url):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT json, checked_at FROM cache WHERE url=?", (url,))
    row = cur.fetchone()
    con.close()
    if not row: return None
    data, ts = row
    if time.time() - ts > CACHE_TTL: return None
    try: return json.loads(data)
    except: return None

def _set_cached(url, data):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""INSERT INTO cache (url, json, checked_at) VALUES (?, ?, ?)
                   ON CONFLICT(url) DO UPDATE SET json=excluded.json, checked_at=excluded.checked_at""",
                (url, json.dumps(data), int(time.time())))
    con.commit()
    con.close()

def check_gsb(url, use_cache=True):
    if not GSB_API_KEY:
        return {"label": "unknown", "confidence": 0.0, "source": "GSB", "detail": "missing_api_key"}
    parsed = urlparse(url if "://" in url else "http://" + url)
    normalized = parsed.geturl()
    if use_cache:
        cached = _get_cached(normalized)
        if cached:
            cached["_cached"] = True
            return cached
    payload = {
        "client": {"clientId": "phish-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": normalized}]
        }
    }
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    try:
        r = requests.post(endpoint, json=payload, timeout=6)
        r.raise_for_status()
        data = r.json()
        if data.get("matches"):
            types = [m.get("threatType") for m in data["matches"]]
            result = {"label": "phishing", "confidence": 1.0, "source": "GSB", "detail": ", ".join(types)}
        else:
            result = {"label": "safe", "confidence": 0.95, "source": "GSB", "detail": "not_reported"}
    except Exception as e:
        result = {"label": "unknown", "confidence": 0.0, "source": "GSB", "detail": str(e)}
    _set_cached(normalized, result)
    return result
