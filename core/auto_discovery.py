import re
import requests
from urllib.parse import urljoin
from typing import Optional, Dict

def discover_endpoint(url: str, timeout: int = 10, insecure: bool = False) -> Optional[Dict]:
    """Cari endpoint chat dari halaman web, dengan opsi insecure SSL."""
    try:
        # Gunakan verify=False jika insecure
        resp = requests.get(url, timeout=timeout, verify=not insecure)
        resp.raise_for_status()
    except Exception:
        return None

    # 1. Cari WebSocket
    ws_pattern = r'["\'](wss?://[^"\']+)["\']'
    ws_matches = re.findall(ws_pattern, resp.text)
    if ws_matches:
        return {"endpoint": ws_matches[0], "method": "WS", "json_path": None}

    # 2. Cari REST API patterns
    rest_patterns = [
        r'["\'](https?://[^"\']*(?:chat|message|send|query)[^"\']*)["\']',
        r'fetch\(["\']([^"\']*)["\']',
        r'baseURL\s*:\s*["\']([^"\']*)["\']',
    ]
    for pat in rest_patterns:
        matches = re.findall(pat, resp.text)
        for m in matches:
            if any(k in m for k in ("chat", "message", "api")):
                endpoint = urljoin(url, m) if not m.startswith("http") else m
                return {"endpoint": endpoint, "method": "POST", "json_path": None}

    # 3. Cek script eksternal
    script_pattern = r'<script[^>]*src="([^"]+)"'
    for script_url in re.findall(script_pattern, resp.text):
        abs_url = urljoin(url, script_url)
        try:
            js_resp = requests.get(abs_url, timeout=5, verify=not insecure)
            for pat in rest_patterns:
                for m in re.findall(pat, js_resp.text):
                    if any(k in m for k in ("chat", "message", "api")):
                        endpoint = urljoin(url, m) if not m.startswith("http") else m
                        return {"endpoint": endpoint, "method": "POST", "json_path": None}
        except:
            continue
    return None