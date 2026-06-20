"""Conservative chat-endpoint discovery for authorized assessments.

Discovery treats page content as untrusted. By default it only follows same-origin
script, endpoint, and redirect references, preventing a malicious page from
turning the local security tool into a client-side SSRF primitive or silently
redirecting a campaign to an unrelated host. External discovery is explicit
opt-in.
"""

import re
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests


_MAX_REDIRECTS = 3


def _same_origin(seed_url: str, candidate_url: str) -> bool:
    seed = urlparse(seed_url)
    candidate = urlparse(candidate_url)

    def normalized_port(parsed):
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme in {"https", "wss"} else 80

    return (seed.hostname, normalized_port(seed)) == (candidate.hostname, normalized_port(candidate))


def _allowed_candidate(seed_url: str, candidate_url: str, allow_external: bool) -> bool:
    parsed = urlparse(candidate_url)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        return False
    return allow_external or _same_origin(seed_url, candidate_url)


def _safe_get(seed_url: str, requested_url: str, timeout: int, insecure: bool, allow_external: bool):
    """GET with bounded redirects that obey discovery origin policy."""
    current = requested_url
    for _ in range(_MAX_REDIRECTS + 1):
        response = requests.get(
            current,
            timeout=timeout,
            verify=not insecure,
            allow_redirects=False,
        )
        status = int(getattr(response, "status_code", 200) or 200)
        headers = getattr(response, "headers", {}) or {}
        location = headers.get("Location") or headers.get("location")
        if 300 <= status < 400 and location:
            next_url = urljoin(current, location)
            if not _allowed_candidate(seed_url, next_url, allow_external):
                return None
            current = next_url
            continue
        response.raise_for_status()
        return response
    return None


def discover_endpoint(
    url: str,
    timeout: int = 10,
    insecure: bool = False,
    allow_external: bool = False,
) -> Optional[Dict]:
    """Discover a likely chat endpoint without cross-origin crawling by default."""
    try:
        response = _safe_get(url, url, timeout, insecure, allow_external)
        if response is None:
            return None
    except Exception:
        return None

    page_base = getattr(response, "url", url) or url
    ws_pattern = r'["\'](wss?://[^"\']+)["\']'
    for match in re.findall(ws_pattern, response.text):
        if _allowed_candidate(url, match, allow_external):
            return {"endpoint": match, "method": "WS", "json_path": None}

    rest_patterns = [
        r'["\'](https?://[^"\']*(?:chat|message|send|query)[^"\']*)["\']',
        r'fetch\(["\']([^"\']*)["\']',
        r'baseURL\s*:\s*["\']([^"\']*)["\']',
    ]
    for pattern in rest_patterns:
        for match in re.findall(pattern, response.text):
            if not any(keyword in match.lower() for keyword in ("chat", "message", "api", "query", "send")):
                continue
            endpoint = urljoin(page_base, match) if not match.startswith("http") else match
            if _allowed_candidate(url, endpoint, allow_external):
                return {"endpoint": endpoint, "method": "POST", "json_path": None}

    script_pattern = r'<script[^>]*src="([^"]+)"'
    for script_url in re.findall(script_pattern, response.text):
        absolute = urljoin(page_base, script_url)
        if not _allowed_candidate(url, absolute, allow_external):
            continue
        try:
            script_response = _safe_get(url, absolute, min(timeout, 5), insecure, allow_external)
            if script_response is None:
                continue
        except Exception:
            continue
        script_base = getattr(script_response, "url", absolute) or absolute
        for pattern in rest_patterns:
            for match in re.findall(pattern, script_response.text):
                if not any(keyword in match.lower() for keyword in ("chat", "message", "api", "query", "send")):
                    continue
                endpoint = urljoin(script_base, match) if not match.startswith("http") else match
                if _allowed_candidate(url, endpoint, allow_external):
                    return {"endpoint": endpoint, "method": "POST", "json_path": None}
    return None
