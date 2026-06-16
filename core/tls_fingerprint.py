import random

try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI = True
except ImportError:
    CURL_CFFI = False

JA3_FINGERPRINTS = {
    "chrome": "chrome110",
    "firefox": "firefox102",
    "safari": "safari15_5",
    "edge": "edge99",
}

def random_ja3() -> str:
    """Kembalikan JA3 fingerprint acak dari daftar."""
    return random.choice(list(JA3_FINGERPRINTS.values()))

def apply_ja3_to_session(session, fingerprint: str = "random"):
    """Terapkan JA3 fingerprint ke sesi curl_cffi."""
    if not CURL_CFFI:
        return session
    if fingerprint == "random":
        impersonate = random_ja3()
    else:
        impersonate = JA3_FINGERPRINTS.get(fingerprint, "chrome110")
    session.impersonate = impersonate
    return session