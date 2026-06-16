import requests
from typing import Dict, Optional

def session_login(login_url: str, credentials: Dict, timeout: int = 10,
                insecure: bool = False) -> Optional[Dict]:
    """
    Melakukan login form dan mengembalikan dict headers (Cookie, Authorization).
    """
    try:
        r = requests.post(login_url, data=credentials, timeout=timeout,
                        allow_redirects=False, verify=not insecure)
        if r.status_code in (200, 302):
            cookies = r.cookies.get_dict()
            if cookies:
                cookie_str = "; ".join([f"{k}={v}" for k,v in cookies.items()])
                return {"Cookie": cookie_str}
        if "Set-Cookie" in r.headers:
            return {"Cookie": r.headers["Set-Cookie"]}
    except Exception:
        pass
    return None