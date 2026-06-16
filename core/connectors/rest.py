import requests
import json
import re
import random
import time
import logging
from typing import Dict, Optional, List
from .base import BaseConnector
from ..utils import load_user_agents, random_user_agent

# matikan peringatan SSL jika verifikasi dimatikan
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("InjectionForgeX.connector")


class RESTChatbotConnector(BaseConnector):
    def __init__(self, endpoint: str, method: str = "POST",
                 api_key: str = "", headers: Optional[Dict[str, str]] = None,
                 cookie: Optional[str] = None,
                 json_path: Optional[str] = None,
                 form_data: bool = False,
                 csrf_token_url: Optional[str] = None,
                 auth_endpoint: Optional[str] = None,
                 auth_data: Optional[Dict] = None,
                 proxy: Optional[str] = None,
                 stealth: bool = False,
                 delay: float = 1.0,
                 timeout: int = 30,
                 waf_session=None,
                 verify_ssl: bool = True):
        self.endpoint = endpoint
        self.method = method.upper()
        self.api_key = api_key
        self.base_headers = dict(headers or {})
        self.cookie = cookie
        self.json_path = json_path
        self.form_data = form_data
        self.csrf_token_url = csrf_token_url
        self.auth_endpoint = auth_endpoint
        self.auth_data = auth_data
        self.proxy = proxy
        self.stealth = stealth
        self.delay = delay
        self.timeout = timeout
        self.waf_session = waf_session
        self.verify_ssl = verify_ssl

        if self.waf_session:
            self.session = self.waf_session.session
        else:
            self.session = requests.Session()
            if self.proxy:
                self.session.proxies = {"http": self.proxy, "https": self.proxy}

        if not self.verify_ssl:
            self.session.verify = False

        self._user_agents = load_user_agents()
        self._auth_token = None
        self._csrf_token = None

        if self.auth_endpoint:
            self._fetch_auth_token()
        if self.csrf_token_url:
            self._fetch_csrf_token()

    def _fetch_auth_token(self):
        payload = self.auth_data or {}
        try:
            r = self.session.post(self.auth_endpoint, json=payload, timeout=self.timeout)
            r.raise_for_status()
            resp = r.json()
            for key in ["token", "access_token", "jwt"]:
                if key in resp:
                    self._auth_token = resp[key]
                    self.base_headers["Authorization"] = f"Bearer {self._auth_token}"
                    break
        except Exception as e:
            print(f"[!] Gagal fetch auth token: {e}")

    def _fetch_csrf_token(self):
        if self.csrf_token_url.startswith("http"):
            try:
                r = self.session.get(self.csrf_token_url, timeout=self.timeout)
                r.raise_for_status()
                if "application/json" in r.headers.get("content-type",""):
                    resp = r.json()
                    for key in ["csrf_token", "csrftoken", "token"]:
                        if key in resp:
                            self._csrf_token = resp[key]
                            break
                else:
                    match = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
                    if match:
                        self._csrf_token = match.group(1)
                if self._csrf_token:
                    self.base_headers["X-CSRFToken"] = self._csrf_token
            except Exception as e:
                print(f"[!] Gagal fetch CSRF token: {e}")
        else:
            self._csrf_token = self.csrf_token_url
            self.base_headers["X-CSRFToken"] = self._csrf_token

    def _build_headers(self):
        headers = dict(self.base_headers)
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}" if not self.api_key.startswith("Bearer ") else self.api_key
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.stealth:
            headers["User-Agent"] = random_user_agent(self._user_agents)
        return headers

    def _auto_detect_response(self, response_json: dict) -> str:
        def find_strings(obj, depth=0):
            if depth > 3:
                return []
            strings = []
            if isinstance(obj, str):
                strings.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    strings.extend(find_strings(v, depth+1))
            elif isinstance(obj, list):
                for item in obj:
                    strings.extend(find_strings(item, depth+1))
            return strings
        candidates = find_strings(response_json)
        if not candidates:
            return str(response_json)
        return max(candidates, key=len)

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        headers = self._build_headers()
        data = None
        params = None

        if self.method in ("POST", "PUT", "PATCH"):
            if self.form_data:
                data = {"message": prompt}
            else:
                payload = {"message": prompt}
                if history:
                    payload["conversation_id"] = history[-1].get("id", "")
                data = json.dumps(payload)
                headers.setdefault("Content-Type", "application/json")
        else:
            params = {"message": prompt}

        # === LOGGING DEBUG ===
        logger.info(f"PAYLOAD: {prompt[:80]}")
        logger.info(f"Mengirim {self.method} ke {self.endpoint}")
        # =====================

        if self.stealth:
            time.sleep(self.delay * random.uniform(0.7, 1.3))

        try:
            r = self.session.request(
                method=self.method,
                url=self.endpoint,
                data=data if not isinstance(data, str) else data,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            r.raise_for_status()
            resp = r.text

            # === LOG RESPONS ===
            logger.info(f"RESPONS: {resp[:100]}")
            # ===================

            try:
                resp_json = r.json()
                if self.json_path:
                    temp = resp_json
                    for key in self.json_path.split("."):
                        temp = temp.get(key, {})
                    resp = str(temp) if temp else resp
                else:
                    resp = self._auto_detect_response(resp_json)
            except json.JSONDecodeError:
                pass
            return resp
        except Exception as e:
            raise