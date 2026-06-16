import time
import random
import requests
from typing import Optional, Dict

try:
    import cloudscraper
except ImportError:
    cloudscraper = None

try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI = True
except ImportError:
    CURL_CFFI = False

try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    SELENIUM = True
except ImportError:
    SELENIUM = False


class WAFBypass:
    def __init__(self, bypass_type: str = "auto", tls_fingerprint: str = "random",
                headless: bool = False, proxy: Optional[str] = None,
                timeout: int = 30, insecure: bool = False):
        self.type = bypass_type
        self.tls_fp = tls_fingerprint
        self.headless = headless
        self.proxy = proxy
        self.timeout = timeout
        self.insecure = insecure
        self.session = self._create_session()

    def _create_session(self):
        if self.type in ("cloudflare", "auto"):
            if cloudscraper:
                scraper = cloudscraper.create_scraper(
                    browser={"browser": "chrome", "platform": "windows", "mobile": False},
                    delay=10
                )
                if self.proxy:
                    scraper.proxies = {"http": self.proxy, "https": self.proxy}
                if self.insecure:
                    scraper.verify = False
                return scraper
            elif self.headless and SELENIUM:
                return self._create_selenium_session()
            elif CURL_CFFI:
                return self._create_curl_cffi_session()

        if self.type == "akamai" or self.tls_fp != "none":
            if CURL_CFFI:
                return self._create_curl_cffi_session()
            else:
                raise ImportError("curl_cffi required for Akamai/TLS bypass.")

        # default requests
        session = requests.Session()
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        if self.insecure:
            session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session

    def _create_curl_cffi_session(self):
        fps = {
            "chrome": "chrome110",
            "firefox": "firefox102",
            "safari": "safari15_5",
            "random": random.choice(["chrome110", "firefox102", "safari15_5", "edge99"])
        }
        impersonate = fps.get(self.tls_fp, "chrome110")
        session = curl_requests.Session()
        session.impersonate = impersonate
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        if self.insecure:
            session.verify = False
        return session

    def _create_selenium_session(self):
        options = uc.ChromeOptions()
        options.headless = True
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")
        driver = uc.Chrome(options=options)
        return driver

    def solve_challenge(self, url: str) -> Dict[str, str]:
        if isinstance(self.session, requests.Session):
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in (403, 503):
                    if self.headless and SELENIUM:
                        return self._solve_with_selenium(url)
            except Exception:
                pass
        return {}

    def _solve_with_selenium(self, url: str) -> Dict[str, str]:
        driver = self._create_selenium_session()
        try:
            driver.get(url)
            time.sleep(5)
            cookies = driver.get_cookies()
            cookie_dict = {c['name']: c['value'] for c in cookies}
            driver.quit()
            return cookie_dict
        except Exception:
            return {}

    def get(self, url: str, **kwargs):
        if isinstance(self.session, requests.Session):
            return self.session.get(url, timeout=self.timeout, **kwargs)
        elif CURL_CFFI and isinstance(self.session, curl_requests.Session):
            return self.session.get(url, timeout=self.timeout, **kwargs)
        else:
            return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs):
        if isinstance(self.session, requests.Session):
            return self.session.post(url, timeout=self.timeout, **kwargs)
        elif CURL_CFFI and isinstance(self.session, curl_requests.Session):
            return self.session.post(url, timeout=self.timeout, **kwargs)
        else:
            return self.session.post(url, **kwargs)


def detect_waf(url: str) -> Optional[str]:
    try:
        from wafw00f.main import WafW00f
        detector = WafW00f(url)
        waf = detector.wafdetections
        if waf:
            return list(waf.keys())[0]
    except Exception:
        pass
    try:
        r = requests.get(url, timeout=5)
        server = r.headers.get("Server", "").lower()
        if "cloudflare" in server:
            return "cloudflare"
        if "akamai" in server:
            return "akamai"
        if r.status_code in (403, 503):
            return "generic_js_challenge"
    except Exception:
        pass
    return None