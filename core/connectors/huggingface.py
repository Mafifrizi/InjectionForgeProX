import requests
from .base import BaseConnector
from ..redaction import redact_text

class HuggingFaceConnector(BaseConnector):
    def __init__(self, endpoint: str, api_key: str = "", timeout: int = 30, **kwargs):
        self.url = endpoint
        self.api_key = api_key
        self.timeout = timeout

    def send(self, prompt: str, history=None) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = {"inputs": prompt, "parameters": {"max_new_tokens": 256}}
        try:
            r = requests.post(self.url, headers=headers, json=data, timeout=self.timeout)
            r.raise_for_status()
            resp = r.json()
            if isinstance(resp, list) and "generated_text" in resp[0]:
                return resp[0]["generated_text"]
            elif isinstance(resp, dict) and "generated_text" in resp:
                return resp["generated_text"]
            return str(resp)
        except Exception as e:
            return f"ERROR: {redact_text(str(e))}"