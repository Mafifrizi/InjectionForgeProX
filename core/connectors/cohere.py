import requests
from .base import BaseConnector
from ..redaction import redact_text

class CohereConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "command-r-plus", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.cohere.ai/v1/generate"

    def send(self, prompt: str, history=None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {"model": self.model, "prompt": prompt, "max_tokens": 256, "temperature": 0.7}
        try:
            r = requests.post(self.url, headers=headers, json=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["generations"][0]["text"]
        except Exception as e:
            return f"ERROR: {redact_text(str(e))}"