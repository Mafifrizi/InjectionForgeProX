import requests
from .base import BaseConnector

class GeminiConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "gemini-pro", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def send(self, prompt: str, history=None) -> str:
        headers = {"Content-Type": "application/json"}
        params = {"key": self.api_key}
        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 256}
        }
        try:
            r = requests.post(self.url, headers=headers, params=params, json=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            return f"ERROR: {e}"