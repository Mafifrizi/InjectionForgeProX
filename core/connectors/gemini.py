import requests
from .base import BaseConnector
from ..transport import transport_error_from_exception


class GeminiConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "gemini-pro", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def send(self, prompt: str, history=None) -> str:
        try:
            response = requests.post(
                self.url,
                headers={"Content-Type": "application/json"},
                params={"key": self.api_key},
                json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": 256}},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
