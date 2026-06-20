import requests
from .base import BaseConnector
from ..transport import transport_error_from_exception


class CohereConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "command-r-plus", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.cohere.ai/v1/generate"

    def send(self, prompt: str, history=None) -> str:
        try:
            response = requests.post(
                self.url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model, "prompt": prompt, "max_tokens": 256, "temperature": 0.7},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["generations"][0]["text"]
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
