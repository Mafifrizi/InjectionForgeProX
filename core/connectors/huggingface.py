import requests
from .base import BaseConnector
from ..transport import transport_error_from_exception


class HuggingFaceConnector(BaseConnector):
    def __init__(self, endpoint: str, api_key: str = "", timeout: int = 30, **kwargs):
        self.url = endpoint
        self.api_key = api_key
        self.timeout = timeout

    def send(self, prompt: str, history=None) -> str:
        try:
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            response = requests.post(
                self.url,
                headers=headers,
                json={"inputs": prompt, "parameters": {"max_new_tokens": 256}},
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, list) and payload and "generated_text" in payload[0]:
                return payload[0]["generated_text"]
            if isinstance(payload, dict) and "generated_text" in payload:
                return payload["generated_text"]
            return str(payload)
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
