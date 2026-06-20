import requests
from .base import BaseConnector
from ..transport import transport_error_from_exception


class OpenAIConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.openai.com/v1/chat/completions"

    def send(self, prompt: str, history=None) -> str:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            messages = list(history) if history else []
            messages.append({"role": "user", "content": prompt})
            response = requests.post(
                self.url,
                headers=headers,
                json={"model": self.model, "messages": messages, "temperature": 0.7},
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
