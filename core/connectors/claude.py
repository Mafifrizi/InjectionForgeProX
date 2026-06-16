import requests
from .base import BaseConnector

class ClaudeConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.anthropic.com/v1/messages"

    def send(self, prompt: str, history=None) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        messages = list(history) if history else []
        messages.append({"role": "user", "content": prompt})
        data = {"model": self.model, "max_tokens": 256, "messages": messages}
        try:
            r = requests.post(self.url, headers=headers, json=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["content"][0]["text"]
        except Exception as e:
            return f"ERROR: {e}"