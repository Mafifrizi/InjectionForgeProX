import requests
from .base import BaseConnector

class OpenAIConnector(BaseConnector):
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", timeout: int = 30, **kwargs):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.url = "https://api.openai.com/v1/chat/completions"

    def send(self, prompt: str, history=None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        messages = list(history) if history else []
        messages.append({"role": "user", "content": prompt})
        data = {"model": self.model, "messages": messages, "temperature": 0.7}
        try:
            r = requests.post(self.url, headers=headers, json=data, timeout=self.timeout)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"ERROR: {e}"