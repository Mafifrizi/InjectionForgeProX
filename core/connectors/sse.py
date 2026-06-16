import requests
import json
from typing import Optional, List, Dict
from sseclient import SSEClient
from .base import BaseConnector

class SSEConnector(BaseConnector):
    def __init__(self, endpoint: str, api_key: str = "", headers: dict = None, timeout: int = 30, **kwargs):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = headers or {}
        self.timeout = timeout

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {"prompt": prompt}
        response = requests.post(self.endpoint, json=payload, headers=self.headers, stream=True, timeout=self.timeout)
        client = SSEClient(response)
        full_text = []
        for event in client.events():
            if event.data and event.data != "[DONE]":
                try:
                    data = json.loads(event.data)
                    if "choices" in data:
                        for choice in data["choices"]:
                            if "delta" in choice and "content" in choice["delta"]:
                                full_text.append(choice["delta"]["content"])
                            elif "text" in choice:
                                full_text.append(choice["text"])
                    elif "text" in data:
                        full_text.append(data["text"])
                except json.JSONDecodeError:
                    full_text.append(event.data)
        return "".join(full_text)