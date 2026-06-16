import requests
import json
from typing import Optional, List, Dict
from .base import BaseConnector

class OllamaConnector(BaseConnector):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3",
                 timeout: int = 60, **kwargs):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.generate_url = f"{self.base_url}/api/generate"

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 256,
                "temperature": 0.7
            }
        }
        try:
            r = requests.post(self.generate_url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            return r.json().get("response", "")
        except Exception as e:
            return f"ERROR: {e}"