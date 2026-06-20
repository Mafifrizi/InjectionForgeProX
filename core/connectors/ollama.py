import logging
from typing import Optional, List, Dict

import requests

from .base import BaseConnector
from ..transport import transport_error_from_exception

logger = logging.getLogger("InjectionForgeX.Ollama")


class OllamaConnector(BaseConnector):
    """Ollama connector using the shared caller-side retry policy."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3",
                 timeout: int = 60, **kwargs):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.generate_url = f"{self.base_url}/api/generate"

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        try:
            full_prompt = prompt
            if history:
                history_text = "\n".join(
                    f"{'User' if item['role'] == 'user' else 'Assistant'}: {item['content']}"
                    for item in history
                )
                full_prompt = f"{history_text}\nUser: {prompt}\nAssistant:"

            logger.debug("Sending Ollama request to %s: prompt=%d bytes", self.base_url, len(full_prompt))
            response = requests.post(
                self.generate_url,
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"num_predict": 128, "temperature": 0.7},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            text = response.json().get("response", "")
            logger.debug("Ollama response received: %d bytes", len(text))
            return text
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
