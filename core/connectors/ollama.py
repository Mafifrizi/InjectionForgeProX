import requests
import time
import logging
from typing import Optional, List, Dict
from .base import BaseConnector
from ..redaction import redact_text

logger = logging.getLogger("InjectionForgeX.Ollama")

class OllamaConnector(BaseConnector):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3",
                 timeout: int = 60, **kwargs):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.generate_url = f"{self.base_url}/api/generate"

    def send(self, prompt: str, history: Optional[List[Dict]] = None, retries: int = 2) -> str:
        # Gabungkan history jika ada
        full_prompt = prompt
        if history:
            history_text = "\n".join(
                f"{'User' if h['role'] == 'user' else 'Assistant'}: {h['content']}"
                for h in history
            )
            full_prompt = f"{history_text}\nUser: {prompt}\nAssistant:"

        payload = {
            "model": self.model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "num_predict": 128,   # Lebih pendek → lebih cepat
                "temperature": 0.7
            }
        }

        last_exc = None
        for attempt in range(retries + 1):
            logger.debug("Mengirim request ke Ollama (%s): prompt=%d bytes (attempt %d)", self.base_url, len(full_prompt), attempt + 1)
            try:
                r = requests.post(self.generate_url, json=payload, timeout=self.timeout)
                r.raise_for_status()
                response = r.json().get("response", "")
                logger.debug("Respons Ollama diterima: %d bytes", len(response))
                return response
            except requests.exceptions.Timeout:
                logger.warning(f"Request ke Ollama timeout ({self.timeout}s). Mencoba lagi...")
                last_exc = "timeout"
                if attempt < retries:
                    time.sleep(2 ** attempt)  # backoff 1s, 2s
                else:
                    return f"ERROR: Request timeout setelah {retries+1} percobaan"
            except Exception as e:
                logger.error("Gagal mengirim ke Ollama: %s", redact_text(str(e)))
                return f"ERROR: {redact_text(str(e))}"

        return f"ERROR: {last_exc}"