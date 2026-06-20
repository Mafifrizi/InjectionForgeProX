import json
import time
from typing import Dict, List, Optional

import requests
from sseclient import SSEClient

from .base import BaseConnector
from ..transport import TransportError, transport_error_from_exception


class SSEConnector(BaseConnector):
    """Connector for server-sent event chat endpoints.

    Request failures propagate into the shared retry layer. Stream safety
    failures are typed non-retryable transport errors rather than fake chatbot
    responses.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str = "",
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        max_events: int = 1000,
        **kwargs,
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = dict(headers or {})
        self.timeout = max(1, int(timeout or 30))
        self.verify_ssl = verify_ssl
        self.max_events = max(1, min(int(max_events or 1000), 10000))

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        headers = dict(self.headers)
        if self.api_key:
            headers.setdefault("Authorization", f"Bearer {self.api_key}")
        payload = {"prompt": prompt}
        if history:
            payload["history"] = history

        response = None
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers=headers,
                stream=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            client = SSEClient(response)
            full_text: List[str] = []
            deadline = time.monotonic() + self.timeout
            for event_number, event in enumerate(client.events(), start=1):
                if event_number > self.max_events or time.monotonic() >= deadline:
                    raise TransportError("SSE stream exceeded safety limit", retryable=False)
                if not event.data:
                    continue
                if event.data.strip() == "[DONE]":
                    break
                try:
                    data = json.loads(event.data)
                    if "choices" in data:
                        for choice in data["choices"]:
                            delta = choice.get("delta") or {}
                            if isinstance(delta, dict) and delta.get("content"):
                                full_text.append(str(delta["content"]))
                            elif choice.get("text"):
                                full_text.append(str(choice["text"]))
                    elif data.get("text"):
                        full_text.append(str(data["text"]))
                    elif data.get("message"):
                        full_text.append(str(data["message"]))
                except (json.JSONDecodeError, TypeError, AttributeError):
                    full_text.append(event.data)
            if not full_text:
                raise TransportError("No SSE response", retryable=True)
            return "".join(full_text)
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
        finally:
            if response is not None:
                response.close()
