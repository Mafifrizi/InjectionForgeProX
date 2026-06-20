import json
import time
from typing import Dict, List, Optional

import requests
from sseclient import SSEClient

from .base import BaseConnector
from ..redaction import redact_text


class SSEConnector(BaseConnector):
    """Connector for server-sent event chat endpoints.

    The connector bounds both the total stream lifetime and the number of
    events. A hostile or faulty endpoint cannot keep a worker occupied forever
    by emitting heartbeat events without sending ``[DONE]``.
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
                    return "ERROR: SSE stream exceeded safety limit"
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
            return "".join(full_text) or "ERROR: No SSE response"
        except requests.RequestException as exc:
            return f"ERROR: {redact_text(str(exc))}"
        except Exception as exc:
            return f"ERROR: {redact_text(str(exc))}"
        finally:
            if response is not None:
                response.close()
