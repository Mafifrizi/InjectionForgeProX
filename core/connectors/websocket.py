import json
import logging
import ssl
import threading
from typing import Dict, List, Optional
from urllib.parse import urlparse

import websocket

from .base import BaseConnector
from ..redaction import redact_text

logger = logging.getLogger("InjectionForgeX.websocket")


class WebSocketConnector(BaseConnector):
    """WebSocket connector with bounded waits and redaction-safe logging."""

    def __init__(
        self,
        endpoint: str,
        timeout: int = 5,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
        api_key: str = "",
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        **kwargs,
    ):
        self.endpoint = endpoint
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.cookie = cookie
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.messages: List[str] = []

    def _header_lines(self) -> List[str]:
        headers = dict(self.headers)
        if self.api_key:
            headers.setdefault("Authorization", self.api_key if self.api_key.startswith("Bearer ") else f"Bearer {self.api_key}")
        return [f"{key}: {value}" for key, value in headers.items()]

    def _run_kwargs(self) -> dict:
        kwargs: dict = {}
        if self.endpoint.lower().startswith("wss://") and not self.verify_ssl:
            kwargs["sslopt"] = {"cert_reqs": ssl.CERT_NONE}
        if self.proxy:
            parsed = urlparse(self.proxy)
            if parsed.hostname:
                kwargs["http_proxy_host"] = parsed.hostname
                if parsed.port:
                    kwargs["http_proxy_port"] = parsed.port
                if parsed.username:
                    kwargs["http_proxy_auth"] = (parsed.username, parsed.password or "")
        return kwargs

    def on_message(self, ws, message):
        # Do not turn connector logs into a second copy of a target response.
        logger.info("WS RECV: %d bytes", len(str(message)))
        self.messages.append(str(message))

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        messages: List[str] = []
        connected = threading.Event()
        received = threading.Event()

        def on_open(ws):
            connected.set()

        def on_message(ws, message):
            logger.info("WS RECV: %d bytes", len(str(message)))
            messages.append(str(message))
            received.set()

        def on_error(ws, error):
            logger.error("WS error: %s", redact_text(str(error)))
            connected.set()
            received.set()

        ws = websocket.WebSocketApp(
            self.endpoint,
            header=self._header_lines(),
            cookie=self.cookie,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
        )
        wst = threading.Thread(target=lambda: ws.run_forever(**self._run_kwargs()), daemon=True)
        wst.start()

        try:
            if not connected.wait(timeout=self.timeout):
                return "ERROR: WebSocket connection timeout"

            payload = json.dumps({"message": prompt})
            logger.info("WS SEND: %d bytes", len(payload))
            ws.send(payload)
            received.wait(timeout=self.timeout)
        except Exception as e:
            logger.error("WS error: %s", redact_text(str(e)))
            return f"ERROR: {redact_text(str(e))}"
        finally:
            ws.close()
            wst.join(timeout=min(1.0, float(self.timeout)))

        self.messages = messages
        if messages:
            return " | ".join(messages)
        return "ERROR: No WebSocket response"
