import websocket
import json
import threading
import logging
from typing import Optional, List, Dict
from .base import BaseConnector

logger = logging.getLogger("InjectionForgeX.websocket")


class WebSocketConnector(BaseConnector):
    def __init__(self, endpoint: str, timeout: int = 5, **kwargs):
        self.endpoint = endpoint
        self.timeout = timeout
        self.messages = []

    def on_message(self, ws, message):
        logger.info(f"WS RECV: {message}")
        self.messages.append(message)

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        messages = []
        connected = threading.Event()
        received = threading.Event()

        def on_open(ws):
            connected.set()

        def on_message(ws, message):
            logger.info(f"WS RECV: {message}")
            messages.append(message)
            received.set()

        def on_error(ws, error):
            logger.error(f"WS error: {error}")
            connected.set()
            received.set()

        ws = websocket.WebSocketApp(
            self.endpoint,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
        )
        wst = threading.Thread(target=ws.run_forever)
        wst.daemon = True
        wst.start()

        try:
            if not connected.wait(timeout=self.timeout):
                return "ERROR: WebSocket connection timeout"

            payload = json.dumps({"message": prompt})
            logger.info(f"WS SEND: {payload}")
            ws.send(payload)
            received.wait(timeout=self.timeout)
        except Exception as e:
            logger.error(f"WS error: {e}")
            return f"ERROR: {e}"
        finally:
            ws.close()

        self.messages = messages
        if messages:
            return " | ".join(messages)
        return "ERROR: No WebSocket response"
