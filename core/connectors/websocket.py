import websocket
import json
import time
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
        self.messages = []
        ws = websocket.WebSocketApp(
            self.endpoint,
            on_message=self.on_message
        )
        wst = threading.Thread(target=ws.run_forever)
        wst.daemon = True
        wst.start()
        time.sleep(1)  # wait for connection

        try:
            payload = json.dumps({"message": prompt})
            logger.info(f"WS SEND: {payload}")
            ws.send(payload)
            time.sleep(self.timeout)
        except Exception as e:
            logger.error(f"WS error: {e}")
        finally:
            ws.close()

        if self.messages:
            # Gabungkan semua pesan yang diterima
            return " | ".join(self.messages)
        return "ERROR: No WebSocket response"