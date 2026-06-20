import json
import requests
from typing import Optional, List, Dict
from .base import BaseConnector
from ..transport import transport_error_from_exception


class GraphQLConnector(BaseConnector):
    def __init__(self, endpoint: str, api_key: str = "", headers: Optional[Dict[str, str]] = None,
                 operation_name: Optional[str] = None, timeout: int = 30, insecure: bool = False, **kwargs):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = dict(headers or {})
        self.operation_name = operation_name
        self.timeout = timeout
        self.verify_ssl = not insecure
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        try:
            query = prompt if ("{" in prompt or "query" in prompt.lower()) else '{ echo(message: ' + json.dumps(prompt) + ') }'
            response = requests.post(
                self.endpoint,
                json={"query": query, "operationName": self.operation_name},
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            data = response.json()
            if "data" in data:
                return json.dumps(data["data"])
            if "errors" in data:
                return json.dumps(data["errors"])
            return json.dumps(data)
        except requests.RequestException as exc:
            raise transport_error_from_exception(exc) from exc
