import json
import requests
from typing import Optional, List, Dict
from .base import BaseConnector
from ..redaction import redact_text

class GraphQLConnector(BaseConnector):
    def __init__(self, endpoint: str, api_key: str = "",
                headers: Optional[Dict[str, str]] = None,
                operation_name: Optional[str] = None,
                 timeout: int = 30, insecure: bool = False, **kwargs):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = dict(headers or {})
        self.operation_name = operation_name
        self.timeout = timeout
        self.verify_ssl = not insecure
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def send(self, prompt: str, history=None) -> str:
        if "{" not in prompt and "query" not in prompt.lower():
            graphql_query = '{ echo(message: ' + json.dumps(prompt) + ') }'
        else:
            graphql_query = prompt

        payload = {
            "query": graphql_query,
            "operationName": self.operation_name
        }
        try:
            resp = requests.post(self.endpoint, json=payload,
                                headers=self.headers, timeout=self.timeout,
                                verify=self.verify_ssl)
            resp.raise_for_status()
            data = resp.json()
            if "data" in data:
                return json.dumps(data["data"])
            elif "errors" in data:
                return json.dumps(data["errors"])
            return json.dumps(data)
        except Exception as e:
            return f"ERROR: {redact_text(str(e))}"