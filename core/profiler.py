import re
from typing import Dict, Optional

import requests

from .rate_limiter import TokenBucketRateLimiter


class TargetProfiler:
    """Low-noise target classification.

    Active GraphQL introspection is intentionally opt-in because it can fall
    outside an engagement's permitted discovery scope. Every HTTP request made
    by the profiler passes through the shared rate limiter when provided.
    """

    def __init__(
        self,
        endpoint: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        timeout: int = 10,
        insecure: bool = False,
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        allow_graphql_introspection: bool = False,
    ):
        self.endpoint = endpoint
        self.method = method.upper()
        self.headers = headers or {}
        self.timeout = timeout
        self.insecure = insecure
        self.rate_limiter = rate_limiter
        self.allow_graphql_introspection = allow_graphql_introspection
        self.profile = self._profile()

    def _request(self, method: str, *args, **kwargs):
        if self.rate_limiter:
            self.rate_limiter.wait()
        return requests.request(method, *args, **kwargs)

    def _profile(self) -> Dict:
        if not self.endpoint:
            return {"type": "unknown", "strategy": "basic", "payload_cat": "basic"}
        try:
            if self.method == "GET":
                r = self._request(
                    "GET", self.endpoint, headers=self.headers,
                    timeout=self.timeout, verify=not self.insecure,
                )
            else:
                r = self._request(
                    "POST", self.endpoint, json={"message": "ping"},
                    headers=self.headers, timeout=self.timeout,
                    verify=not self.insecure,
                )
            body = r.text[:1000]
            resp_headers = r.headers
        except Exception:
            return {"type": "unknown", "strategy": "basic", "payload_cat": "basic"}

        if self._is_graphql(body):
            return {"type": "graphql", "strategy": "graphql_injection", "payload_cat": "graphql"}
        if self._is_openai_api(body, resp_headers):
            return {"type": "openai_api", "strategy": "advanced", "payload_cat": "advanced"}
        if self._is_langchain_agent(body):
            return {"type": "langchain_agent", "strategy": "multi_turn", "payload_cat": "agent"}
        if self._has_tool_calling(body):
            return {"type": "agent_with_tools", "strategy": "agent_takeover", "payload_cat": "agent"}
        if self._is_dialogflow(body):
            return {"type": "dialogflow", "strategy": "single", "payload_cat": "indirect"}
        if self._is_websocket():
            return {"type": "websocket_chatbot", "strategy": "fragmentation", "payload_cat": "indirect"}
        if self._has_csrf_protection(resp_headers):
            return {"type": "web_chatbot_with_csrf", "strategy": "auto_login", "payload_cat": "basic"}
        if "text/html" in resp_headers.get("content-type", ""):
            return {"type": "web_chatbot", "strategy": "single", "payload_cat": "basic"}

        return {"type": "generic", "strategy": "basic", "payload_cat": "basic"}

    def _is_graphql(self, body: str) -> bool:
        if '"errors"' in body or "graphql" in body.lower():
            return True
        if not self.allow_graphql_introspection:
            return False
        try:
            r = self._request(
                "POST", self.endpoint,
                json={"query": "{__schema{types{name}}}"},
                headers=self.headers, timeout=5,
                verify=not self.insecure,
            )
            return r.status_code == 200 and '"data"' in r.text
        except Exception:
            return False

    def _is_openai_api(self, body, headers):
        return "chat.completions" in body or "openai" in str(headers).lower()

    def _is_langchain_agent(self, body):
        return "langchain" in body.lower() or "agent" in body.lower()

    def _has_tool_calling(self, body):
        return bool(re.search(r"tool_calls|function_call|action\s*:", body, re.IGNORECASE))

    def _is_dialogflow(self, body):
        return "query_input" in body or "dialogflow" in body.lower()

    def _is_websocket(self):
        return self.endpoint.startswith("wss://") or self.endpoint.startswith("ws://")

    def _has_csrf_protection(self, headers):
        return "csrf" in str(headers).lower() or "xsrf" in str(headers).lower()
