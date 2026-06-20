from __future__ import annotations

from dataclasses import dataclass

import pytest
import requests

from core.adaptive_agent import AdaptiveAgent
from core.connectors.base import BaseConnector
from core.engine import InjectionEngine
from core.transport import TransportError, send_with_retry


@dataclass
class _Response:
    status_code: int
    headers: dict | None = None

    def __post_init__(self):
        self.headers = self.headers or {}


def _http_error(status: int, headers: dict | None = None) -> requests.exceptions.HTTPError:
    response = _Response(status, headers)
    error = requests.exceptions.HTTPError(f"HTTP {status}")
    error.response = response
    return error


def test_shared_retry_retries_429_then_returns_real_response():
    calls = 0
    sleeps = []

    def send():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise _http_error(429)
        return "real target response"

    outcome = send_with_retry(send, max_attempts=3, sleep=sleeps.append, jitter=lambda *_: 0)
    assert outcome.ok is True
    assert outcome.response == "real target response"
    assert outcome.attempts == 3
    assert calls == 3
    assert sleeps == [1.0, 2.0]


def test_retry_after_is_honored_and_capped_without_extra_final_sleep():
    calls = 0
    sleeps = []

    def send():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise _http_error(429, {"Retry-After": "7"})
        return "ok"

    outcome = send_with_retry(
        send,
        max_attempts=3,
        max_retry_after_seconds=10,
        sleep=sleeps.append,
        jitter=lambda *_: 0,
    )
    assert outcome.ok
    assert calls == 2
    assert sleeps == [7.0]

    calls = 0
    sleeps = []

    def always_limited():
        nonlocal calls
        calls += 1
        raise _http_error(429)

    failed = send_with_retry(always_limited, max_attempts=3, sleep=sleeps.append, jitter=lambda *_: 0)
    assert not failed.ok
    assert failed.status_code == 429
    assert failed.attempts == 3
    assert calls == 3
    assert sleeps == [1.0, 2.0]


def test_non_retryable_http_error_fails_once():
    calls = 0

    def send():
        nonlocal calls
        calls += 1
        raise _http_error(401)

    outcome = send_with_retry(send, max_attempts=3, sleep=lambda _: pytest.fail("must not sleep"))
    assert not outcome.ok
    assert outcome.status_code == 401
    assert outcome.attempts == 1
    assert calls == 1


def test_rate_limiter_runs_once_for_every_network_attempt():
    class Limiter:
        calls = 0

        def wait(self):
            self.calls += 1

    limiter = Limiter()
    calls = 0

    def send():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise requests.exceptions.ConnectionError("temporary")
        return "ok"

    outcome = send_with_retry(send, max_attempts=3, rate_limiter=limiter, sleep=lambda _: None, jitter=lambda *_: 0)
    assert outcome.ok
    assert calls == 2
    assert limiter.calls == 2


class _Always429Connector(BaseConnector):
    def __init__(self):
        self.calls = 0

    def send(self, prompt, history=None):
        self.calls += 1
        raise _http_error(429)


class _PayloadManager:
    def __init__(self):
        self.weight_updates = []

    def get_payload(self, *args, **kwargs):
        return "probe"

    def update_weights(self, category, success):
        self.weight_updates.append((category, success))


class _NeverAnalyze:
    analysis_mode = "balanced"

    def __init__(self):
        self.calls = 0

    def analyze(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("transport errors must not be analyzed")


def test_engine_records_429_as_transport_error_without_scoring(monkeypatch):
    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    connector = _Always429Connector()
    payloads = _PayloadManager()
    analyzer = _NeverAnalyze()
    engine = InjectionEngine(connector, payloads, analyzer, workers=1)

    results = engine.run_campaign(rounds=1)
    assert connector.calls == 3
    assert analyzer.calls == 0
    assert payloads.weight_updates == []
    assert results[0]["transport_error"] is True
    assert results[0]["transport_status_code"] == 429
    assert results[0]["response"].startswith("TRANSPORT_ERROR:")


def test_attack_tree_stops_on_transport_failure_without_expanding(monkeypatch):
    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    connector = _Always429Connector()
    engine = InjectionEngine(
        connector,
        _PayloadManager(),
        _NeverAnalyze(),
        attack_tree=True,
        workers=1,
    )
    result = engine.run_campaign()
    assert connector.calls == 3
    assert len(result) == 1
    assert result[0]["transport_error"] is True


def test_adaptive_agent_does_not_analyze_transport_error(monkeypatch):
    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    connector = _Always429Connector()
    analyzer = _NeverAnalyze()
    agent = AdaptiveAgent(connector, analyzer)

    results = agent.run_adaptive_session(max_turns=1)
    assert connector.calls == 3
    assert analyzer.calls == 0
    assert results[0]["transport_error"] is True
    assert results[0]["response_class"] == "transport_error"


def test_http_connectors_raise_redacted_transport_error(monkeypatch):
    from core.connectors.openai import OpenAIConnector
    import core.connectors.openai as module

    secret = "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

    def fail(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError(f"upstream token={secret}")

    monkeypatch.setattr(module.requests, "post", fail)
    with pytest.raises(TransportError) as exc_info:
        OpenAIConnector("sk-test").send("hello")
    assert secret not in str(exc_info.value)
    assert exc_info.value.retryable is True


def test_legacy_error_string_is_not_analyzed_as_a_target_response():
    outcome = send_with_retry(lambda: "ERROR: 429 Too Many Requests", max_attempts=3)
    assert not outcome.ok
    assert outcome.attempts == 1
    assert outcome.display_response.startswith("TRANSPORT_ERROR:")


def test_rest_connector_429_reaches_engine_retry_and_only_real_response_is_analyzed(monkeypatch):
    from core.connectors.rest import RESTChatbotConnector

    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    calls = 0

    class Response:
        def __init__(self, status_code):
            self.status_code = status_code
            self.headers = {"content-type": "application/json"}
            self.text = '{"reply":"safe target response"}'

        def raise_for_status(self):
            if self.status_code == 429:
                error = requests.exceptions.HTTPError("429 Too Many Requests")
                error.response = self
                raise error

        def json(self):
            return {"reply": "safe target response"}

    connector = RESTChatbotConnector("https://example.test/chat")

    def request(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return Response(429 if calls < 3 else 200)

    monkeypatch.setattr(connector.session, "request", request)

    class Analyzer:
        analysis_mode = "balanced"
        responses = []

        def analyze(self, payload, response, baseline_response=None):
            self.responses.append(response)
            return {
                "success": False,
                "confidence": 0.0,
                "method": "none",
                "severity": "Info",
                "leak_category": "",
                "analysis_mode": "balanced",
                "decision_reason": "safe",
                "evidence": [],
                "leaked_data": [],
                "language": "en",
            }

    analyzer = Analyzer()
    payloads = _PayloadManager()
    engine = InjectionEngine(connector, payloads, analyzer, workers=1)
    result = engine.run_campaign(rounds=1)

    assert calls == 3
    assert analyzer.responses == ["safe target response"]
    assert result[0]["transport_error"] is False
    assert payloads.weight_updates == [("basic", False)]


def test_all_builtin_connectors_follow_raised_error_contract():
    from pathlib import Path

    connector_dir = Path("core/connectors")
    names = ["openai.py", "claude.py", "gemini.py", "cohere.py", "huggingface.py", "graphql.py", "ollama.py", "rest.py", "sse.py"]
    for name in names:
        source = (connector_dir / name).read_text(encoding="utf-8")
        assert 'return f"ERROR:' not in source
        assert "return 'ERROR:" not in source


def test_campaign_circuit_breaker_stops_later_rounds_after_exhausted_429s(monkeypatch):
    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    connector = _Always429Connector()
    payloads = _PayloadManager()
    analyzer = _NeverAnalyze()
    engine = InjectionEngine(
        connector,
        payloads,
        analyzer,
        workers=1,
        max_consecutive_rate_limits=2,
    )

    results = engine.run_campaign(rounds=5)
    # Two exhausted rounds x three attempts; remaining queued rounds are blocked
    # before a network call and cannot amplify throttling.
    assert connector.calls == 6
    assert len(results) == 5
    assert [item["transport_attempts"] for item in results] == [3, 3, 0, 0, 0]
    assert all(item["transport_error"] for item in results)


def test_engine_resets_rate_limit_circuit_between_campaigns(monkeypatch):
    monkeypatch.setattr("core.transport.time.sleep", lambda _: None)
    connector = _Always429Connector()
    engine = InjectionEngine(
        connector,
        _PayloadManager(),
        _NeverAnalyze(),
        workers=1,
        max_consecutive_rate_limits=1,
    )
    engine.run_campaign(rounds=2)
    assert connector.calls == 3

    engine.run_campaign(rounds=1)
    # The next independent campaign gets a fresh request budget rather than an
    # inherited open circuit.
    assert connector.calls == 6
