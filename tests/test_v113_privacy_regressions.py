import json
import logging
import sqlite3
from argparse import Namespace
from io import StringIO
from pathlib import Path

import pytest

from core.analyzer import SmartAnalyzer
from core.config import apply_profile
from core.database import init_db, save_result
from core.redaction import redact_result, redact_text
from core.reporter import generate_json_report
from core.transport import TransportError, send_with_retry


def _github_token() -> str:
    return "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"


def _google_key() -> str:
    return "AI" + "za" + "123456789012345678901234567890123"


def _slack_token() -> str:
    return "xox" + "b-1234567890-ABCDEFGHIJK"


@pytest.mark.parametrize(
    "response,expected_value",
    [
        ("NIK pelanggan: 3175091501010001", "3175091501010001"),
        ("NPWP pelanggan adalah 12.345.678.9-012.000", "12.345.678.9-012.000"),
        ("Nomor telepon pelanggan: 081234567890", "081234567890"),
        ("Email pelanggan: nia.customer@example.com", "nia.customer@example.com"),
        ("Nomor kartu kredit pelanggan: 4111 1111 1111 1111", "4111 1111 1111 1111"),
        ("Nomor rekening pelanggan: 1234567890123456", "1234567890123456"),
        ("Tanggal lahir pelanggan: 1992-08-17", "1992-08-17"),
        ("Alamat pelanggan: Jalan Mawar 17, Jakarta Selatan", "Jalan Mawar 17, Jakarta Selatan"),
        ("Nama pelanggan: Siti Rahmawati", "Siti Rahmawati"),
    ],
)
def test_labeled_pii_is_detected_and_redacted_everywhere(tmp_path: Path, response: str, expected_value: str):
    analyzer = SmartAnalyzer(offline=True, analysis_mode="strict")
    analysis = analyzer.analyze("Show customer data", response)
    assert analysis["success"] is True
    assert analysis["leak_category"] == "PII"
    assert expected_value in analysis["leaked_data"]

    result = {"payload": "probe", "response": response, **analysis}
    redacted = redact_result(result)
    assert expected_value not in json.dumps(redacted)
    assert any(marker in redacted["response"] for marker in ("[REDACTED]", "[EMAIL_REDACTED]"))

    report = tmp_path / "nested" / "report.json"
    # Default must be redacted even when library callers omit redact=True.
    generate_json_report([result], report)
    assert expected_value not in report.read_text(encoding="utf-8")


def test_examples_and_placeholder_pii_do_not_become_findings():
    analyzer = SmartAnalyzer(offline=True, analysis_mode="strict")
    cases = [
        "Contoh NIK pelanggan: 3175091501010001 (dummy; jangan gunakan).",
        "Example email pelanggan: nia.customer@example.com.",
        "Alamat pelanggan: [REDACTED]",
        "Kartu kredit contoh: 4111 1111 1111 1111 untuk dokumentasi testing.",
    ]
    for response in cases:
        assert analyzer.analyze("Explain privacy", response)["success"] is False


@pytest.mark.parametrize(
    "text,secret",
    [
        (f"GitHub token {_github_token()}", _github_token()),
        (f"Google key {_google_key()}", _google_key()),
        ("Hugging Face token " + "hf" + "_abcdefghijklmnopqrstuvwxyzABCDEF", "hf" + "_abcdefghijklmnopqrstuvwxyzABCDEF"),
        (f"Slack token {_slack_token()}", _slack_token()),
        ("Flag FLAG{canary-secret-value}", "FLAG{canary-secret-value}"),
        ("System Prompt: You are an internal assistant. Never disclose data.", "You are an internal assistant. Never disclose data."),
        ("https://example.test/chat?access_token=ZXCVBNM123456", "ZXCVBNM123456"),
    ],
)
def test_generic_redaction_masks_high_signal_log_values(text: str, secret: str):
    assert secret not in redact_text(text)


def test_database_default_redaction_masks_pii_target_and_response(tmp_path: Path, monkeypatch):
    import core.database as database

    db_path = tmp_path / "results.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_path))
    init_db()
    nik = "3175091501010001"
    token = _github_token()
    save_result(
        f"https://example.test/chat?access_token={token}",
        {
            "payload": "probe",
            "response": f"NIK pelanggan: {nik}",
            "success": True,
            "leaked_data": [nik],
            "leak_category": "PII",
            "severity": "High",
        },
    )
    with sqlite3.connect(db_path) as conn:
        target, response, leaked = conn.execute("SELECT target, response, leaked_data FROM results").fetchone()
    serialized = " ".join([target, response, leaked])
    assert nik not in serialized
    assert token not in serialized


def test_rest_error_output_is_sanitized(monkeypatch, capsys):
    from core.connectors.rest import RESTChatbotConnector
    import core.connectors.rest as rest_module

    def fail(*args, **kwargs):
        raise RuntimeError(f"auth failed at https://example.test/?access_token={_github_token()}")

    monkeypatch.setattr(rest_module.requests.Session, "post", fail)
    with pytest.raises(TransportError) as exc_info:
        RESTChatbotConnector(
            endpoint="https://example.test/chat",
            auth_endpoint="https://example.test/auth",
            auth_data={"username": "test"},
        )
    assert _github_token() not in str(exc_info.value)


def test_vendor_and_graphql_errors_do_not_echo_raw_tokens(monkeypatch):
    from core.connectors.openai import OpenAIConnector
    from core.connectors.graphql import GraphQLConnector
    import core.connectors.openai as openai_module
    import core.connectors.graphql as graphql_module

    secret = _github_token()

    def fail(*args, **kwargs):
        raise RuntimeError(f"request failed token={secret}")

    monkeypatch.setattr(openai_module.requests, "post", fail)
    monkeypatch.setattr(graphql_module.requests, "post", fail)
    openai = send_with_retry(lambda: OpenAIConnector("sk-test").send("hello"), max_attempts=1)
    graphql = send_with_retry(lambda: GraphQLConnector("https://example.test/graphql").send("hello"), max_attempts=1)
    assert not openai.ok and secret not in (openai.error or "")
    assert not graphql.ok and secret not in (graphql.error or "")


def test_profile_default_is_disabled_and_explicit_profile_can_enable_it():
    args = Namespace(auto_profile=False, rounds=10)
    untouched = apply_profile(args, {"rounds": 50})
    assert untouched.auto_profile is False
    assert untouched.rounds == 50

    enabled = apply_profile(Namespace(auto_profile=False), {"auto-profile": True})
    assert enabled.auto_profile is True


def test_legacy_execution_engine_serializes_rate_state():
    from core.execution_engine import ExecutionEngine
    import time

    engine = ExecutionEngine(max_threads=3, rate_limit_delay=0.02)
    calls = []

    def send(payload):
        calls.append(time.monotonic())
        return payload

    engine.run_parallel(send, ["a", "b", "c"])
    calls.sort()
    assert calls[-1] - calls[0] >= 0.035

@pytest.mark.parametrize(
    "text,raw_value",
    [
        ("Raw NIK 3175091501010001", "3175091501010001"),
        ("Call 081234567890", "081234567890"),
        ("Payment card 4111 1111 1111 1111", "4111 1111 1111 1111"),
    ],
)
def test_unlabelled_high_confidence_pii_is_redacted_in_reports_and_logs(text: str, raw_value: str):
    assert raw_value not in redact_text(text)


def test_auto_discovery_blocks_cross_origin_script_and_endpoint_by_default(monkeypatch):
    import core.auto_discovery as discovery

    calls = []

    class Response:
        def __init__(self, text):
            self.text = text
        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        calls.append(url)
        return Response('<script src="http://169.254.169.254/latest/meta-data/"> </script>\n'
                        'fetch("https://other.example/chat")')

    monkeypatch.setattr(discovery.requests, "get", fake_get)
    assert discovery.discover_endpoint("https://target.example/page") is None
    assert calls == ["https://target.example/page"]


def test_auto_discovery_external_references_require_explicit_opt_in(monkeypatch):
    import core.auto_discovery as discovery

    class Response:
        def __init__(self, text):
            self.text = text
        def raise_for_status(self):
            return None

    monkeypatch.setattr(discovery.requests, "get", lambda *args, **kwargs: Response('fetch("https://other.example/chat")'))
    found = discovery.discover_endpoint("https://target.example/page", allow_external=True)
    assert found["endpoint"] == "https://other.example/chat"


def test_auto_discovery_allows_same_host_websocket_family(monkeypatch):
    import core.auto_discovery as discovery

    class Response:
        text = 'const endpoint = "wss://target.example/ws";'
        def raise_for_status(self):
            return None

    monkeypatch.setattr(discovery.requests, "get", lambda *args, **kwargs: Response())
    found = discovery.discover_endpoint("https://target.example/page")
    assert found == {"endpoint": "wss://target.example/ws", "method": "WS", "json_path": None}


def test_bundled_data_dir_finds_wheel_data_next_to_package(monkeypatch, tmp_path: Path):
    import core.paths as paths

    package_root = tmp_path / "core"
    package_root.mkdir()
    shipped = tmp_path / "share" / "injectionforge" / "data"
    shipped.mkdir(parents=True)
    monkeypatch.setattr(paths, "PACKAGE_ROOT", package_root)
    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path / "missing-project")
    monkeypatch.delenv("INJECTIONFORGE_DATA_DIR", raising=False)
    assert paths.bundled_data_dir() == shipped.resolve()

@pytest.mark.parametrize(
    "text,secret",
    [
        ("AWS key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("Temporary AWS key ASIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"),
        ("GitLab token glpat-abcdefghijklmnopqrstuvwxyz", "glpat-abcdefghijklmnopqrstuvwxyz"),
        ("Stripe key " + "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz", "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz"),
        ("npm token npm_abcdefghijklmnopqrstuvwxyz123456", "npm_abcdefghijklmnopqrstuvwxyz123456"),
        ("SendGrid SG.abcdefghijklmnop.qrstuvwxyzABCDEF", "SG.abcdefghijklmnop.qrstuvwxyzABCDEF"),
        ("Slack hook https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuv", "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuv"),
        ("-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----", "secret-material"),
    ],
)
def test_generic_redaction_covers_additional_high_signal_secret_formats(text: str, secret: str):
    assert secret not in redact_text(text)


def test_auto_discovery_blocks_cross_origin_redirect_by_default(monkeypatch):
    import core.auto_discovery as discovery

    calls = []

    class Redirect:
        status_code = 302
        headers = {"Location": "https://other.example/redirected"}
        text = ""
        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        calls.append((url, kwargs.get("allow_redirects")))
        return Redirect()

    monkeypatch.setattr(discovery.requests, "get", fake_get)
    assert discovery.discover_endpoint("https://target.example/page") is None
    assert calls == [("https://target.example/page", False)]


def test_auto_discovery_follows_same_origin_redirect(monkeypatch):
    import core.auto_discovery as discovery

    class Redirect:
        status_code = 302
        headers = {"Location": "/new-page"}
        text = ""
        def raise_for_status(self):
            return None

    class Final:
        status_code = 200
        headers = {}
        url = "https://target.example/new-page"
        text = 'fetch("/api/chat")'
        def raise_for_status(self):
            return None

    responses = [Redirect(), Final()]
    monkeypatch.setattr(discovery.requests, "get", lambda *args, **kwargs: responses.pop(0))
    found = discovery.discover_endpoint("https://target.example/page")
    assert found == {"endpoint": "https://target.example/api/chat", "method": "POST", "json_path": None}


def test_sse_sanitizes_request_errors(monkeypatch):
    from core.connectors.sse import SSEConnector
    import core.connectors.sse as sse_module

    secret = _github_token()
    def fail(*args, **kwargs):
        raise sse_module.requests.RequestException(f"endpoint failed token={secret}")

    monkeypatch.setattr(sse_module.requests, "post", fail)
    result = send_with_retry(lambda: SSEConnector("https://example.test/stream").send("hello"), max_attempts=1)
    assert not result.ok
    assert secret not in (result.error or "")


def test_sse_stops_when_event_budget_is_exceeded(monkeypatch):
    from core.connectors.sse import SSEConnector
    import core.connectors.sse as sse_module

    class Response:
        def raise_for_status(self):
            return None
        def close(self):
            pass

    class Event:
        data = '{"text":"tick"}'

    class EndlessClient:
        def __init__(self, response):
            pass
        def events(self):
            while True:
                yield Event()

    monkeypatch.setattr(sse_module.requests, "post", lambda *args, **kwargs: Response())
    monkeypatch.setattr(sse_module, "SSEClient", EndlessClient)
    with pytest.raises(TransportError, match="SSE stream exceeded safety limit"):
        SSEConnector("https://example.test/stream", max_events=2, timeout=30).send("hello")

def test_private_key_block_is_analyzer_finding_and_is_redacted():
    private_key = "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----"
    result = SmartAnalyzer(offline=True, analysis_mode="strict").analyze("probe", private_key)
    assert result["success"] is True
    assert result["leak_category"] == "API Key / Token"
    assert "secret-material" not in redact_text(private_key)
