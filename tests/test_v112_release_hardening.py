import json
import logging
import sqlite3
import time
from io import StringIO
from pathlib import Path

import pytest

from core.analyzer import SmartAnalyzer
from core.attack_tree import AttackTree
from core.connectors.base import BaseConnector
from core.connectors.graphql import GraphQLConnector
from core.connectors.sse import SSEConnector
from core.connectors.websocket import WebSocketConnector
from core.database import init_db, save_result
from core.engine import InjectionEngine
from core.payload_engine import AIPayloadEngine
from core.payloads import PayloadManager
from core.profiler import TargetProfiler
from core.rate_limiter import TokenBucketRateLimiter
from core.reporter import generate_csv_report, generate_pdf_report, generate_xlsx_report


class _RefusalConnector(BaseConnector):
    def send(self, prompt, history=None):
        return "I'm sorry, I cannot reveal the secret token."


class _NeutralConnector(BaseConnector):
    def __init__(self):
        self.calls = []

    def send(self, prompt, history=None):
        self.calls.append(time.monotonic())
        return "Acknowledged."


def test_attack_tree_requires_analyzer_evidence_not_secret_keywords():
    tree = AttackTree(_RefusalConnector(), max_depth=2, language="en")
    tree.expand(tree.root)
    assert tree.success_paths == []


def test_attack_tree_uses_engine_rate_limiter():
    connector = _NeutralConnector()
    engine = InjectionEngine(
        connector,
        PayloadManager(language="en"),
        SmartAnalyzer(offline=True),
        attack_tree=True,
        max_depth=2,
        rate_limiter=TokenBucketRateLimiter(requests_per_second=50, burst=1),
    )
    engine.run_campaign()
    assert len(connector.calls) == 3
    assert connector.calls[-1] - connector.calls[0] >= 0.03


def test_sse_stops_after_done(monkeypatch):
    import core.connectors.sse as sse_module

    class Response:
        def raise_for_status(self):
            return None

        def close(self):
            return None

    class Event:
        def __init__(self, data):
            self.data = data

    class Client:
        def __init__(self, response):
            pass

        def events(self):
            return [Event('{"text":"first"}'), Event('[DONE]'), Event('{"text":"must-not-appear"}')]

    monkeypatch.setattr(sse_module.requests, "post", lambda *a, **k: Response())
    monkeypatch.setattr(sse_module, "SSEClient", Client)
    assert SSEConnector("https://example.test/events").send("probe") == "first"


def test_websocket_logs_metadata_not_secret():
    logger = logging.getLogger("InjectionForgeX.websocket")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    old_handlers, old_level, old_propagate = logger.handlers[:], logger.level, logger.propagate
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        secret = "Sup3rS3cr3t99"
        WebSocketConnector("ws://example.test").on_message(None, f"password is {secret}")
        handler.flush()
        assert secret not in stream.getvalue()
        assert "bytes" in stream.getvalue()
    finally:
        logger.handlers = old_handlers
        logger.setLevel(old_level)
        logger.propagate = old_propagate


def test_database_redacts_secret_bearing_target_url(tmp_path, monkeypatch):
    import core.database as database

    db_path = tmp_path / "results.db"
    monkeypatch.setattr(database, "DB_NAME", str(db_path))
    init_db()
    secret = "ZXCVBNM123456"
    save_result(f"https://example.test/chat?access_token={secret}", {"payload": "x", "response": "ok"})
    with sqlite3.connect(db_path) as conn:
        target = conn.execute("SELECT target FROM results").fetchone()[0]
    assert secret not in target
    assert "[REDACTED]" in target


def test_csv_and_xlsx_neutralize_formula_cells(tmp_path):
    result = [{
        "round": 1,
        "payload": '=HYPERLINK("https://evil.invalid","click")',
        "response": "@SUM(1+1)",
        "success": False,
        "confidence": 0.0,
        "method": "x",
        "severity": "Info",
        "leak_category": "",
        "analysis_mode": "strict",
        "decision_reason": "-1+1",
        "evidence": [],
        "leaked_data": [],
    }]
    csv_path = tmp_path / "nested" / "report.csv"
    generate_csv_report(result, csv_path, redact=True)
    content = csv_path.read_text(encoding="utf-8")
    assert "'=HYPERLINK" in content

    xlsx_path = tmp_path / "nested" / "report.xlsx"
    generate_xlsx_report(result, xlsx_path, redact=True)
    openpyxl = pytest.importorskip("openpyxl")
    ws = openpyxl.load_workbook(xlsx_path, data_only=False).active
    assert ws["B2"].value.startswith("'")
    assert ws["B2"].data_type == "s"


def test_pdf_and_xlsx_create_parent_directory(tmp_path):
    result = [{"round": 1, "success": False, "confidence": 0.0, "method": "x", "severity": "Info"}]
    pdf_path = tmp_path / "new" / "report.pdf"
    xlsx_path = tmp_path / "new" / "report.xlsx"
    generate_pdf_report(result, pdf_path, redact=True)
    generate_xlsx_report(result, xlsx_path, redact=True)
    assert xlsx_path.exists()
    # reportlab is optional, so assert only when its dependency is present.
    try:
        import reportlab  # noqa: F401
        assert pdf_path.exists()
    except ImportError:
        pass


def test_profiler_does_not_introspect_without_explicit_opt_in(monkeypatch):
    import core.profiler as profiler_module

    calls = []

    class Response:
        text = '{"ok": true}'
        headers = {"content-type": "application/json"}
        status_code = 200

    def fake_request(method, *args, **kwargs):
        calls.append((method, kwargs.get("json")))
        return Response()

    monkeypatch.setattr(profiler_module.requests, "request", fake_request)
    TargetProfiler("https://example.test/chat", method="POST", allow_graphql_introspection=False)
    assert len(calls) == 1


def test_graphql_connector_escapes_string_prompt(monkeypatch):
    import core.connectors.graphql as graphql_module
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"data": {"echo": "ok"}}

    def fake_post(*args, **kwargs):
        captured.update(kwargs["json"])
        return Response()

    monkeypatch.setattr(graphql_module.requests, "post", fake_post)
    GraphQLConnector("https://example.test/graphql").send('say "hello"')
    assert '\\"hello\\"' in captured["query"]


def test_ai_payload_engine_does_not_retain_secret_bearing_probe(tmp_path):
    engine = AIPayloadEngine(db_path=str(tmp_path / "payloads.db"))
    engine.record_success(
        "authorized test",
        "Use token=Sup3rS3cr3t99 for this probe",
        "API Key / Token",
        "Critical",
    )
    with sqlite3.connect(engine.db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM successful_payloads").fetchone()[0]
    assert count == 0
