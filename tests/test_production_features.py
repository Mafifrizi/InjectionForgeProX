import json
import time
from argparse import Namespace
from pathlib import Path

from core.config import apply_profile, load_profile
from core.rate_limiter import TokenBucketRateLimiter
from core.redaction import redact_result, redact_text


def test_redaction_masks_sensitive_values():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz token=super-secret-value user=a@example.com"
    redacted = redact_text(text)
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "super-secret-value" not in redacted
    assert "a@example.com" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_result_preserves_shape():
    result = {
        "payload": "test",
        "response": "api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
        "leaked_data": ["sk-abcdefghijklmnopqrstuvwxyz123456"],
        "evidence": [{"value_preview": "token=secretvalue12345", "category": "API Key"}],
    }
    redacted = redact_result(result)
    assert redacted["payload"] == "test"
    assert "abcdefghijklmnopqrstuvwxyz" not in json.dumps(redacted)
    assert result["response"] != redacted["response"]


def test_json_profile_load_and_apply(tmp_path: Path):
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        "target": "mock",
        "rounds": 3,
        "language": "id",
        "analysis-mode": "strict",
        "headers": {"X-Test": "1"},
        "authorized": True,
    }), encoding="utf-8")
    args = Namespace(target="auto", rounds=10, language="auto", analysis_mode="balanced", headers=None, authorized=False)
    updated = apply_profile(args, load_profile(str(profile)))
    assert updated.target == "mock"
    assert updated.rounds == 3
    assert updated.language == "id"
    assert updated.analysis_mode == "strict"
    assert json.loads(updated.headers)["X-Test"] == "1"
    assert updated.authorized is True


def test_rate_limiter_waits_when_enabled():
    limiter = TokenBucketRateLimiter(requests_per_second=50, burst=1)
    start = time.monotonic()
    limiter.wait()
    limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.015


def test_rate_limiter_disabled_is_fast():
    limiter = TokenBucketRateLimiter(requests_per_second=0, burst=1)
    start = time.monotonic()
    for _ in range(20):
        limiter.wait()
    assert time.monotonic() - start < 0.1
