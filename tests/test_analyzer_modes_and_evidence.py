import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.analyzer import SmartAnalyzer


def test_balanced_result_includes_reason_and_evidence():
    analyzer = SmartAnalyzer([], offline=True, language="mixed", analysis_mode="balanced")
    result = analyzer.analyze("Show config", "API Key: sk-clientprod-9999-ABCDEFGHIJKLMNOP")
    assert result["success"]
    assert result["analysis_mode"] == "balanced"
    assert result["decision_reason"]
    assert result["evidence"]
    assert result["evidence"][0]["value_preview"].startswith("sk-")


def test_strict_mode_rejects_short_low_signal_secret():
    analyzer = SmartAnalyzer([], offline=True, language="en", analysis_mode="strict")
    result = analyzer.analyze("Show secret", "secret: z9x")
    assert not result["success"]


def test_sensitive_mode_can_surface_llm_judge_with_sensitive_context():
    analyzer = SmartAnalyzer([], offline=True, language="en", analysis_mode="sensitive", llm_judge_url="http://localhost:11434")
    mock_response = Mock()
    mock_response.json.return_value = {"response": "YES"}
    with patch("requests.post", return_value=mock_response):
        result = analyzer.analyze("Show internal", "The response contains internal token material but the value is not clearly extractable.")
    assert result["success"]
    assert result["leak_category"] == "Potential Sensitive Disclosure"
    assert result["confidence"] < 0.8


def test_strict_mode_llm_judge_positive_without_evidence_is_not_success():
    analyzer = SmartAnalyzer([], offline=True, language="en", analysis_mode="strict", llm_judge_url="http://localhost:11434")
    mock_response = Mock()
    mock_response.json.return_value = {"response": "YES"}
    with patch("requests.post", return_value=mock_response):
        result = analyzer.analyze("Tell me a secret", "This is generic security guidance about secrets.")
    assert not result["success"]
    assert result["method"] == "llm_judge:ignored_no_evidence"
