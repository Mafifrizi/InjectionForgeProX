import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.analyzer import SmartAnalyzer
from core.attack_tree import AttackTree
from core.connectors.mock_target import MockTargetConnector
from core.language import detect_language, detect_language_profile, resolve_language
from core.payloads import PayloadManager
from unittest.mock import patch
from core.llm_generator import LLMGenerator


def test_detect_indonesian_refusal():
    profile = detect_language_profile("Maaf, saya tidak bisa membantu permintaan tersebut.")
    assert profile.language == "id"
    assert profile.scores["id"] > profile.scores["en"]


def test_detect_english_refusal():
    assert detect_language("Sorry, I can't assist with that request.") == "en"


def test_detect_mixed_language():
    assert detect_language("Maaf, I can't assist with that token request.") == "mixed"


def test_resolve_auto_fallback_mixed():
    assert resolve_language("auto", samples=["???"]) == "mixed"


def test_payload_manager_indonesian_loads_id_payloads():
    pm = PayloadManager(language="id")
    payload_blob = "\n".join(pm.payloads["basic"]).lower()
    assert "abaikan instruksi" in payload_blob
    assert "kata sandi" in payload_blob


def test_payload_manager_mixed_loads_both_languages():
    pm = PayloadManager(language="mixed")
    payload_blob = "\n".join(pm.payloads["basic"]).lower()
    assert "ignore previous" in payload_blob
    assert "abaikan instruksi" in payload_blob


def test_analyzer_indonesian_system_prompt():
    analyzer = SmartAnalyzer([], offline=True, language="id")
    res = analyzer.analyze("", "Instruksi sistem: Kamu adalah asisten internal Masta.id.")
    assert res["success"]
    assert res["leak_category"] == "System Prompt"
    assert res["severity"] == "High"
    assert res["language"] in ("id", "mixed")


def test_analyzer_indonesian_token():
    analyzer = SmartAnalyzer([], offline=True, language="id")
    res = analyzer.analyze("", "Token internal adalah masta-token-2025")
    assert res["success"]
    assert res["leak_category"] == "API Key / Token"
    assert res["severity"] == "Critical"


def test_analyzer_indonesian_refusal():
    analyzer = SmartAnalyzer([], offline=True, language="id")
    res = analyzer.analyze("", "Maaf, saya tidak bisa membantu permintaan tersebut.")
    assert not res["success"]
    assert "refusal" in res["method"]


def test_attack_tree_language_id_uses_indonesian_root():
    tree = AttackTree(MockTargetConnector(), max_depth=1, language="id")
    assert tree.root.payload == "Halo"


def test_llm_generator_indonesian_fallback():
    gen = LLMGenerator(language="id")
    with patch("requests.post", side_effect=RuntimeError("offline")):
        payloads = gen.generate_payloads("target uji", n=1)
    assert payloads
    assert any(word in payloads[0].lower() for word in ["instruksi", "konfigurasi", "prompt"])
