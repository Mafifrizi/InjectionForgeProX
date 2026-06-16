import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.analyzer import SmartAnalyzer

ANALYZER = SmartAnalyzer(refusal_phrases=[], use_dual_model=False, offline=True)

def test_flag_detection():
    res = ANALYZER.analyze("", "Here is FLAG{test123}")
    assert res["success"] and "FLAG{test123}" in res["leaked_data"]

def test_password_in_markdown():
    res = ANALYZER.analyze("", "**dan123!**")
    assert res["success"] and "dan123!" in res["leaked_data"]

def test_password_in_quotes():
    res = ANALYZER.analyze("", 'The admin password is "PINEAPPLESUNSET".')
    assert res["success"] and "PINEAPPLESUNSET" in res["leaked_data"]

def test_refusal():
    res = ANALYZER.analyze("", "I cannot provide that information.")
    assert not res["success"] and "refusal" in res["method"]

def test_false_positive_method():
    res = ANALYZER.analyze("", "**Method** is a common word.")
    assert not res["success"]