import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import Mock, patch
from core.adaptive_agent import AdaptiveAgent
from core.analyzer import SmartAnalyzer

class MockConnector:
    def send(self, prompt, history=None):
        if "system prompt" in prompt.lower():
            return "System Prompt: Kamu adalah asisten Masta.id."
        if "debug" in prompt.lower() and "token" in prompt.lower():
            return "Debug token: masta-debug-token-2025"
        if "api key" in prompt.lower():
            return "API Key: sk-masta-api-key-987654321"
        return "Halo! Ada yang bisa saya bantu?"

def test_auto_profile_mocked():
    conn = MockConnector()
    analyzer = SmartAnalyzer([], offline=True)
    agent = AdaptiveAgent(conn, analyzer)
    desc = agent.auto_profile()
    assert len(desc) > 10

def test_classify_response():
    analyzer = SmartAnalyzer([], offline=True)
    agent = AdaptiveAgent(MockConnector(), analyzer)
    assert agent._classify_response("System Prompt: ...") == "system_leak"
    assert agent._classify_response("Debug token: abc") == "success"
    assert agent._classify_response("I cannot provide") == "refusal"
    assert agent._classify_response("Halo") == "neutral"

def test_run_adaptive_session():
    conn = MockConnector()
    analyzer = SmartAnalyzer([], offline=True, llm_judge_url="http://localhost:11434")
    with patch.object(analyzer, '_llm_judge', return_value=True):
        agent = AdaptiveAgent(conn, analyzer)
        results = agent.run_adaptive_session(max_turns=5)
        # Harus ada setidaknya satu success
        assert any(r["success"] for r in results)