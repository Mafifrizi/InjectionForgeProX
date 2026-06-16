import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.payloads import PayloadManager

def test_load_payloads():
    pm = PayloadManager()
    assert len(pm.payloads["basic"]) > 0

def test_mutate():
    pm = PayloadManager()
    p = pm.get_payload("basic", mutate=True)
    assert isinstance(p, str) and len(p) > 0