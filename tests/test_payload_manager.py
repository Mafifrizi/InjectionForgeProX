import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.payloads import PayloadManager

def test_load_all_categories():
    pm = PayloadManager()
    assert "basic" in pm.payloads
    assert "advanced" in pm.payloads
    assert len(pm.payloads["advanced"]) > 0

def test_get_payload_basic():
    pm = PayloadManager()
    p = pm.get_payload("advanced")
    assert isinstance(p, str) and len(p) > 0

def test_get_payload_aggressive():
    pm = PayloadManager()
    p = pm.get_payload("basic", aggressive=True)
    assert isinstance(p, str) and len(p) > 0

def test_get_payload_graphql():
    pm = PayloadManager()
    p = pm.get_payload("graphql", aggressive=True)
    assert isinstance(p, str) and len(p) > 0

def test_update_weights():
    pm = PayloadManager()
    old = pm.success_weights["basic"]
    pm.update_weights("basic", True)
    assert pm.success_weights["basic"] > old