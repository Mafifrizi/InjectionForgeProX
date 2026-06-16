import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.reporter import generate_json_report, generate_html_report

def test_json_report():
    results = [{"round":1, "payload":"test", "response":"ok", "success":True, "confidence":0.99, "method":"regex", "leaked_data":[], "severity":"Low"}]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
        generate_json_report(results, f.name)
        assert "test" in Path(f.name).read_text()
        Path(f.name).unlink()

def test_html_escape():
    results = [{"round":1, "payload":"<script>alert(1)</script>", "response":"<b>Bold</b>", "success":True, "confidence":0.99, "method":"regex", "severity":"Medium"}]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
        generate_html_report(results, f.name)
        content = Path(f.name).read_text()
        assert "<script>" not in content
        Path(f.name).unlink()