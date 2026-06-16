import subprocess
import sys
import json
from pathlib import Path

def test_mock_campaign():
    """Jalankan tool ke mock target dan pastikan ada hasil."""
    cmd = [
        sys.executable, "forge_x.py",
        "--target", "mock",
        "--rounds", "5",
        "--aggressive",
        "--format", "json",
        "--offline",
        "--output", "tests/mock_result.json"
    ]
    # Tangkap output agar tidak crash karena encoding
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    # Pastikan file output terbuat
    out = Path("tests/mock_result.json")
    assert out.exists(), "File output tidak ditemukan"
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 5
    # Bersihkan
    out.unlink()