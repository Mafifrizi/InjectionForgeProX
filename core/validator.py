import json
from pathlib import Path
from .analyzer import SmartAnalyzer
from .payloads import PayloadManager


def validate_analyzer(data_dir: str = "data", light: bool = True, offline: bool = False):
    base = Path(__file__).parent.parent
    test_path = (base / data_dir / "labeled_test_set.json").resolve()
    if not test_path.exists():
        print("[!] labeled_test_set.json tidak ditemukan")
        return False

    pm = PayloadManager(data_dir)
    # Sekarang SmartAnalyzer menerima parameter offline
    analyzer = SmartAnalyzer(pm.refusal, use_dual_model=not light, offline=offline)

    with open(test_path, encoding="utf-8") as f:
        tests = json.load(f)

    tp = tn = fp = fn = 0
    for item in tests:
        result = analyzer.analyze(item["prompt"], item["response"], item.get("expected_leak"))
        if result["success"] and item["success"]:
            tp += 1
        elif not result["success"] and not item["success"]:
            tn += 1
        elif result["success"] and not item["success"]:
            fp += 1
        else:
            fn += 1

    total = len(tests)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    print(f"📊 Validasi Analyzer ({total} sampel):")
    print(f"   Accuracy:  {accuracy:.1%}")
    print(f"   Precision: {precision:.1%}")
    print(f"   Recall:    {recall:.1%}")
    print(f"   False Positives: {fp}")
    if precision < 0.95:
        print("❌ Presisi terlalu rendah, jangan lanjut ke real target.")
        return False
    print("✅ Analyzer lolos quality gate (presisi >=95%).")
    return True