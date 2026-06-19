import json
from collections import defaultdict
from pathlib import Path
from .analyzer import SmartAnalyzer, normalize_analysis_mode
from .payloads import PayloadManager


def _item_expected(item):
    if "success" in item:
        return bool(item["success"])
    return bool(item.get("label", 0))


def validate_analyzer(data_dir: str = "data", light: bool = True, offline: bool = False,
                      language: str = "auto", analysis_mode: str = "balanced"):
    analysis_mode = normalize_analysis_mode(analysis_mode)
    base = Path(__file__).parent.parent
    test_path = (base / data_dir / "labeled_test_set.json").resolve()
    if not test_path.exists():
        print("[ERROR] labeled_test_set.json not found")
        return False

    pm = PayloadManager(data_dir, language=language)
    analyzer = SmartAnalyzer(
        pm.refusal,
        use_dual_model=not light,
        offline=offline,
        language=language,
        analysis_mode=analysis_mode,
    )

    with open(test_path, encoding="utf-8") as f:
        tests = json.load(f)

    tp = tn = fp = fn = 0
    by_type = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0})
    failures = []

    for item in tests:
        result = analyzer.analyze(item["prompt"], item["response"], item.get("expected_leak"))
        expected = _item_expected(item)
        actual = bool(result["success"])
        case_type = item.get("case_type") or item.get("taxonomy") or item.get("type") or "uncategorized"
        by_type[case_type]["total"] += 1
        if actual and expected:
            tp += 1; by_type[case_type]["tp"] += 1
        elif not actual and not expected:
            tn += 1; by_type[case_type]["tn"] += 1
        elif actual and not expected:
            fp += 1; by_type[case_type]["fp"] += 1
            failures.append(("FP", item, result))
        else:
            fn += 1; by_type[case_type]["fn"] += 1
            failures.append(("FN", item, result))

    total = len(tests)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    print(f"Analyzer validation ({total} samples, mode={analysis_mode}, language={language})")
    print(f"   Accuracy:        {accuracy:.1%}")
    print(f"   Precision:       {precision:.1%}")
    print(f"   Recall:          {recall:.1%}")
    print(f"   False Positives: {fp}")
    print(f"   False Negatives: {fn}")

    print("   Case-type breakdown:")
    for case_type in sorted(by_type):
        row = by_type[case_type]
        print(f"     - {case_type}: total={row['total']}, fp={row['fp']}, fn={row['fn']}")

    if failures:
        print("   First failures:")
        for kind, item, result in failures[:5]:
            ident = item.get("id", "unknown")
            print(f"     - {kind} {ident}: method={result.get('method')} reason={result.get('decision_reason')}")

    precision_floor = 0.95
    recall_floor = 0.90
    if analysis_mode == "sensitive":
        precision_floor = 0.85
        recall_floor = 0.95
    elif analysis_mode == "strict":
        precision_floor = 0.98
        recall_floor = 0.85

    if precision < precision_floor:
        print(f"[FAIL] Precision below required floor ({precision_floor:.0%}). Do not use on real targets yet.")
        return False
    if recall < recall_floor:
        print(f"[FAIL] Recall below required floor ({recall_floor:.0%}). Analyzer may miss valid findings.")
        return False
    print("[PASS] Analyzer quality gate passed.")
    return True
