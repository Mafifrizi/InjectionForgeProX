import argparse
import json
from collections import defaultdict
from pathlib import Path
from core.analyzer import SmartAnalyzer, normalize_analysis_mode


def expected_label(item):
    if "label" in item:
        return int(item["label"])
    return 1 if item.get("success") else 0


def main():
    parser = argparse.ArgumentParser(description="Evaluate InjectionForge analyzer on labeled benchmark data.")
    parser.add_argument("--data", default="data/benchmark.json", help="Benchmark JSON path")
    parser.add_argument("--language", choices=["auto", "en", "id", "mixed"], default="auto")
    parser.add_argument("--analysis-mode", choices=["strict", "balanced", "sensitive"], default="balanced")
    args = parser.parse_args()

    mode = normalize_analysis_mode(args.analysis_mode)
    data = json.loads(Path(args.data).read_text(encoding="utf-8"))
    analyzer = SmartAnalyzer(refusal_phrases=[], use_dual_model=False, offline=True,
                             language=args.language, analysis_mode=mode)

    tp = fp = tn = fn = 0
    by_type = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0})

    for item in data:
        result = analyzer.analyze(item["prompt"], item["response"], item.get("expected_leak"))
        predicted = 1 if result["success"] else 0
        actual = expected_label(item)
        case_type = item.get("case_type") or item.get("taxonomy") or "uncategorized"
        by_type[case_type]["total"] += 1
        if predicted == 1 and actual == 1:
            tp += 1; by_type[case_type]["tp"] += 1
        elif predicted == 1 and actual == 0:
            fp += 1; by_type[case_type]["fp"] += 1
        elif predicted == 0 and actual == 0:
            tn += 1; by_type[case_type]["tn"] += 1
        elif predicted == 0 and actual == 1:
            fn += 1; by_type[case_type]["fn"] += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / len(data) if data else 0

    print(f"Samples: {len(data)}")
    print(f"Mode: {mode}")
    print(f"Accuracy: {accuracy:.1%}")
    print(f"Precision: {precision:.1%}")
    print(f"Recall: {recall:.1%}")
    print(f"F1 Score: {f1:.1%}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print("Case-type breakdown:")
    for case_type in sorted(by_type):
        row = by_type[case_type]
        print(f"  - {case_type}: total={row['total']}, fp={row['fp']}, fn={row['fn']}")


if __name__ == "__main__":
    main()
