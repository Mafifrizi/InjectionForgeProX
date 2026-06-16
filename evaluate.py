import json
from pathlib import Path
from core.analyzer import SmartAnalyzer

# Load dataset
data = json.loads(Path("data/benchmark.json").read_text())

# Inisialisasi analyzer (offline, ringan)
analyzer = SmartAnalyzer(refusal_phrases=[], use_dual_model=False, offline=True)

tp = fp = tn = fn = 0
for item in data:
    result = analyzer.analyze(item["prompt"], item["response"])
    predicted = 1 if result["success"] else 0
    actual = item["label"]
    if predicted == 1 and actual == 1:
        tp += 1
    elif predicted == 1 and actual == 0:
        fp += 1
    elif predicted == 0 and actual == 0:
        tn += 1
    elif predicted == 0 and actual == 1:
        fn += 1

precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

print(f"Precision: {precision:.1%}")
print(f"Recall: {recall:.1%}")
print(f"F1 Score: {f1:.1%}")