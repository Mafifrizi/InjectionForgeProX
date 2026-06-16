import json
import random
from pathlib import Path
from typing import List, Dict
from .payload_generator import generate_aggressive_payload, generate_graphql_payload

class PayloadManager:
    def __init__(self, data_dir: str = "data"):
        base = Path(__file__).parent.parent
        self.data_dir = (base / data_dir).resolve()
        self.payloads = self._load_all()
        self.refusal = self._load_txt("refusal_phrases.txt")
        self.success_weights = {cat: 1.0 for cat in self.payloads}

    def _load_all(self) -> Dict[str, List[str]]:
        cats = {}
        for name in ["basic", "advanced", "indirect", "agent", "graphql"]:
            path = self.data_dir / f"payloads_{name}.json"
            if path.exists():
                with open(path, encoding="utf-8") as f:
                    cats[name] = json.load(f).get("payloads", [])
        if not any(cats.values()):
            cats = {"basic": [], "advanced": [], "indirect": [], "agent": [], "graphql": []}
        return cats

    def _load_txt(self, filename):
        path = self.data_dir / filename
        if not path.exists():
            return ["I cannot", "I'm unable", "against my guidelines"]
        return [line.strip() for line in path.open(encoding="utf-8") if line.strip()]

    def update_weights(self, category: str, success: bool):
        if category in self.success_weights:
            self.success_weights[category] *= 1.2 if success else 0.8
            self.success_weights[category] = max(0.1, min(5.0, self.success_weights[category]))

    def get_payload(self, category: str = "basic", mutate: bool = False,
                    aggressive: bool = False, adaptive: bool = False,
                    audit: bool = False) -> str:
        if adaptive:
            cats = list(self.payloads.keys())
            weights = [self.success_weights.get(c, 1.0) for c in cats]
            category = random.choices(cats, weights=weights, k=1)[0]

        # Mode audit: selalu gunakan generator dengan payload bisnis/agresif, tanpa mutasi
        if audit:
            payload = generate_aggressive_payload()
            # Tidak ada mutasi
            return payload

        pool = self.payloads.get(category, [])

        if aggressive or not pool:
            if category == "graphql":
                payload = generate_graphql_payload()
            else:
                payload = generate_aggressive_payload()
        else:
            payload = random.choice(pool)

        if mutate:
            from core.obfuscator import Obfuscator
            if aggressive:
                payload = Obfuscator.aggressive_mutate(payload)
            else:
                payload = Obfuscator.random_obfuscate(payload)
        return payload