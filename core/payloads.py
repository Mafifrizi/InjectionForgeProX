import json
import random
import threading
from pathlib import Path
from typing import Dict, List

from .paths import bundled_data_dir
from .language import language_family, normalize_language, unique_preserve_order
from .payload_generator import generate_aggressive_payload, generate_graphql_payload


class PayloadManager:
    def __init__(self, data_dir: str = "data", language: str = "en"):
        self.data_dir = bundled_data_dir(data_dir)
        self.language = normalize_language(language)
        self.payloads = self._load_all()
        self.refusal = self._load_refusals()
        self.success_weights = {cat: 1.0 for cat in self.payloads}
        self._weights_lock = threading.Lock()

    def _load_json_payloads(self, filename: str) -> List[str]:
        path = self.data_dir / filename
        if not path.exists():
            return []
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("payloads", []) or []

    def _payload_filenames(self, name: str) -> List[str]:
        langs = language_family(self.language)
        filenames = []
        if "en" in langs:
            filenames.append(f"payloads_{name}.json")
        if "id" in langs:
            filenames.append(f"payloads_{name}_id.json")
        return filenames

    def _load_all(self) -> Dict[str, List[str]]:
        cats = {}
        for name in ["basic", "advanced", "indirect", "agent", "graphql"]:
            payloads = []
            for filename in self._payload_filenames(name):
                payloads.extend(self._load_json_payloads(filename))

            # Safe fallback: if a requested language file is missing, keep the
            # old English payloads so existing campaigns do not break.
            if not payloads:
                payloads.extend(self._load_json_payloads(f"payloads_{name}.json"))
            cats[name] = unique_preserve_order(payloads)

        if not any(cats.values()):
            cats = {"basic": [], "advanced": [], "indirect": [], "agent": [], "graphql": []}
        return cats

    def _load_txt(self, filename: str) -> List[str]:
        path = self.data_dir / filename
        if not path.exists():
            return []
        return [line.strip() for line in path.open(encoding="utf-8") if line.strip()]

    def _load_refusals(self) -> List[str]:
        refusals = []
        langs = language_family(self.language)
        if "en" in langs:
            refusals.extend(self._load_txt("refusal_phrases.txt"))
        if "id" in langs:
            refusals.extend(self._load_txt("refusal_phrases_id.txt"))
        if not refusals:
            refusals = ["I cannot", "I'm unable", "against my guidelines"]
        return unique_preserve_order(refusals)

    def update_weights(self, category: str, success: bool):
        with self._weights_lock:
            if category in self.success_weights:
                self.success_weights[category] *= 1.2 if success else 0.8
                self.success_weights[category] = max(0.1, min(5.0, self.success_weights[category]))

    def get_payload(self, category: str = "basic", mutate: bool = False,
                    aggressive: bool = False, adaptive: bool = False,
                    audit: bool = False) -> str:
        if adaptive:
            cats = list(self.payloads.keys())
            with self._weights_lock:
                weights = [self.success_weights.get(c, 1.0) for c in cats]
            category = random.choices(cats, weights=weights, k=1)[0]

        # Mode audit: selalu gunakan generator dengan payload bisnis/agresif, tanpa mutasi
        if audit:
            payload = generate_aggressive_payload()
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
