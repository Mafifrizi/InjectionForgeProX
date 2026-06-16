import time
import random
import logging
import requests
from .payloads import PayloadManager
from .analyzer import SmartAnalyzer
from .connectors.base import BaseConnector
from .attack_tree import AttackTree, AttackNode

logger = logging.getLogger("InjectionForgeX")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


class InjectionEngine:
    def __init__(self, connector: BaseConnector, payload_mgr: PayloadManager,
                 analyzer: SmartAnalyzer, stealth: bool = False,
                 delay: float = 1.0, diff_mode: bool = False,
                 attack_tree: bool = False, max_depth: int = 2):
        self.connector = connector
        self.payload_mgr = payload_mgr
        self.analyzer = analyzer
        self.stealth = stealth
        self.delay = delay
        self.diff_mode = diff_mode
        self.attack_tree_mode = attack_tree
        self.max_depth = max_depth
        self.results = []

    def run_campaign(self, rounds=5, category="basic", mutate=False,
                     aggressive=False, adaptive=False, history=None,
                     multi_stage=False, audit=False):
        # Jika mode attack tree, jalankan pohon serangan
        if self.attack_tree_mode:
            return self._run_attack_tree()

        baseline_response = None
        if self.diff_mode:
            try:
                baseline_response = self._safe_send("Hello", history)
            except Exception:
                pass

        for i in range(rounds):
            if multi_stage:
                primer = self.payload_mgr.get_payload("advanced", mutate=True, aggressive=aggressive, audit=audit)
                resp1 = self._safe_send(primer, history)
                updated_history = list(history or [])
                updated_history.append({"role": "user", "content": primer})
                updated_history.append({"role": "assistant", "content": resp1})
                payload = self.payload_mgr.get_payload(category, mutate=mutate,
                                                    aggressive=aggressive, adaptive=adaptive, audit=audit)
                response = self._safe_send(payload, updated_history)
            else:
                payload = self.payload_mgr.get_payload(category, mutate=mutate,
                                                    aggressive=aggressive, adaptive=adaptive, audit=audit)
                response = self._safe_send(payload, history)

            analysis = self.analyzer.analyze(payload, response,
                                            baseline_response=baseline_response)
            self.payload_mgr.update_weights(category, analysis["success"])
            self.results.append({
                "round": i+1,
                "payload": payload,
                "response": response,
                "success": analysis["success"],
                "confidence": analysis["confidence"],
                "method": analysis["method"],
                "leaked_data": analysis.get("leaked_data", []),
                "diff": analysis.get("diff", ""),
                "severity": analysis.get("severity", "Info")
            })
            logger.info(f"Round {i+1}: success={analysis['success']} conf={analysis['confidence']:.2f}")
            if self.stealth:
                time.sleep(self.delay * random.uniform(0.7, 1.3))
            else:
                time.sleep(0.8)
        return self.results

    def _run_attack_tree(self):
        """Jalankan attack tree dan kumpulkan hasil."""
        tree = AttackTree(self.connector, max_depth=self.max_depth)
        tree.expand(tree.root)
        
        for i, path in enumerate(tree.success_paths):
            # Ambil payload pertama dan terakhir sebagai representasi
            entry = {
                "round": i+1,
                "payload": " -> ".join(path),
                "response": "Attack tree path berhasil",
                "success": True,
                "confidence": 0.98,
                "method": "attack_tree",
                "leaked_data": [],
                "diff": "",
                "severity": "High"
            }
            self.results.append(entry)
            logger.info(f"Attack tree path {i+1}: {entry['payload']}")
        
        if not tree.success_paths:
            # Catat bahwa tidak ada jalur yang berhasil
            self.results.append({
                "round": 1,
                "payload": "Attack tree (no success)",
                "response": "Tidak ada jalur yang berhasil",
                "success": False,
                "confidence": 0.0,
                "method": "attack_tree",
                "leaked_data": [],
                "diff": "",
                "severity": "Info"
            })
        return self.results

    def _safe_send(self, prompt, history, retries=3):
        last_exc = None
        for attempt in range(retries):
            try:
                return self.connector.send(prompt, history)
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(f"Rate limited, menunggu {wait:.1f}s...")
                    time.sleep(wait)
                    continue
                last_exc = e
                break
            except Exception as e:
                last_exc = e
                if attempt == retries - 1:
                    logger.error(f"Gagal setelah {retries}x: {e}")
                    return f"ERROR: {e}"
                time.sleep(2 ** attempt)
        return f"ERROR: {last_exc}"