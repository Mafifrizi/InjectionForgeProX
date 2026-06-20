import time
import random
import logging
import concurrent.futures
import requests
from .payloads import PayloadManager
from .analyzer import SmartAnalyzer
from .connectors.base import BaseConnector
from .attack_tree import AttackTree, AttackNode
from .database import save_result
from .rate_limiter import TokenBucketRateLimiter
from .redaction import redact_text

logger = logging.getLogger("InjectionForgeX")
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


class InjectionEngine:
    def __init__(self, connector: BaseConnector, payload_mgr: PayloadManager,
                 analyzer: SmartAnalyzer, stealth: bool = False,
                 delay: float = 1.0, diff_mode: bool = False,
                 attack_tree: bool = False, max_depth: int = 2,
                 workers: int = 4, language: str = "en",
                 rate_limiter: TokenBucketRateLimiter | None = None):
        self.connector = connector
        self.payload_mgr = payload_mgr
        self.analyzer = analyzer
        self.stealth = stealth
        self.delay = delay
        self.diff_mode = diff_mode
        self.attack_tree_mode = attack_tree
        self.max_depth = max_depth
        self.workers = workers
        self.language = language
        self.results = []
        self.rate_limiter = rate_limiter

    def run_campaign(self, rounds=5, category="basic", mutate=False,
                     aggressive=False, adaptive=False, history=None,
                     multi_stage=False, audit=False, target_endpoint=""):
        # Jika mode attack tree, jalankan pohon serangan
        if self.attack_tree_mode:
            return self._run_attack_tree()

        baseline_response = None
        if self.diff_mode:
            try:
                baseline_response = self._safe_send("Hello", history)
            except Exception:
                pass

        def execute_round(i):
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
            result = {
                "round": i+1,
                "payload": payload,
                "response": response,
                "success": analysis["success"],
                "confidence": analysis["confidence"],
                "method": analysis["method"],
                "leaked_data": analysis.get("leaked_data", []),
                "diff": analysis.get("diff", ""),
                "severity": analysis.get("severity", "Info"),
                "leak_category": analysis.get("leak_category", ""),
                "analysis_mode": analysis.get("analysis_mode", getattr(self.analyzer, "analysis_mode", "balanced")),
                "decision_reason": analysis.get("decision_reason", ""),
                "evidence": analysis.get("evidence", []),
                "language": analysis.get("language", self.language)
            }
            # Simpan ke database
            try:
                save_result(target_endpoint, result)
            except Exception as e:
                logger.warning("Gagal menyimpan hasil ke database: %s", redact_text(str(e)))
            return result

        # Multi-threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(execute_round, i) for i in range(rounds)]
            for future in concurrent.futures.as_completed(futures):
                self.results.append(future.result())
                if self.stealth and self.delay > 0:
                    time.sleep(self.delay)

        # Urutkan hasil berdasarkan round
        self.results.sort(key=lambda x: x["round"])
        return self.results

    def _run_attack_tree(self):
        """Jalankan attack tree dan kumpulkan hasil."""
        tree = AttackTree(
            self.connector,
            max_depth=self.max_depth,
            language=self.language,
            analyzer=self.analyzer,
            send_func=lambda payload: self._safe_send(payload, None),
        )
        tree.expand(tree.root)

        for i, (path, node) in enumerate(zip(tree.success_paths, tree.success_nodes), 1):
            analysis = node.analysis or {}
            entry = {
                "round": i,
                "payload": " -> ".join(path),
                "response": node.response or "",
                "success": True,
                "confidence": analysis.get("confidence", 0.0),
                "method": "attack_tree",
                "leaked_data": analysis.get("leaked_data", []),
                "diff": analysis.get("diff", ""),
                "severity": analysis.get("severity", "Info"),
                "leak_category": analysis.get("leak_category", ""),
                "analysis_mode": analysis.get("analysis_mode", getattr(self.analyzer, "analysis_mode", "balanced")),
                "decision_reason": analysis.get("decision_reason", "Evidence-gated attack-tree finding."),
                "evidence": analysis.get("evidence", []),
                "language": analysis.get("language", self.language)
            }
            self.results.append(entry)
            logger.info("Attack tree path %d: %s", i + 1, redact_text(entry["payload"]))
        
        if not tree.success_paths:
            self.results.append({
                "round": 1,
                "payload": "Attack tree (no success)",
                "response": "Tidak ada jalur yang berhasil",
                "success": False,
                "confidence": 0.0,
                "method": "attack_tree",
                "leaked_data": [],
                "diff": "",
                "severity": "Info",
                "leak_category": "",
                "analysis_mode": getattr(self.analyzer, "analysis_mode", "balanced"),
                "decision_reason": "Attack tree did not find a successful path.",
                "evidence": [],
                "language": self.language
            })
        return self.results

    def _safe_send(self, prompt, history, retries=3):
        last_exc = None
        for attempt in range(retries):
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait()
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
                    logger.error("Gagal setelah %dx: %s", retries, redact_text(str(e)))
                    return f"ERROR: {redact_text(str(e))}"
                time.sleep(2 ** attempt)
        return f"ERROR: {redact_text(str(last_exc))}"