import concurrent.futures
import logging
import time
from typing import Optional

from .attack_tree import AttackTree
from .analyzer import SmartAnalyzer
from .connectors.base import BaseConnector
from .database import save_result
from .payloads import PayloadManager
from .rate_limiter import TokenBucketRateLimiter
from .redaction import redact_text
from .transport import TransportCircuitBreaker, TransportResult, send_with_retry

logger = logging.getLogger("InjectionForgeX")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class InjectionEngine:
    """Campaign engine with one shared transport/retry boundary.

    Transport failures are stored as typed result metadata and are never passed
    to the semantic analyzer or payload-weight learning logic.
    """

    def __init__(
        self,
        connector: BaseConnector,
        payload_mgr: PayloadManager,
        analyzer: SmartAnalyzer,
        stealth: bool = False,
        delay: float = 1.0,
        diff_mode: bool = False,
        attack_tree: bool = False,
        max_depth: int = 2,
        workers: int = 4,
        language: str = "en",
        rate_limiter: Optional[TokenBucketRateLimiter] = None,
        max_send_attempts: int = 3,
        max_consecutive_rate_limits: int = 3,
    ):
        self.connector = connector
        self.payload_mgr = payload_mgr
        self.analyzer = analyzer
        self.stealth = stealth
        self.delay = delay
        self.diff_mode = diff_mode
        self.attack_tree_mode = attack_tree
        self.max_depth = max_depth
        self.workers = max(1, int(workers or 1))
        self.language = language
        self.results = []
        self.rate_limiter = rate_limiter
        self.max_send_attempts = max(1, int(max_send_attempts or 1))
        self.transport_breaker = TransportCircuitBreaker(max_consecutive_rate_limits)

    def _safe_send(self, prompt: str, history=None, retries: Optional[int] = None) -> TransportResult:
        """Send one target request through the single retry contract."""
        attempts = self.max_send_attempts if retries is None else max(1, int(retries or 1))
        return send_with_retry(
            lambda: self.connector.send(prompt, history),
            max_attempts=attempts,
            rate_limiter=self.rate_limiter,
            logger=logger,
            circuit_breaker=self.transport_breaker,
        )

    def _transport_result(self, round_number: int, payload: str, outcome: TransportResult, phase: str = "target") -> dict:
        result = {
            "round": round_number,
            "payload": payload,
            "response": outcome.display_response,
            "success": False,
            "confidence": 0.0,
            "method": "transport_error",
            "leaked_data": [],
            "diff": "",
            "severity": "Info",
            "leak_category": "",
            "analysis_mode": getattr(self.analyzer, "analysis_mode", "balanced"),
            "decision_reason": (
                f"{phase.capitalize()} transport failure after {outcome.attempts} attempt(s): "
                f"{outcome.error or 'Unknown error'}"
            ),
            "evidence": [],
            "language": self.language,
            "transport_error": True,
            "transport_attempts": outcome.attempts,
            "transport_status_code": outcome.status_code,
            "transport_retryable": outcome.retryable,
        }
        return result

    def _analyzed_result(self, round_number: int, payload: str, response: str, baseline_response: Optional[str]) -> dict:
        analysis = self.analyzer.analyze(payload, response, baseline_response=baseline_response)
        return {
            "round": round_number,
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
            "language": analysis.get("language", self.language),
            "transport_error": False,
            "transport_attempts": None,
            "transport_status_code": None,
            "transport_retryable": False,
        }

    def run_campaign(
        self,
        rounds: int = 5,
        category: str = "basic",
        mutate: bool = False,
        aggressive: bool = False,
        adaptive: bool = False,
        history=None,
        multi_stage: bool = False,
        audit: bool = False,
        target_endpoint: str = "",
    ):
        self.results = []
        self.transport_breaker.reset()
        if self.attack_tree_mode:
            return self._run_attack_tree()

        baseline_response = None
        if self.diff_mode:
            baseline = self._safe_send("Hello", history)
            if baseline.ok:
                baseline_response = baseline.response
            else:
                logger.warning("Baseline skipped due to transport failure: %s", baseline.error)

        def persist(result: dict) -> dict:
            try:
                save_result(target_endpoint, result)
            except Exception as exc:
                logger.warning("Gagal menyimpan hasil ke database: %s", redact_text(str(exc)))
            return result

        def execute_round(index: int) -> dict:
            round_number = index + 1
            if multi_stage:
                primer = self.payload_mgr.get_payload("advanced", mutate=True, aggressive=aggressive, audit=audit)
                primer_outcome = self._safe_send(primer, history)
                if not primer_outcome.ok:
                    return persist(self._transport_result(round_number, primer, primer_outcome, phase="primer"))
                updated_history = list(history or [])
                updated_history.append({"role": "user", "content": primer})
                updated_history.append({"role": "assistant", "content": primer_outcome.response or ""})
                payload = self.payload_mgr.get_payload(category, mutate=mutate, aggressive=aggressive, adaptive=adaptive, audit=audit)
                outcome = self._safe_send(payload, updated_history)
            else:
                payload = self.payload_mgr.get_payload(category, mutate=mutate, aggressive=aggressive, adaptive=adaptive, audit=audit)
                outcome = self._safe_send(payload, history)

            if not outcome.ok:
                return persist(self._transport_result(round_number, payload, outcome))

            result = self._analyzed_result(round_number, payload, outcome.response or "", baseline_response)
            # A transport failure never reaches this point, so adaptive weighting
            # only consumes genuine target responses.
            self.payload_mgr.update_weights(category, result["success"])
            return persist(result)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(execute_round, index) for index in range(max(0, int(rounds or 0)))]
            for future in concurrent.futures.as_completed(futures):
                self.results.append(future.result())
                if self.stealth and self.delay > 0:
                    time.sleep(self.delay)

        self.results.sort(key=lambda item: item["round"])
        return self.results

    def _run_attack_tree(self):
        tree = AttackTree(
            self.connector,
            max_depth=self.max_depth,
            language=self.language,
            analyzer=self.analyzer,
            send_func=lambda payload: self._safe_send(payload, None),
        )
        tree.expand(tree.root)

        for index, (path, node) in enumerate(zip(tree.success_paths, tree.success_nodes), 1):
            analysis = node.analysis or {}
            self.results.append({
                "round": index,
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
                "language": self.language,
                "transport_error": False,
                "transport_attempts": None,
                "transport_status_code": None,
                "transport_retryable": False,
            })
            logger.info("Attack tree path %d: %s", index, redact_text(" -> ".join(path)))

        if not tree.success_paths:
            if tree.transport_failures:
                failure = tree.transport_failures[0]
                self.results.append(self._transport_result(1, "Attack tree", failure, phase="attack-tree"))
            else:
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
                    "language": self.language,
                    "transport_error": False,
                    "transport_attempts": None,
                    "transport_status_code": None,
                    "transport_retryable": False,
                })
        return self.results
