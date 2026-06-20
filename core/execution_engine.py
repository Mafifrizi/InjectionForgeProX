"""Legacy execution helper retained for integrations outside the CLI path."""

import threading
import time
from typing import Callable, Dict, List

from .transport import TransportCircuitBreaker, TransportError, send_with_retry


class ExecutionEngine:
    """Parallel execution helper using the same transport retry contract."""

    def __init__(self, max_threads: int = 3, rate_limit_delay: float = 1.0):
        self.max_threads = max(1, int(max_threads or 1))
        self.rate_limit_delay = max(0.0, float(rate_limit_delay or 0.0))
        self.last_request_time = 0.0
        self._rate_lock = threading.Lock()
        self.transport_breaker = TransportCircuitBreaker()

    def _rate_limit_wait(self) -> None:
        if self.rate_limit_delay <= 0:
            return
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
            self.last_request_time = time.monotonic()

    def send_with_retry(self, send_func: Callable, payload: str, max_retries: int = 3) -> str:
        outcome = send_with_retry(
            lambda: send_func(payload),
            max_attempts=max(1, int(max_retries or 1)),
            rate_limiter=self._rate_limit_wait,
            circuit_breaker=self.transport_breaker,
        )
        if outcome.ok:
            return outcome.response or ""
        raise TransportError(
            outcome.error or "Max retries exceeded",
            retryable=outcome.retryable,
            status_code=outcome.status_code,
        )

    def run_parallel(self, send_func: Callable, payloads: List[str]) -> List[Dict]:
        self.transport_breaker.reset()
        results: List[Dict] = []
        result_lock = threading.Lock()

        def worker(payload: str) -> None:
            response = self.send_with_retry(send_func, payload)
            with result_lock:
                results.append({"payload": payload, "response": response})

        threads: List[threading.Thread] = []
        for payload in payloads:
            thread = threading.Thread(target=worker, args=(payload,))
            thread.start()
            threads.append(thread)
            if len(threads) >= self.max_threads:
                for item in threads:
                    item.join()
                threads = []
        for item in threads:
            item.join()
        return results
