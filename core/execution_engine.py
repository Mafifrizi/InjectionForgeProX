"""Legacy execution helper retained for integrations outside the CLI path.

The main CLI uses ``TokenBucketRateLimiter``. This helper protects its local
pacing state with a lock so direct integrations cannot exceed the configured
rate delay under concurrent worker use.
"""

import threading
import time
from typing import Callable, Dict, List

import requests


class ExecutionEngine:
    """Parallel execution helper with thread-safe pacing and bounded retry."""

    def __init__(self, max_threads: int = 3, rate_limit_delay: float = 1.0):
        self.max_threads = max(1, int(max_threads or 1))
        self.rate_limit_delay = max(0.0, float(rate_limit_delay or 0.0))
        self.session = requests.Session()
        self.last_request_time = 0.0
        self._rate_lock = threading.Lock()

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
        attempts = max(1, int(max_retries or 1))
        for attempt in range(attempts):
            self._rate_limit_wait()
            try:
                return send_func(payload)
            except requests.exceptions.HTTPError as error:
                if error.response is not None and error.response.status_code == 429:
                    time.sleep((2 ** attempt) + 1)
                    continue
                raise
            except Exception:
                if attempt == attempts - 1:
                    raise
                time.sleep(2 ** attempt)
        return "ERROR: Max retries exceeded"

    def run_parallel(self, send_func: Callable, payloads: List[str]) -> List[Dict]:
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
