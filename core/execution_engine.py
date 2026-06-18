# core/execution_engine.py
import threading
import time
import requests
from typing import List, Dict, Optional, Callable
from queue import Queue

class ExecutionEngine:
    """Engine eksekusi paralel dengan rate‑limit awareness."""
    
    def __init__(self, max_threads: int = 3, rate_limit_delay: float = 1.0):
        self.max_threads = max_threads
        self.rate_limit_delay = rate_limit_delay
        self.session = requests.Session()
        self.last_request_time = 0
    
    def _rate_limit_wait(self):
        """Tunggu sesuai rate limit."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def send_with_retry(self, send_func: Callable, payload: str, max_retries: int = 3) -> str:
        """Kirim payload dengan retry dan rate‑limit awareness."""
        for attempt in range(max_retries):
            self._rate_limit_wait()
            try:
                return send_func(payload)
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = (2 ** attempt) + 1
                    print(f"[!] Rate limited, menunggu {wait}s...")
                    time.sleep(wait)
                    continue
                raise
            except Exception:
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
        return "ERROR: Max retries exceeded"
    
    def run_parallel(self, send_func: Callable, payloads: List[str]) -> List[Dict]:
        """Jalankan payload secara paralel."""
        results = []
        queue = Queue()
        
        def worker(p):
            resp = self.send_with_retry(send_func, p)
            results.append({"payload": p, "response": resp})
        
        threads = []
        for p in payloads:
            t = threading.Thread(target=worker, args=(p,))
            t.start()
            threads.append(t)
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        return results