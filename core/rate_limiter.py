import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_second: float = 0.0
    burst: int = 1


class TokenBucketRateLimiter:
    """Thread-safe token-bucket limiter shared across workers.

    requests_per_second <= 0 disables waiting. This keeps local/lab usage fast
    while giving production users a central throttle for real targets.
    """

    def __init__(self, requests_per_second: float = 0.0, burst: int = 1):
        self.requests_per_second = max(0.0, float(requests_per_second or 0.0))
        self.capacity = max(1, int(burst or 1))
        self.tokens = float(self.capacity)
        self.updated_at = time.monotonic()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.requests_per_second > 0

    def wait(self) -> None:
        if not self.enabled:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated_at
                self.updated_at = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.requests_per_second)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                needed = 1.0 - self.tokens
                sleep_for = needed / self.requests_per_second
            time.sleep(min(max(sleep_for, 0.0), 5.0))


def build_rate_limiter(requests_per_second: Optional[float], burst: Optional[int]) -> TokenBucketRateLimiter:
    return TokenBucketRateLimiter(requests_per_second=requests_per_second or 0.0, burst=burst or 1)
