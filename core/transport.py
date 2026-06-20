"""Shared transport retry contract for target connectors.

Connectors return only successful target responses and raise on transport failures.
Callers use :func:`send_with_retry` so HTTP 429 and transient network failures
are retried consistently and never get analyzed as chatbot output.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import logging
import random
import time
import threading
from typing import Callable, Optional, Protocol, Union

import requests

from .redaction import redact_text


RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_RETRY_AFTER_SECONDS = 60.0


class _RateLimiter(Protocol):
    def wait(self) -> None: ...


class TransportError(RuntimeError):
    """A connector-level transport failure that has no chatbot response.

    ``retryable`` is intentionally explicit for transports that do not expose
    a ``requests`` exception (for example WebSocket timeouts).
    """

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = False,
        status_code: Optional[int] = None,
        response: object = None,
    ) -> None:
        super().__init__(message)
        self.retryable = bool(retryable)
        self.status_code = status_code
        self.response = response


class TransportCircuitBreaker:
    """Stop a campaign from repeatedly hammering a rate-limited target.

    The breaker opens only after consecutive *exhausted* HTTP 429 outcomes.
    It is shared by every send path within one campaign. A blocked outcome has
    zero attempts, so reports distinguish it from an actual network call.
    """

    def __init__(self, max_consecutive_rate_limits: int = 3) -> None:
        self.max_consecutive_rate_limits = max(1, int(max_consecutive_rate_limits or 1))
        self._consecutive_429 = 0
        self._open = False
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._open

    def reset(self) -> None:
        with self._lock:
            self._consecutive_429 = 0
            self._open = False

    def blocked_result(self) -> "TransportResult":
        return TransportResult(
            response=None,
            error=(
                "Campaign transport circuit breaker is open after "
                f"{self.max_consecutive_rate_limits} consecutive exhausted HTTP 429 responses"
            ),
            attempts=0,
            status_code=429,
            retryable=True,
        )

    def record(self, result: "TransportResult") -> None:
        with self._lock:
            if result.ok:
                self._consecutive_429 = 0
                return
            if result.status_code == 429:
                self._consecutive_429 += 1
                if self._consecutive_429 >= self.max_consecutive_rate_limits:
                    self._open = True
            else:
                self._consecutive_429 = 0


@dataclass(frozen=True)
class TransportResult:
    """Outcome of a bounded send operation.

    A failed result is deliberately distinct from a target response. Consumers
    must not pass ``display_response`` to the analyzer; it is report-only.
    """

    response: Optional[str]
    error: Optional[str]
    attempts: int
    status_code: Optional[int] = None
    retryable: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def display_response(self) -> str:
        if self.ok:
            return self.response or ""
        return f"TRANSPORT_ERROR: {self.error or 'Unknown transport failure'}"


def _status_code_from_exception(exc: BaseException) -> Optional[int]:
    if isinstance(exc, TransportError):
        if exc.status_code is not None:
            return int(exc.status_code)
        response = exc.response
    elif isinstance(exc, requests.exceptions.HTTPError):
        response = exc.response
    else:
        return None

    status = getattr(response, "status_code", None)
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _is_retryable_exception(exc: BaseException, status_code: Optional[int]) -> bool:
    if isinstance(exc, TransportError):
        return exc.retryable or status_code in RETRYABLE_HTTP_STATUS_CODES
    if isinstance(exc, requests.exceptions.HTTPError):
        return status_code in RETRYABLE_HTTP_STATUS_CODES
    if isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
        return True
    if isinstance(exc, requests.exceptions.RequestException):
        # Other request exceptions (invalid URL, SSL validation, malformed
        # request) are generally deterministic and should fail fast.
        return False
    return False


def transport_error_from_exception(exc: BaseException) -> TransportError:
    """Convert a request exception into a redaction-safe raised failure."""
    status_code = _status_code_from_exception(exc)
    response = getattr(exc, "response", None)
    return TransportError(
        _safe_error_message(exc),
        retryable=_is_retryable_exception(exc, status_code),
        status_code=status_code,
        response=response,
    )


def retry_after_seconds(
    response: object,
    *,
    now: Optional[datetime] = None,
    max_seconds: float = DEFAULT_MAX_RETRY_AFTER_SECONDS,
) -> Optional[float]:
    """Parse a bounded Retry-After value from a response, if present."""
    headers = getattr(response, "headers", None) or {}
    value = headers.get("Retry-After") or headers.get("retry-after")
    if value is None:
        return None

    raw = str(value).strip()
    try:
        seconds = float(raw)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(raw)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            current = now or datetime.now(timezone.utc)
            seconds = (retry_at - current).total_seconds()
        except (TypeError, ValueError, IndexError, OverflowError):
            return None

    if seconds < 0:
        return 0.0
    return min(float(max_seconds), seconds)


def _retry_after_for_exception(exc: BaseException) -> Optional[float]:
    response = None
    if isinstance(exc, TransportError):
        response = exc.response
    elif isinstance(exc, requests.exceptions.HTTPError):
        response = exc.response
    return retry_after_seconds(response) if response is not None else None


def _wait_for_rate_limit(rate_limiter: Optional[Union[_RateLimiter, Callable[[], None]]]) -> None:
    if rate_limiter is None:
        return
    if callable(rate_limiter):
        rate_limiter()
        return
    rate_limiter.wait()


def _safe_error_message(exc: BaseException) -> str:
    detail = redact_text(str(exc)).strip()
    name = type(exc).__name__
    return f"{name}: {detail}" if detail else name


def send_with_retry(
    send: Callable[[], str],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    rate_limiter: Optional[Union[_RateLimiter, Callable[[], None]]] = None,
    logger: Optional[logging.Logger] = None,
    base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS,
    max_retry_after_seconds: float = DEFAULT_MAX_RETRY_AFTER_SECONDS,
    sleep: Optional[Callable[[float], None]] = None,
    jitter: Optional[Callable[[float, float], float]] = None,
    circuit_breaker: Optional[TransportCircuitBreaker] = None,
) -> TransportResult:
    """Run ``send`` with bounded retries for transient transport failures.

    ``max_attempts`` is the total number of network calls, not additional
    retries. The rate limiter is applied to **every** attempt. Retry-After is
    honored when supplied, capped to prevent an unbounded worker stall. No
    delay occurs after the final failed attempt.
    """
    attempts_limit = max(1, int(max_attempts or 1))
    base_delay = max(0.0, float(base_backoff_seconds or 0.0))
    sleep_fn = sleep or time.sleep
    jitter_fn = jitter or random.uniform

    if circuit_breaker and circuit_breaker.is_open:
        return circuit_breaker.blocked_result()

    for attempt_index in range(attempts_limit):
        if circuit_breaker and circuit_breaker.is_open:
            return circuit_breaker.blocked_result()
        _wait_for_rate_limit(rate_limiter)
        try:
            response = send()
            if not isinstance(response, str):
                response = str(response)
            # Legacy or third-party connectors may still return an error string
            # instead of raising. Treat that sentinel as a non-analyzable
            # transport failure; do not infer retryability from brittle text.
            if response.lstrip().upper().startswith("ERROR:"):
                result = TransportResult(
                    response=None,
                    error=redact_text(response.strip()),
                    attempts=attempt_index + 1,
                    retryable=False,
                )
                if circuit_breaker:
                    circuit_breaker.record(result)
                return result
            result = TransportResult(response=response, error=None, attempts=attempt_index + 1)
            if circuit_breaker:
                circuit_breaker.record(result)
            return result
        except Exception as exc:  # converted into a typed, non-analyzable outcome
            status_code = _status_code_from_exception(exc)
            retryable = _is_retryable_exception(exc, status_code)
            final_attempt = attempt_index == attempts_limit - 1

            if not retryable or final_attempt:
                result = TransportResult(
                    response=None,
                    error=_safe_error_message(exc),
                    attempts=attempt_index + 1,
                    status_code=status_code,
                    retryable=retryable,
                )
                if circuit_breaker:
                    circuit_breaker.record(result)
                return result

            retry_after = _retry_after_for_exception(exc)
            if retry_after is not None:
                wait_seconds = min(max_retry_after_seconds, retry_after)
                wait_reason = "Retry-After"
            else:
                wait_seconds = base_delay * (2 ** attempt_index) + max(0.0, jitter_fn(0.0, 1.0))
                wait_reason = "exponential backoff"

            if logger:
                logger.warning(
                    "Transient transport failure (%s%s); retrying attempt %d/%d after %.2fs via %s.",
                    f"HTTP {status_code}" if status_code is not None else type(exc).__name__,
                    "" if status_code is not None else "",
                    attempt_index + 2,
                    attempts_limit,
                    wait_seconds,
                    wait_reason,
                )
            sleep_fn(wait_seconds)

    # Defensive fallback; the loop always returns on success/failure.
    result = TransportResult(response=None, error="Retry loop exhausted", attempts=attempts_limit)
    if circuit_breaker:
        circuit_breaker.record(result)
    return result
