import copy
import re
from typing import Any, Dict, Iterable

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(bearer\s+)[a-z0-9._\-+/=]{12,}"),
    re.compile(r"(?i)\b(sk-[a-z0-9][a-z0-9_\-]{12,})\b"),
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|kata\s+sandi|sandi)\s*[:=]\s*(['\"]?)([^\s,'\";]{4,})(\2)"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
]


def _mask_token(token: str, keep: int = 4) -> str:
    if not token:
        return token
    if len(token) <= keep * 2:
        return "[REDACTED]"
    return f"{token[:keep]}...[REDACTED]...{token[-keep:]}"


def redact_text(value: Any, enabled: bool = True) -> Any:
    if not enabled or not isinstance(value, str):
        return value
    text = value

    def bearer_repl(match: re.Match) -> str:
        return match.group(1) + "[REDACTED]"

    def key_repl(match: re.Match) -> str:
        return _mask_token(match.group(1))

    def assignment_repl(match: re.Match) -> str:
        return f"{match.group(1)}=[REDACTED]"

    text = SENSITIVE_PATTERNS[0].sub(bearer_repl, text)
    text = SENSITIVE_PATTERNS[1].sub(key_repl, text)
    text = SENSITIVE_PATTERNS[2].sub(assignment_repl, text)
    text = SENSITIVE_PATTERNS[3].sub("[JWT_REDACTED]", text)
    text = SENSITIVE_PATTERNS[4].sub("[EMAIL_REDACTED]", text)
    return text


def _redact_recursive(obj: Any, enabled: bool = True) -> Any:
    if not enabled:
        return obj
    if isinstance(obj, str):
        return redact_text(obj, enabled=True)
    if isinstance(obj, list):
        return [_redact_recursive(item, enabled=True) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_recursive(item, enabled=True) for item in obj)
    if isinstance(obj, dict):
        redacted = {}
        for key, value in obj.items():
            key_lower = str(key).lower()
            if key_lower in {"leaked_data", "value", "raw_value"}:
                redacted[key] = _redact_recursive(value, enabled=True)
            elif any(marker in key_lower for marker in ["token", "secret", "password", "api_key", "apikey", "authorization", "cookie"]):
                redacted[key] = "[REDACTED]" if isinstance(value, str) else _redact_recursive(value, enabled=True)
            else:
                redacted[key] = _redact_recursive(value, enabled=True)
        return redacted
    return obj


def redact_result(result: Dict[str, Any], enabled: bool = True) -> Dict[str, Any]:
    if not enabled:
        return result
    return _redact_recursive(copy.deepcopy(result), enabled=True)


def redact_results(results: Iterable[Dict[str, Any]], enabled: bool = True) -> list:
    if not enabled:
        return list(results)
    return [redact_result(item, enabled=True) for item in results]
