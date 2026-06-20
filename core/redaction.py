"""Redaction helpers for reports, runtime storage, and operational logs.

The analyzer remains the source of truth for extracted values. ``redact_result``
masks concrete analyzer findings first, then applies conservative fallback patterns
for credentials, privacy data, URLs, and common token formats.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Iterable, List, Sequence

# Public for compatibility. The first patterns cover credentials and URLs; the
# remaining patterns cover system-instruction labels and labeled PII.
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(?P<scheme>bearer|basic)\s+(?P<value>[a-z0-9._\-+/=]{12,})"),
    re.compile(r"(?i)\b(?P<value>sk-[a-z0-9][a-z0-9_\-]{12,})\b"),
    re.compile(
        r'''(?ix)
        \b(?P<label>api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|
        authorization|token|secret|password|passwd|kata\s+sandi|sandi)
        (?P<separator>\s*(?::|=|\bis\b|\bare\b|\badalah\b|\byaitu\b)\s*)
        (?P<quote>['\"]?)(?P<value>[^\s,'\";]{4,})(?P=quote)
        '''
    ),
    re.compile(
        r"(?i)([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|"
        r"token|secret|password|passwd|authorization|auth|credential|session(?:id)?|cookie|jwt|signature|sig|key)=)([^&#\s]+)"
    ),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{24,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9_\-/]{10,}"),
    re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]{0,20000}?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----"),
    re.compile(r"\bFLAG\{[^}\n]{3,}\}"),
    re.compile(
        r'''(?ix)
        \b(?P<label>system\s*prompt|system\s*instruction|developer\s*instruction|prompt\s*sistem|
        instruksi\s*sistem|perintah\s*sistem|instruksi\s*developer)
        (?P<separator>\s*:\s*)(?P<value>[^\n]{3,})
        '''
    ),
    re.compile(r'''(?ix)\b(?P<label>nik|ktp)(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>\d{16})\b'''),
    re.compile(r'''(?ix)\b(?P<label>npwp)(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>(?:\d{2}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d[.\-]?\d{3}[.\-]?\d{3}|\d{15,16}))\b'''),
    re.compile(r'''(?ix)\b(?P<label>(?:phone|telephone|mobile|telepon|nomor\s*(?:telepon|hp)|no\.?(?:\s*hp)?))(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>(?:\+?62|0)8[1-9][0-9\-\s]{6,13})\b'''),
    re.compile(r'''(?ix)\b(?P<label>email(?:\s+(?:pelanggan|customer|user|pengguna))?)\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b'''),
    re.compile(r'''(?ix)\b(?P<label>(?:(?:nomor\s+)?kartu\s+kredit|credit\s+card(?:\s+number)?))(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>(?:\d[ -]?){13,19}\d)\b'''),
    re.compile(r'''(?ix)\b(?P<label>(?:nomor\s+rekening|rekening|bank\s+account(?:\s+number)?))(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>\d{8,20})\b'''),
    re.compile(r'''(?ix)\b(?P<label>(?:tanggal\s+lahir|date\s+of\s+birth|dob))(?:\s+(?:pelanggan|customer|user|pengguna))?\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)['\"]?(?P<value>(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}))\b'''),
    re.compile(r'''(?im)\b(?P<label>alamat(?:\s+(?:pelanggan|customer|user|pengguna))?|address(?:\s+(?:of\s+)?(?:customer|user))?)\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)(?P<value>[^\n]{5,160})'''),
    re.compile(r'''(?im)\b(?P<label>nama\s+(?:pelanggan|customer|user|pengguna)|customer\s+name|user\s+name)\s*(?P<separator>\s*(?:[:=]|\bis\b|\badalah\b|\byaitu\b)\s*)(?P<value>[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ .'-]{2,100})'''),
]

_SECRET_VALUE_KEYS = {
    "leaked_data", "value", "raw_value", "value_preview", "secret_value",
    "credential", "credentials",
}
_SECRET_KEY_MARKERS = {
    "token", "secret", "password", "passwd", "api_key", "apikey",
    "authorization", "cookie", "credential", "nik", "npwp", "rekening",
    "credit_card", "kartu_kredit",
}
_PLACEHOLDER_VALUES = {
    "", "[redacted]", "[retracted]", "[masked]", "<redacted>", "<masked>",
    "[email_redacted]", "[jwt_redacted]", "[pii_redacted]",
}

# High-confidence unlabelled identifiers are masked for report/log privacy.
# They are not used as analyzer findings because redaction should favor privacy
# while analysis should avoid turning ordinary numeric text into a security alert.
_UNLABELED_PII_PATTERNS = [
    re.compile(r"(?<!\d)\d{16}(?!\d)"),
    re.compile(r"(?<!\d)\d{2}[.\-]?\d{3}[.\-]?\d{3}[.\-]?\d[.\-]?\d{3}[.\-]?\d{3}(?!\d)"),
    re.compile(r"(?<!\d)(?:\+?62|0)8[1-9][0-9\-\s]{6,13}(?!\d)"),
]
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}\d(?!\d)")


def _luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value or "")
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0



def _mask_token(token: str, keep: int = 4) -> str:
    del keep
    return "[REDACTED]" if token else token


def _assignment_repl(match: re.Match) -> str:
    separator = match.group("separator")
    # Word separators ("is", "adalah", "yaitu") may be captured without a
    # leading space; restore readability without preserving the sensitive value.
    if separator and separator[0].isalpha():
        separator = " " + separator
    return f"{match.group('label')}{separator}[REDACTED]"


def _scheme_repl(match: re.Match) -> str:
    return f"{match.group('scheme')} [REDACTED]"


def redact_text(value: Any, enabled: bool = True) -> Any:
    """Mask common secrets and labeled privacy data in arbitrary text.

    Unlabelled PII remains untouched to avoid sweeping false positives. Strong
    token formats are masked wherever they occur; PII is masked when a clear
    field label is present.
    """
    if not enabled or not isinstance(value, str):
        return value

    text = value
    text = SENSITIVE_PATTERNS[0].sub(_scheme_repl, text)
    text = SENSITIVE_PATTERNS[1].sub(lambda m: _mask_token(m.group('value')), text)
    text = SENSITIVE_PATTERNS[2].sub(_assignment_repl, text)
    text = SENSITIVE_PATTERNS[3].sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = SENSITIVE_PATTERNS[4].sub("[JWT_REDACTED]", text)
    text = SENSITIVE_PATTERNS[5].sub("[EMAIL_REDACTED]", text)
    # Token and PII/system-label patterns are intentionally handled by their
    # named groups instead of hard-coded list indexes. This keeps redaction
    # behavior stable as new strong token formats are added.
    for pattern in SENSITIVE_PATTERNS[6:]:
        groups = pattern.groupindex
        if "label" in groups and "separator" in groups:
            text = pattern.sub(_assignment_repl, text)
        else:
            text = pattern.sub("[REDACTED]", text)
    for pattern in _UNLABELED_PII_PATTERNS:
        text = pattern.sub("[PII_REDACTED]", text)
    text = _CARD_CANDIDATE.sub(lambda match: "[PII_REDACTED]" if _luhn_valid(match.group(0)) else match.group(0), text)
    return text


def _is_useful_sensitive_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    cleaned = value.strip()
    if len(cleaned) < 4:
        return False
    if cleaned.lower() in _PLACEHOLDER_VALUES:
        return False
    if cleaned.startswith("[") and cleaned.endswith("]"):
        return False
    return True


def _collect_sensitive_literals(result: Dict[str, Any]) -> List[str]:
    values: List[str] = []

    def add(candidate: Any) -> None:
        if _is_useful_sensitive_literal(candidate):
            values.append(candidate.strip())

    leaked_data = result.get("leaked_data", [])
    if isinstance(leaked_data, (list, tuple, set)):
        for item in leaked_data:
            add(item)
    else:
        add(leaked_data)

    evidence = result.get("evidence", [])
    if isinstance(evidence, dict):
        evidence = [evidence]
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes)):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            for key in ("raw_value", "value", "secret_value"):
                add(item.get(key))

    return sorted(set(values), key=len, reverse=True)


def _redact_known_literals(text: str, literals: Sequence[str]) -> str:
    redacted = text
    for literal in literals:
        redacted = re.sub(re.escape(literal), "[REDACTED]", redacted)
    return redacted


def _redact_recursive(obj: Any, literals: Sequence[str], enabled: bool = True, key_hint: str = "") -> Any:
    if not enabled:
        return obj
    key_lower = key_hint.lower()
    if key_lower in _SECRET_VALUE_KEYS or any(marker in key_lower for marker in _SECRET_KEY_MARKERS):
        if isinstance(obj, str):
            return "[REDACTED]" if obj else obj
        if isinstance(obj, (list, tuple, set)):
            return ["[REDACTED]" for _ in obj]
    if isinstance(obj, str):
        return _redact_known_literals(redact_text(obj, enabled=True), literals)
    if isinstance(obj, list):
        return [_redact_recursive(item, literals, enabled=True, key_hint=key_hint) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_recursive(item, literals, enabled=True, key_hint=key_hint) for item in obj)
    if isinstance(obj, dict):
        return {key: _redact_recursive(value, literals, enabled=True, key_hint=str(key)) for key, value in obj.items()}
    return obj


def redact_result(result: Dict[str, Any], enabled: bool = True) -> Dict[str, Any]:
    """Return a deep-copied, share-safe representation of an analysis result."""
    if not enabled:
        return result
    copied = copy.deepcopy(result)
    literals = _collect_sensitive_literals(copied)
    return _redact_recursive(copied, literals, enabled=True)


def redact_results(results: Iterable[Dict[str, Any]], enabled: bool = True) -> list:
    if not enabled:
        return list(results)
    return [redact_result(item, enabled=True) for item in results]
