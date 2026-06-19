"""Lightweight multilingual support for InjectionForge Pro X.

The module intentionally avoids heavyweight language-detection dependencies so
`--offline` remains truly lightweight. It supports English, Indonesian, mixed,
and auto mode using deterministic keyword scoring.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Mapping, Sequence

SUPPORTED_LANGUAGES = ("auto", "en", "id", "mixed")

LANGUAGE_ALIASES = {
    "english": "en",
    "eng": "en",
    "en-us": "en",
    "en_gb": "en",
    "indonesia": "id",
    "indonesian": "id",
    "bahasa": "id",
    "bahasa-indonesia": "id",
    "bindo": "id",
    "indo": "id",
    "id-id": "id",
    "multi": "mixed",
    "multilingual": "mixed",
    "bilingual": "mixed",
}

ID_STOPWORDS = {
    "aku", "anda", "apa", "apakah", "bantu", "bisa", "boleh", "dapat",
    "dengan", "di", "ini", "itu", "jangan", "kamu", "kami", "karena",
    "kata", "ke", "mohon", "sandi", "saya", "sebagai", "sebelumnya",
    "sistem", "tidak", "tolong", "untuk", "yang", "rahasia", "instruksi",
    "pengembang", "internal", "konfigurasi", "kunci", "akses", "token",
}

EN_STOPWORDS = {
    "a", "about", "admin", "and", "are", "as", "assist", "can", "cannot",
    "configuration", "developer", "for", "from", "hello", "hidden", "i",
    "instruction", "internal", "key", "password", "please", "previous",
    "reveal", "secret", "show", "sorry", "system", "that", "the", "this",
    "token", "to", "you", "your",
}

ID_REFUSAL = [
    "maaf", "saya tidak bisa", "saya tidak dapat", "tidak bisa membantu",
    "tidak dapat membantu", "tidak boleh", "tidak diizinkan", "tidak bisa memberikan",
    "tidak dapat memberikan", "tidak bisa membagikan", "tidak dapat membagikan",
    "saya tidak akan", "saya harus menolak", "permintaan tersebut tidak dapat",
]

EN_REFUSAL = [
    "i cannot", "i can't", "i am unable", "i'm unable", "sorry", "i won't",
    "i will not", "not able to", "cannot assist", "can't assist",
]

ID_SENSITIVE_KEYWORDS = [
    "instruksi sistem", "prompt sistem", "perintah sistem", "kamu adalah",
    "anda adalah", "kata sandi", "sandi", "rahasia", "token internal",
    "kunci api", "kunci akses", "kredensial", "konfigurasi", "mode debug",
    "mode pengembang", "data internal", "admin", "database", "env",
]

EN_SENSITIVE_KEYWORDS = [
    "system prompt", "system instruction", "initial instruction", "you are",
    "password", "secret", "token", "api key", "credential", "configuration",
    "debug mode", "developer mode", "internal data", "admin", "database", "env",
]


@dataclass(frozen=True)
class LanguageProfile:
    language: str
    confidence: float
    scores: Mapping[str, int]


def normalize_language(language: str | None) -> str:
    """Normalize user input into auto/en/id/mixed."""
    if not language:
        return "auto"
    value = str(language).strip().lower().replace("_", "-")
    value = LANGUAGE_ALIASES.get(value, value)
    if value not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language '{language}'. Use: {', '.join(SUPPORTED_LANGUAGES)}")
    return value


def language_family(language: str | None) -> tuple[str, ...]:
    """Return concrete language set used by a mode."""
    language = normalize_language(language)
    if language == "en":
        return ("en",)
    if language == "id":
        return ("id",)
    return ("en", "id")


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-zA-ZÀ-ÿ]+", (text or "").lower())


def score_language(text: str) -> dict[str, int]:
    tokens = _tokens(text)
    token_set = set(tokens)
    score_id = sum(1 for token in token_set if token in ID_STOPWORDS)
    score_en = sum(1 for token in token_set if token in EN_STOPWORDS)

    lower = (text or "").lower()
    # Phrase-level boosts for high-signal terms.
    score_id += sum(2 for phrase in ID_REFUSAL + ID_SENSITIVE_KEYWORDS if phrase in lower)
    score_en += sum(2 for phrase in EN_REFUSAL + EN_SENSITIVE_KEYWORDS if phrase in lower)
    return {"id": score_id, "en": score_en}


def detect_language_profile(text: str, min_score: int = 2, mixed_margin: int = 1) -> LanguageProfile:
    """Detect Indonesian/English/mixed/unknown with deterministic scores."""
    scores = score_language(text)
    id_score = scores["id"]
    en_score = scores["en"]
    total = id_score + en_score

    if total < min_score:
        return LanguageProfile("unknown", 0.0, scores)

    # Treat code-switching as mixed even when one language is slightly dominant.
    # This catches common Indonesian/English chatbot responses such as
    # "Maaf, I can't assist with that token request."
    if id_score and en_score:
        minor = min(id_score, en_score)
        major = max(id_score, en_score)
        if abs(id_score - en_score) <= mixed_margin or (minor / major) >= 0.35 or minor >= 3:
            confidence = min(0.99, total / (total + 3))
            return LanguageProfile("mixed", confidence, scores)

    if id_score > en_score:
        confidence = min(0.99, (id_score - en_score + 1) / (total + 1))
        return LanguageProfile("id", confidence, scores)

    confidence = min(0.99, (en_score - id_score + 1) / (total + 1))
    return LanguageProfile("en", confidence, scores)


def detect_language(text: str) -> str:
    return detect_language_profile(text).language


def detect_language_from_samples(samples: Iterable[str]) -> LanguageProfile:
    combined_scores = {"id": 0, "en": 0}
    for sample in samples:
        scores = score_language(sample)
        combined_scores["id"] += scores["id"]
        combined_scores["en"] += scores["en"]
    combined = " ".join(str(s) for s in samples if s)
    if not combined.strip():
        return LanguageProfile("unknown", 0.0, combined_scores)
    return detect_language_profile(combined)


def resolve_language(requested: str | None, samples: Sequence[str] | None = None,
                     fallback: str = "mixed") -> str:
    """Resolve auto into a concrete language mode using samples when available."""
    requested = normalize_language(requested)
    if requested != "auto":
        return requested
    if samples:
        profile = detect_language_from_samples(samples)
        if profile.language in ("en", "id", "mixed") and profile.confidence >= 0.35:
            return profile.language
    return fallback


def should_include_indonesian(language: str | None) -> bool:
    return "id" in language_family(language)


def should_include_english(language: str | None) -> bool:
    return "en" in language_family(language)


def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen = set()
    output = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output
