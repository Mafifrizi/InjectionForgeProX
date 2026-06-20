"""Regression checks for dependency-boundary policy.

The project intentionally uses bounded compatible ranges rather than a single
cross-platform hash lock. These checks stop accidental reintroduction of bare
or unbounded direct dependencies in the files that users and CI install from.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_NAME_RE = re.compile(r"^([A-Za-z0-9_.-]+)")
_QUOTED_RE = re.compile(r'^\s*"([^"]+)"\s*,?\s*$')


def _canonical_name(spec: str) -> str:
    match = _NAME_RE.match(spec.strip())
    assert match, f"Invalid dependency specifier: {spec!r}"
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def _is_bounded(spec: str) -> bool:
    # A direct dependency must declare both a reviewed floor and an upper bound.
    # We support either a compatible range (>=x,<y) or an exact == pin.
    compact = spec.replace(" ", "")
    return (">=" in compact and "<" in compact) or "==" in compact


def _requirements_specs() -> list[str]:
    specs: list[str] = []
    for raw in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        specs.append(line)
    return specs


def _project_dependency_specs() -> dict[str, str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    sections = {
        "runtime": re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)^\]", text),
        "test": re.search(r"(?ms)^test\s*=\s*\[(.*?)^\]", text),
        "browser": re.search(r"(?ms)^browser\s*=\s*\[(.*?)^\]", text),
        "build": re.search(r"(?ms)^requires\s*=\s*\[(.*?)^\]", text),
    }
    collected: dict[str, str] = {}
    for section, match in sections.items():
        assert match, f"Missing {section} dependency section"
        for raw in match.group(1).splitlines():
            quoted = _QUOTED_RE.match(raw)
            if quoted:
                spec = quoted.group(1)
                collected[_canonical_name(spec)] = spec
    return collected


def test_all_installer_facing_dependencies_are_bounded() -> None:
    specs = _requirements_specs()
    assert specs, "requirements.txt must not be empty"
    for spec in specs:
        assert _is_bounded(spec), f"Unbounded requirement: {spec}"

    for name, spec in _project_dependency_specs().items():
        assert _is_bounded(spec), f"Unbounded {name} dependency: {spec}"


def test_requirements_are_declared_in_project_metadata() -> None:
    metadata = _project_dependency_specs()
    for spec in _requirements_specs():
        name = _canonical_name(spec)
        assert name in metadata, f"{spec} exists in requirements.txt but not pyproject.toml"
        assert metadata[name] == spec, (
            f"Dependency mismatch for {name}: requirements.txt={spec!r}, "
            f"pyproject.toml={metadata[name]!r}"
        )


def test_unused_default_dependencies_are_not_reintroduced() -> None:
    runtime = _project_dependency_specs()
    for name in ("numpy", "httpx", "openai", "playwright"):
        assert name not in runtime, f"Unused default dependency reintroduced: {name}"
