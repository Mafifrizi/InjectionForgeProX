"""Create a clean source ZIP without runtime data, cache, build, or VCS state."""

from __future__ import annotations

import argparse
import fnmatch
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {".git", ".pytest_cache", "__pycache__", "reports", "dist", "build", ".venv", "venv", ".mypy_cache"}
EXCLUDED_NAMES = {"injectionforge_results.db", "payloads.db"}
EXCLUDED_GLOBS = ("*.pyc", "*.pyo", "*.db", "*.db-wal", "*.db-shm", "*.log")


def project_version() -> str:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to read project version from pyproject.toml")
    return match.group(1)


def include(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_DIRS or part.endswith(".egg-info") for part in relative.parts):
        return False
    if path.name in EXCLUDED_NAMES:
        return False
    return not any(fnmatch.fnmatch(path.name, pattern) for pattern in EXCLUDED_GLOBS)


def build(output: Path, top_level: str) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            if path.is_file() and include(path):
                archive.write(path, Path(top_level) / path.relative_to(ROOT))
    return output


def main() -> None:
    version = project_version()
    parser = argparse.ArgumentParser(description="Build a clean InjectionForge source release ZIP.")
    parser.add_argument("--output", default=f"dist/InjectionForgeProX-v{version}.zip")
    parser.add_argument("--top-level", default=f"InjectionForgeProX-v{version}")
    args = parser.parse_args()
    output = build((ROOT / args.output).resolve(), args.top_level)
    print(f"Built clean release: {output}")


if __name__ == "__main__":
    main()
