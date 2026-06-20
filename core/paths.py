"""Path helpers for source checkouts and installed distributions."""

from __future__ import annotations

import os
import sys
import sysconfig
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent


def bundled_data_dir(data_dir: str = "data") -> Path:
    """Return the directory containing shipped payload and benchmark data.

    Source checkouts use ``<project>/data``. Installed wheels use setuptools
    ``data-files`` under ``<prefix>/share/injectionforge/data``. The package-root
    candidate is important for ``pip --target`` and embedded deployments where
    ``sysconfig.get_path('data')`` still points at the host interpreter.
    """
    override = os.environ.get("INJECTIONFORGE_DATA_DIR")
    candidates = []
    if override:
        candidates.append(Path(override).expanduser())
    candidates.extend([
        PROJECT_ROOT / data_dir,
        PACKAGE_ROOT.parent / "share" / "injectionforge" / data_dir,
        Path(sys.prefix) / "share" / "injectionforge" / data_dir,
        Path(sysconfig.get_path("data")) / "share" / "injectionforge" / data_dir,
        Path(sysconfig.get_path("data")) / "injectionforge" / data_dir,
    ])
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    return (PROJECT_ROOT / data_dir).resolve()


def runtime_dir() -> Path:
    """Return a user-writable runtime directory; never write into site-packages."""
    override = os.environ.get("INJECTIONFORGE_HOME")
    if override:
        base = Path(override).expanduser()
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "InjectionForgeProX"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "injectionforge"
    base.mkdir(parents=True, exist_ok=True)
    return base.resolve()


def source_checkout() -> bool:
    """Whether this code is running from a checkout with the bundled data folder."""
    return (PROJECT_ROOT / "data").is_dir()


def default_runtime_file(filename: str) -> Path:
    """Use the checkout root during development, user state directory when installed."""
    if source_checkout():
        return (PROJECT_ROOT / filename).resolve()
    return runtime_dir() / filename
