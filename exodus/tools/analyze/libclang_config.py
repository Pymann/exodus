"""Helpers for resolving libclang library path."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Union

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _version_key(path: Path) -> tuple[int, int, int]:
    name = path.name
    match = _VERSION_RE.search(name)
    if not match:
        return (0, 0, 0)
    major, minor, patch = match.groups()
    return (
        int(major) if major else 0,
        int(minor) if minor else 0,
        int(patch) if patch else 0,
    )


def _cache_root(cwd: Optional[Path] = None) -> Path:
    env = os.environ.get("EXODUS_CACHE")
    if env:
        return Path(env).expanduser().resolve()
    base = cwd if cwd is not None else Path.cwd()
    return (base / "__exodus_cache").resolve()


def resolve_libclang_path(
    cwd: Optional[Path] = None,
    preferred_path: Optional[Union[str, Path]] = None,
) -> Optional[Path]:
    if preferred_path:
        candidate = Path(preferred_path).expanduser()
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()

    cache_root = _cache_root(cwd)
    if not cache_root.exists():
        return None

    search_patterns = [
        "**/libclang.so",
        "**/libclang-*.so",
        "**/libclang-*.so.*",
    ]

    candidates: list[Path] = []
    for pattern in search_patterns:
        candidates.extend(p for p in cache_root.glob(pattern) if p.is_file())

    if not candidates:
        return None

    # Prefer highest discovered version from cache.
    candidates.sort(key=lambda p: (_version_key(p), str(p)))
    return candidates[-1].resolve()
