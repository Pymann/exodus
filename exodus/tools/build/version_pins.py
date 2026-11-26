"""
The version pins of a configuration, checked before anything is compiled
(aiml spec/68 F68-98 to F68-100).

A mismatch is one line on stderr, in the form `aiml build` writes, and does
not stop the build: an incompatibility is a signal, not a failure.  A host
such as cosmos recognises the line and marks the step magenta (aiml spec/62
F62-47).
"""

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, TextIO

from exodus.models.project import ProjectConfig
from exodus.models.version_pin import VersionRange, parse_version


def _first_line(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    return lines[0].strip() if lines else ""


def _compiler_path(name: str) -> Optional[Path]:
    if "$AIML" in name:
        from exodus.tools.build.build import AimlPlaceholderError, aiml_compiler

        try:
            name = name.replace("$AIML", aiml_compiler())
        except AimlPlaceholderError:
            return None
    if "/" not in name:
        found = shutil.which(name)
        if not found:
            return None
        name = found
    return Path(name).resolve()


def _venv_root() -> Optional[Path]:
    env = os.environ.get("AIML_VENV")
    if env:
        return Path(env)
    from exodus.tools.build.build import AimlPlaceholderError, aiml_venv_root

    try:
        return Path(aiml_venv_root())
    except AimlPlaceholderError:
        return None


def _installed(root: Path) -> Dict[str, str]:
    record = root / "lib" / "aiml" / "aiml.installed.json"
    try:
        tools = json.loads(record.read_text(encoding="utf-8")).get("tools", {})
    except (OSError, ValueError, AttributeError):
        return {}
    return {
        str(k): str(v.get("version", ""))
        for k, v in tools.items()
        if isinstance(v, dict)
    }


def _line(
    kind: str,
    name: str,
    found: str,
    pin: VersionRange,
    config_file: str,
    reason: str,
) -> str:
    tail = f" — {reason}" if reason else ""
    return (
        f"aiml: version-mismatch {kind} {name} {found or 'none'} not in"
        f" {pin.show()} ({config_file}){tail}"
    )


def check_version_pins(
    config: ProjectConfig, config_file: str, out: TextIO = sys.stderr
) -> List[str]:
    """Write one line per mismatch and return them."""
    lines: List[str] = []
    pin = config.compiler.version
    if pin is not None:
        comp = _compiler_path(config.compiler.name)
        stamp = (
            comp.parent.parent / "lib" / "aiml.version" if comp else None
        )
        found = _first_line(stamp) if stamp else ""
        reason = ""
        if not found:
            reason = (
                f"no {stamp} — not a released compiler"
                if stamp
                else "the compiler cannot be found"
            )
        elif parse_version(found) is None:
            reason = "not a released version"
        if reason or not pin.admits(found):
            lines.append(
                _line("compiler", "aiml", found, pin, config_file, reason)
            )
    pinned = [d for d in config.dependencies if d.version is not None]
    if pinned:
        root = _venv_root()
        installed = _installed(root) if root else {}
        for dep in pinned:
            assert dep.version is not None
            found = installed.get(dep.name, "")
            if root is None:
                reason = "no venv to look in"
            elif dep.name not in installed:
                reason = f"not installed in {root}"
            elif not found:
                reason = "installed without a version"
            elif parse_version(found) is None:
                reason = "not a released version"
            else:
                reason = ""
            if reason or not dep.version.admits(found):
                lines.append(
                    _line(
                        "dependency",
                        dep.name,
                        found,
                        dep.version,
                        config_file,
                        reason,
                    )
                )
    for line in lines:
        print(line, file=out)
    return lines
