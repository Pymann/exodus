import os
from pathlib import Path

import pytest

from exodus.tools.build import build as b


def _venv(tmp_path: Path) -> Path:
    root = tmp_path / "v"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "aiml").write_text("#!/bin/sh\n")
    (root / "bin" / "aiml").chmod(0o755)
    (root / "env").write_text("# aiml venv\nexport AIML_VENV='x'\n")
    return root


def test_env_variables_win(monkeypatch):
    monkeypatch.setenv("AIML_VENV", "/opt/v")
    monkeypatch.setenv("AIML", "/opt/v/bin/aiml")
    assert b.aiml_venv_root() == "/opt/v"
    assert b.aiml_compiler() == "/opt/v/bin/aiml"


def test_venv_from_compiler_on_path(monkeypatch, tmp_path):
    root = _venv(tmp_path)
    monkeypatch.delenv("AIML_VENV", raising=False)
    monkeypatch.delenv("AIML", raising=False)
    monkeypatch.setenv("PATH", str(root / "bin"))
    assert b.aiml_venv_root() == str(root.resolve())
    assert b.aiml_compiler() == str(root / "bin" / "aiml")


def test_compiler_from_venv(monkeypatch):
    monkeypatch.delenv("AIML", raising=False)
    monkeypatch.setenv("AIML_VENV", "/opt/v")
    assert b.aiml_compiler() == "/opt/v/bin/aiml"


def test_unresolvable_is_an_error(monkeypatch, tmp_path):
    for k in ("AIML", "AIML_VENV"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(b.AimlPlaceholderError, match="<venv>/env"):
        b.aiml_compiler()
    with pytest.raises(b.AimlPlaceholderError, match="<venv>/env"):
        b.aiml_venv_root()


def test_origin_is_left_alone(monkeypatch):
    monkeypatch.setenv("AIML_VENV", "/opt/v")
    monkeypatch.setenv("AIML", "/opt/v/bin/aiml")
    tool = b.BuildTool.__new__(b.BuildTool)
    s = tool._expand_cache("-Wl,-rpath,$ORIGIN/../lib:$AIML_VENV/lib $AIML", None)
    assert s == "-Wl,-rpath,$ORIGIN/../lib:/opt/v/lib /opt/v/bin/aiml"
