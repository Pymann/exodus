"""Version pins (aiml spec/68 §7.2): the model and the check before a build."""

import io
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from exodus.models.project import ProjectConfig
from exodus.models.version_pin import VersionRange
from exodus.tools.build.version_pins import check_version_pins


def _release(tmp_path: Path, version: str = "v1.0.2.7") -> Path:
    root = tmp_path / "v"
    (root / "bin").mkdir(parents=True)
    (root / "lib" / "aiml").mkdir(parents=True)
    (root / "bin" / "aiml").write_text("#!/bin/sh\n")
    (root / "bin" / "aiml").chmod(0o755)
    (root / "env").write_text("# aiml venv\n")
    if version:
        (root / "lib" / "aiml.version").write_text(version + "\n")
    return root


def _config(compiler_pin=None, deps=None) -> ProjectConfig:
    compiler = {"name": "$AIML"}
    if compiler_pin is not None:
        compiler["version"] = compiler_pin
    return ProjectConfig.model_validate(
        {"name": "t", "compiler": compiler, "dependencies": deps or []}
    )


@pytest.fixture
def venv(tmp_path, monkeypatch):
    root = _release(tmp_path)
    monkeypatch.setenv("AIML", str(root / "bin" / "aiml"))
    monkeypatch.setenv("AIML_VENV", str(root))
    return root


def _check(cfg: ProjectConfig):
    return check_version_pins(cfg, "exodus.json", out=io.StringIO())


def test_a_pin_that_admits_the_compiler_says_nothing(venv):
    assert _check(_config({"ge": "1.0.2.7", "lt": "1.1"})) == []


def test_v_prefix_and_numeric_order(venv):
    assert _check(_config({"eq": "1.0.2.7"})) == []
    assert _check(_config({"lt": "1.0.10"})) == []


def test_a_mismatch_is_one_line_in_the_fixed_form(venv):
    lines = _check(_config({"gt": "1.0.2.7"}))
    assert lines == [
        "aiml: version-mismatch compiler aiml v1.0.2.7 not in {gt 1.0.2.7}"
        " (exodus.json)"
    ]


def test_an_unreleased_compiler_matches_no_pin(tmp_path, monkeypatch):
    root = _release(tmp_path, version="")
    monkeypatch.setenv("AIML", str(root / "bin" / "aiml"))
    lines = _check(_config({"ge": "0"}))
    assert len(lines) == 1 and "not a released compiler" in lines[0]
    (root / "lib" / "aiml.version").write_text("git-abc1234\n")
    lines = _check(_config({"ge": "0"}))
    assert len(lines) == 1 and "not a released version" in lines[0]


def test_dependencies_are_checked_against_the_venv(venv):
    cfg = _config(deps=[{"name": "ufo", "version": {"eq": "0.1.0"}}])
    lines = _check(cfg)
    assert len(lines) == 1 and "dependency ufo none" in lines[0]
    assert "not installed" in lines[0]
    record = venv / "lib" / "aiml" / "aiml.installed.json"
    record.write_text(json.dumps({"tools": {"ufo": {"version": "0.1.0"}}}))
    assert _check(cfg) == []


def test_a_dependency_without_a_pin_is_not_checked(venv):
    assert _check(_config(deps=[{"name": "aiml"}])) == []


@pytest.mark.parametrize(
    "bad",
    [
        "1.0.2.7",
        {"eq": "1.0", "lt": "2"},
        {"gte": "1.0"},
        {"gt": "2", "lt": "1"},
        {"ge": "1.0", "lt": "1.0"},
        {"eq": "1.0-rc1"},
        {},
    ],
)
def test_refused(bad):
    with pytest.raises(ValidationError):
        _config(bad)


def test_ranges():
    r = VersionRange(ge="1.0.2.7", lt="1.1")
    assert r.admits("1.0.2.7") and r.admits("1.0.9") and not r.admits("1.1")
    assert VersionRange(le="1.0").admits("1.0.0.0")
    assert VersionRange(ge="1.0", le="1.0").admits("1")
