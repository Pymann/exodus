"""A library_path that does not exist must not be silent.

The linker ignores a -L it cannot read and the loader skips a dead rpath
entry, so the host's copy is used instead without a word.  That is how a
stale pin hides, so the build has to say it.
"""
import logging
from types import SimpleNamespace

from exodus.tools.build import build as b


def _tool():
    tool = b.BuildTool.__new__(b.BuildTool)
    tool.logger = b.get_logger("test")
    return tool


def test_existing_path_is_quiet(tmp_path, caplog):
    (tmp_path / "lib").mkdir()
    with caplog.at_level(logging.WARNING):
        assert _tool()._check_library_path(str(tmp_path / "lib")) is True
    assert caplog.records == []


def test_missing_path_warns(tmp_path, caplog):
    missing = str(tmp_path / "apt" / "libssl3t64" / "3.0.13-0ubuntu3.7" / "lib")
    with caplog.at_level(logging.WARNING):
        assert _tool()._check_library_path(missing) is False
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert missing in msg
    assert "does not exist" in msg
    assert "pkg install" in msg   # says what to do, not just what is wrong


def test_warns_once_per_path(tmp_path, caplog):
    tool = _tool()
    a = str(tmp_path / "a")
    bb = str(tmp_path / "b")
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            tool._check_library_path(a)
        tool._check_library_path(bb)
    # one line per distinct path, not one per link
    assert len(caplog.records) == 2
