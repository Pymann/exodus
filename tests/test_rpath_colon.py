import os
from pathlib import Path
from types import SimpleNamespace

from exodus.tools.build import build as b


def _tool():
    tool = b.BuildTool.__new__(b.BuildTool)
    tool.logger = b.get_logger("test")
    return tool


def test_plain_path_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("EXODUS_CACHE", str(tmp_path / "c"))
    cfg = SimpleNamespace(source_root=tmp_path)
    assert _tool()._rpath_entry("/usr/lib/x", cfg) == "/usr/lib/x"


def test_epoch_path_gets_a_colon_free_alias(tmp_path, monkeypatch):
    cache = tmp_path / "c"
    real = cache / "apt" / "libllvm18" / "amd64" / "1:18.1.3-1ubuntu1" / "payload" / "lib"
    real.mkdir(parents=True)
    (real / "libLLVM.so.18.1").write_text("x")
    monkeypatch.setenv("EXODUS_CACHE", str(cache))
    cfg = SimpleNamespace(source_root=tmp_path)
    tool = _tool()
    entry = tool._rpath_entry(str(real), cfg)
    assert entry is not None and ":" not in entry
    assert Path(entry) == cache.resolve() / "rpath" / "apt" / "libllvm18" / "amd64" / "1%3a18.1.3-1ubuntu1" / "payload" / "lib"
    assert (Path(entry) / "libLLVM.so.18.1").read_text() == "x"
    # idempotent
    assert tool._rpath_entry(str(real), cfg) == entry


def test_stale_alias_is_repointed(tmp_path, monkeypatch):
    cache = tmp_path / "c"
    real = cache / "apt" / "z" / "amd64" / "1:1.0" / "lib"
    other = tmp_path / "elsewhere"
    real.mkdir(parents=True)
    other.mkdir()
    monkeypatch.setenv("EXODUS_CACHE", str(cache))
    cfg = SimpleNamespace(source_root=tmp_path)
    alias = cache / "rpath" / "apt" / "z" / "amd64" / "1%3a1.0" / "lib"
    alias.parent.mkdir(parents=True)
    alias.symlink_to(other, target_is_directory=True)
    entry = _tool()._rpath_entry(str(real.resolve()), cfg)
    assert entry == str(cache.resolve() / "rpath" / "apt" / "z" / "amd64" / "1%3a1.0" / "lib")
    assert Path(os.readlink(alias)) == real.resolve()


def test_colon_path_outside_cache_is_left_out(tmp_path, monkeypatch):
    monkeypatch.setenv("EXODUS_CACHE", str(tmp_path / "c"))
    cfg = SimpleNamespace(source_root=tmp_path)
    assert _tool()._rpath_entry("/opt/odd:dir/lib", cfg) is None
