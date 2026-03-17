import argparse
import os
import tempfile
import unittest
from pathlib import Path

from exodus.tools.build.build import BuildTool


class BuildDependencyTests(unittest.TestCase):
    """Tests for the generic .d file dependency mechanism."""

    def _make_tool(self) -> BuildTool:
        args = argparse.Namespace(
            jobs=1,
            clean=False,
            config="exodus.json",
            all=False,
        )
        return BuildTool(args)

    def test_recompiles_when_d_file_dependency_is_newer(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_file = root / "main.src"
            imported_file = root / "lib.src"
            source_file.write_text("dummy", encoding="utf-8")
            imported_file.write_text("dummy", encoding="utf-8")

            obj_file = root / "out" / "main.o"
            obj_file.parent.mkdir(parents=True)
            obj_file.write_text("", encoding="utf-8")

            # Write .d file in Makefile format (same as gcc -MMD)
            dep_file = obj_file.with_suffix(".d")
            dep_file.write_text(
                f"{obj_file}: {source_file} \\\n  {imported_file}\n",
                encoding="utf-8",
            )

            # Source older than obj, but imported file newer than obj
            os.utime(source_file, (1_700_000_000, 1_700_000_000))
            os.utime(obj_file, (1_700_000_010, 1_700_000_010))
            os.utime(imported_file, (1_700_000_020, 1_700_000_020))

            should_recompile = self._make_tool()._should_recompile(
                source_file,
                obj_file,
            )

            self.assertTrue(should_recompile)

    def test_no_recompile_when_d_file_deps_are_older(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_file = root / "main.src"
            imported_file = root / "lib.src"
            source_file.write_text("dummy", encoding="utf-8")
            imported_file.write_text("dummy", encoding="utf-8")

            obj_file = root / "out" / "main.o"
            obj_file.parent.mkdir(parents=True)
            obj_file.write_text("", encoding="utf-8")

            dep_file = obj_file.with_suffix(".d")
            dep_file.write_text(
                f"{obj_file}: {source_file} \\\n  {imported_file}\n",
                encoding="utf-8",
            )

            # All deps older than obj
            os.utime(source_file, (1_700_000_000, 1_700_000_000))
            os.utime(imported_file, (1_700_000_005, 1_700_000_005))
            os.utime(obj_file, (1_700_000_010, 1_700_000_010))

            should_recompile = self._make_tool()._should_recompile(
                source_file,
                obj_file,
            )

            self.assertFalse(should_recompile)

    def test_recompiles_when_no_obj_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source_file = root / "main.c"
            source_file.write_text("dummy", encoding="utf-8")
            obj_file = root / "out" / "main.o"

            should_recompile = self._make_tool()._should_recompile(
                source_file,
                obj_file,
            )

            self.assertTrue(should_recompile)


if __name__ == "__main__":
    unittest.main()
