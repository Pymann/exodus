import argparse
import os
import tempfile
import unittest
from pathlib import Path

from exodus.models.project import ProjectConfig
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

    def _make_config(self, root: Path) -> ProjectConfig:
        return ProjectConfig(
            name="demo",
            source_root=root,
            build_root=root / "out",
        )

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

    def test_derives_expected_generated_aiml_objects_from_depfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = self._make_config(root)
            tool = self._make_tool()

            source_file = root / "client" / "main.aiml"
            imported_a = root / "client" / "cards_screen.aiml"
            imported_b = root / "shared" / "game_view.aiml"
            source_file.parent.mkdir(parents=True, exist_ok=True)
            imported_b.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text("dummy", encoding="utf-8")
            imported_a.write_text("dummy", encoding="utf-8")
            imported_b.write_text("dummy", encoding="utf-8")

            obj_file = tool._object_file_for_source(source_file, cfg)
            obj_file.parent.mkdir(parents=True, exist_ok=True)
            obj_file.write_text("", encoding="utf-8")
            dep_file = obj_file.with_suffix(".d")
            dep_file.write_text(
                f"{obj_file}: {source_file} \\\n  client/cards_screen.aiml \\\n  shared/game_view.aiml\n",
                encoding="utf-8",
            )

            expected = tool._expected_generated_aiml_objects_for_source(
                source_file,
                obj_file,
                cfg,
            )

            self.assertEqual(
                expected,
                {
                    obj_file.parent / "client_cards_screen_aiml.o",
                    obj_file.parent / "shared_game_view_aiml.o",
                },
            )

    def test_filters_unexpected_generated_aiml_objects_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = self._make_config(root)
            tool = self._make_tool()

            source_file = root / "client" / "main.aiml"
            imported_file = root / "client" / "cards_screen.aiml"
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text("dummy", encoding="utf-8")
            imported_file.write_text("dummy", encoding="utf-8")

            obj_file = tool._object_file_for_source(source_file, cfg)
            obj_file.parent.mkdir(parents=True, exist_ok=True)
            obj_file.write_text("", encoding="utf-8")
            obj_file.with_suffix(".d").write_text(
                f"{obj_file}: {source_file} \\\n  client/cards_screen.aiml\n",
                encoding="utf-8",
            )

            expected_extra = obj_file.parent / "client_cards_screen_aiml.o"
            stale_extra = obj_file.parent / "deleted_module_aiml.o"
            expected_extra.write_text("", encoding="utf-8")
            stale_extra.write_text("", encoding="utf-8")

            filtered = tool._filter_discovered_extra_objects(
                [source_file],
                [expected_extra, stale_extra],
                cfg,
            )

            self.assertEqual(filtered, [expected_extra])

    def test_missing_expected_generated_aiml_object_is_hard_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = self._make_config(root)
            tool = self._make_tool()

            source_file = root / "client" / "main.aiml"
            imported_file = root / "client" / "cards_screen.aiml"
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text("dummy", encoding="utf-8")
            imported_file.write_text("dummy", encoding="utf-8")

            obj_file = tool._object_file_for_source(source_file, cfg)
            obj_file.parent.mkdir(parents=True, exist_ok=True)
            obj_file.write_text("", encoding="utf-8")
            obj_file.with_suffix(".d").write_text(
                f"{obj_file}: {source_file} \\\n  client/cards_screen.aiml\n",
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                tool._filter_discovered_extra_objects(
                    [source_file],
                    [],
                    cfg,
                )

    def test_filters_unexpected_non_aiml_extra_object_from_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = self._make_config(root)
            tool = self._make_tool()

            source_file = root / "main.c"
            source_file.write_text("int main(void){return 0;}", encoding="utf-8")
            obj_file = tool._object_file_for_source(source_file, cfg)
            obj_file.parent.mkdir(parents=True, exist_ok=True)
            obj_file.write_text("", encoding="utf-8")

            stray_extra = obj_file.parent / "generated_helper.o"
            stray_extra.write_text("", encoding="utf-8")

            filtered = tool._filter_discovered_extra_objects(
                [source_file],
                [stray_extra],
                cfg,
            )

            self.assertEqual(filtered, [])

    def test_explicit_object_source_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            cfg = self._make_config(root)
            tool = self._make_tool()

            source_file = root / "main.c"
            source_file.write_text("int main(void){return 0;}", encoding="utf-8")
            explicit_obj = (root / "vendor" / "prebuilt.o").resolve()
            explicit_obj.parent.mkdir(parents=True, exist_ok=True)
            explicit_obj.write_text("", encoding="utf-8")

            filtered = tool._filter_discovered_extra_objects(
                [source_file, explicit_obj],
                [explicit_obj],
                cfg,
            )

            self.assertEqual(filtered, [explicit_obj])


if __name__ == "__main__":
    unittest.main()
