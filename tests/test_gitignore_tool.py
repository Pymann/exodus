import argparse
import os
import tempfile
import unittest
from pathlib import Path

from exodus.models.project import Project, ProjectConfig
from exodus.tools.gitignore import GitignoreTool


class GitignoreToolTests(unittest.TestCase):
    def test_collect_entries_uses_defaults_without_config(self) -> None:
        entries = GitignoreTool.collect_entries()

        self.assertEqual(entries, ["out/", "__exodus_cache/"])

    def test_collect_entries_adds_build_root_artifact_and_map_file(self) -> None:
        config = ProjectConfig(
            name="demo",
            build_root=Path("build-out"),
            artifact_in_cwd=True,
            output_type="shared_lib",
        )
        config.linker.map_file = Path("maps/demo.map")

        entries = GitignoreTool.collect_entries([config])

        self.assertEqual(
            entries,
            [
                "out/",
                "__exodus_cache/",
                "build-out/",
                "libdemo.so",
                "maps/demo.map",
            ],
        )

    def test_run_creates_gitignore_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            args = argparse.Namespace(config="missing.json", all=False)

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                rc = GitignoreTool(args).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            self.assertEqual(
                (root / ".gitignore").read_text(encoding="utf-8"),
                "# Exodus artifacts\nout/\n__exodus_cache/\n",
            )

    def test_run_extends_existing_gitignore_without_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            Project(
                root,
                ProjectConfig(
                    name="demo",
                    build_root=Path("build-out"),
                    artifact_in_cwd=True,
                    output_type="static_lib",
                ),
            ).save(root, config_name="exodus.json")
            (root / ".gitignore").write_text(
                "venv/\n__exodus_cache/\n",
                encoding="utf-8",
            )
            args = argparse.Namespace(config="exodus.json", all=False)

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                rc = GitignoreTool(args).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            self.assertEqual(
                (root / ".gitignore").read_text(encoding="utf-8"),
                "venv/\n__exodus_cache/\n\n# Exodus artifacts\nout/\nbuild-out/\nlibdemo.a\n",
            )

    def test_run_all_collects_entries_from_multiple_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            Project(
                root,
                ProjectConfig(name="alpha", build_root=Path("out-alpha")),
            ).save(root, config_name="alpha.json")
            Project(
                root,
                ProjectConfig(
                    name="beta",
                    build_root=Path("out-beta"),
                    artifact_in_cwd=True,
                ),
            ).save(root, config_name="beta.json")
            args = argparse.Namespace(config="exodus.json", all=True)

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                rc = GitignoreTool(args).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            self.assertEqual(
                (root / ".gitignore").read_text(encoding="utf-8"),
                "# Exodus artifacts\nout/\n__exodus_cache/\nout-alpha/\nout-beta/\nbeta\n",
            )


if __name__ == "__main__":
    unittest.main()
