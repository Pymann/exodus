import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exodus.models.project import EXODUS_PROJECT_SCHEMA, Project, ProjectConfig
from exodus.tools.build.build import BuildTool
from exodus.tools.pkg.package_manager import PackageManager
from exodus.tools.sbom.sbom import SbomTool


class MultiConfigCommandTests(unittest.TestCase):
    def _write_project_config(
        self, root: Path, config_name: str, name: str
    ) -> None:
        Project(root, ProjectConfig(name=name, sources=["*.c"])).save(
            root, config_name=config_name
        )

    def test_discover_config_names_filters_by_exodus_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project_config(root, "alpha.json", "alpha")
            self._write_project_config(root, "beta.json", "beta")
            (root / "foreign.json").write_text(
                json.dumps(
                    {
                        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json"
                    }
                ),
                encoding="utf-8",
            )
            (root / "broken.json").write_text("{", encoding="utf-8")

            config_names = Project.discover_config_names(root)

            self.assertEqual(config_names, ["alpha.json", "beta.json"])

    def test_build_all_runs_each_matching_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project_config(root, "alpha.json", "alpha")
            self._write_project_config(root, "beta.json", "beta")
            (root / "notes.json").write_text(
                json.dumps({"$schema": "not.exodus"}),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                jobs=1,
                clean=False,
                config="exodus.json",
                all=True,
            )
            seen: list[str] = []
            tool = BuildTool(args)

            def record_build(config_name: str) -> int:
                seen.append(config_name)
                return 0

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                with patch.object(
                    BuildTool,
                    "_run_config",
                    side_effect=record_build,
                ):
                    rc = tool.run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            self.assertEqual(seen, ["alpha.json", "beta.json"])

    def test_build_all_rejects_duplicate_project_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project_config(root, "alpha.json", "shared")
            self._write_project_config(root, "beta.json", "shared")
            args = argparse.Namespace(
                jobs=1,
                clean=False,
                config="exodus.json",
                all=True,
            )
            tool = BuildTool(args)

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                with patch.object(BuildTool, "_run_config") as run_config:
                    rc = tool.run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 1)
            run_config.assert_not_called()

    def test_build_can_place_final_output_in_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            args = argparse.Namespace(
                jobs=1,
                clean=False,
                config="exodus.json",
                all=False,
            )
            tool = BuildTool(args)
            config = ProjectConfig(
                name="demo",
                output_type="executable",
                artifact_in_cwd=True,
            )

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                output_file = tool._linked_output_file(config)
            finally:
                os.chdir(old_cwd)

            self.assertEqual(output_file, root / "demo")

    def test_sbom_all_generates_each_matching_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project_config(root, "alpha.json", "alpha")
            self._write_project_config(root, "beta.json", "beta")
            (root / "foreign.json").write_text(
                json.dumps(
                    {
                        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json"
                    }
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                config="exodus.json",
                action="manifest",
                all=True,
            )

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                rc = SbomTool(args).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            for name in ("alpha", "beta"):
                sbom_path = root / "out" / name / "manifest.sbom.json"
                self.assertTrue(sbom_path.exists())
                payload = json.loads(sbom_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    payload["$schema"],
                    "https://cyclonedx.org/schema/bom-1.6.schema.json",
                )

    def test_pkg_install_all_runs_each_matching_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project_config(root, "alpha.json", "alpha")
            self._write_project_config(root, "beta.json", "beta")
            (root / "foreign.json").write_text(
                json.dumps(
                    {"$schema": EXODUS_PROJECT_SCHEMA.replace("1.0", "2.0")}
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                action="install",
                name=None,
                arch=None,
                version=None,
                force=False,
                all=True,
            )
            seen: list[str] = []
            manager = PackageManager(args)

            def record_install(
                project: Project, config_name: str = "exodus.json"
            ) -> int:
                del project
                seen.append(config_name)
                return 0

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                with patch.object(
                    PackageManager,
                    "_install",
                    side_effect=record_install,
                ):
                    rc = manager.run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            self.assertEqual(seen, ["alpha.json", "beta.json"])


if __name__ == "__main__":
    unittest.main()
