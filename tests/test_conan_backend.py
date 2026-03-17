import argparse
import json
import tempfile
import unittest
from pathlib import Path

from exodus.core.logger import get_logger
from exodus.tools.pkg.conan_backend import ConanApiCommandRunner, ConanBackend


class ConanApiCommandRunnerTests(unittest.TestCase):
    def test_run_initializes_cli_and_default_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conan_home = Path(tmpdir) / "conan-home"
            cwd = Path(tmpdir)
            runner = ConanApiCommandRunner(get_logger(__name__))

            rc, stdout, stderr = runner.run(
                ["profile", "path", "default"],
                conan_home=conan_home,
                cwd=cwd,
            )

            self.assertEqual(rc, 0, stderr)
            default_profile = conan_home / "profiles" / "default"
            self.assertEqual(stdout.strip(), str(default_profile))
            self.assertTrue(default_profile.exists())

    def test_run_supports_command_formatters(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            conan_home = Path(tmpdir) / "conan-home"
            cwd = Path(tmpdir)
            runner = ConanApiCommandRunner(get_logger(__name__))

            rc, stdout, stderr = runner.run(
                ["profile", "list", "--format=json"],
                conan_home=conan_home,
                cwd=cwd,
            )

            self.assertEqual(rc, 0, stderr)
            profiles = json.loads(stdout)
            self.assertIn("default", profiles)


class ConanBackendJsonExtractionTests(unittest.TestCase):
    def test_extract_paths_from_component_cpp_info(self) -> None:
        args = argparse.Namespace()
        backend = ConanBackend(args)
        package_folder = Path("/tmp/conan-package")
        payload = {
            "graph": {
                "nodes": {
                    "1": {
                        "package_folder": str(package_folder),
                        "cpp_info": {
                            "root": {
                                "includedirs": ["include"],
                                "libdirs": ["lib"],
                            },
                            "_fmt": {
                                "includedirs": ["include"],
                                "libdirs": ["lib64"],
                            },
                        },
                    }
                }
            }
        }

        include_dir = package_folder / "include"
        lib_dir = package_folder / "lib"
        lib64_dir = package_folder / "lib64"

        with tempfile.TemporaryDirectory() as tmpdir:
            real_root = Path(tmpdir)
            include_dir = real_root / "include"
            lib_dir = real_root / "lib"
            lib64_dir = real_root / "lib64"
            include_dir.mkdir()
            lib_dir.mkdir()
            lib64_dir.mkdir()
            payload["graph"]["nodes"]["1"]["package_folder"] = str(real_root)

            include_dirs, lib_dirs = backend._extract_paths_from_json(payload)

        self.assertEqual(include_dirs, [include_dir])
        self.assertEqual(lib_dirs, [lib_dir, lib64_dir])


if __name__ == "__main__":
    unittest.main()
