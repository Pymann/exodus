import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exodus.models.project import Project, ProjectConfig
from exodus.models.packages import AptPkg, ConanPkg
from exodus.tools.sbom.sbom import SbomTool


class _Args:
    config = "exodus.json"
    action = "manifest"


class SbomToolTests(unittest.TestCase):
    def test_generates_manifest_sbom_in_project_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            project = Project(
                root,
                ProjectConfig(
                    name="demo",
                    version="1.2.3",
                    apt_packages=[
                        AptPkg(
                            name="zlib1g-dev",
                            version="1:1.3.1-1",
                            arch="amd64",
                        )
                    ],
                    conan_packages=[
                        ConanPkg(
                            name="fmt",
                            version="10.2.1",
                            arch="x86_64",
                            user="demo",
                            channel="stable",
                            remote="https://center2.conan.io",
                            settings={
                                "os": "Linux",
                                "compiler": "gcc",
                                "compiler.version": "13",
                                "compiler.cppstd": "gnu20",
                            },
                            options={"shared": "False", "fPIC": "True"},
                        )
                    ],
                ),
            )
            project.save(root)

            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                with patch.object(
                    SbomTool,
                    "_deb_purl_context",
                    return_value=("ubuntu", "noble"),
                ):
                    rc = SbomTool(_Args()).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            sbom_path = root / "out" / "demo" / "manifest.sbom.json"
            self.assertTrue(sbom_path.exists())

            payload = json.loads(sbom_path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["$schema"],
                "https://cyclonedx.org/schema/bom-1.6.schema.json",
            )
            self.assertEqual(payload["bomFormat"], "CycloneDX")
            self.assertEqual(payload["specVersion"], "1.6")
            self.assertEqual(payload["metadata"]["component"]["name"], "demo")
            components = {
                component["name"]: component
                for component in payload["components"]
            }
            self.assertEqual(components["fmt"]["type"], "library")
            self.assertEqual(
                components["fmt"]["purl"],
                "pkg:conan/demo/fmt@10.2.1?arch=x86_64&channel=stable&compiler=gcc&compiler_cppstd=gnu20&compiler_version=13&option_fpic=True&option_shared=False&os=Linux",
            )
            self.assertEqual(
                components["fmt"]["externalReferences"],
                [
                    {
                        "type": "distribution",
                        "url": "https://center2.conan.io",
                        "comment": "Conan remote",
                    }
                ],
            )
            self.assertEqual(
                components["zlib1g-dev"]["purl"],
                "pkg:deb/ubuntu/zlib1g-dev@1%3A1.3.1-1?arch=amd64&distro=noble",
            )

    def test_generates_resolved_sbom_from_cached_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            project = Project(
                root,
                ProjectConfig(
                    name="demo",
                    version="1.2.3",
                    apt_packages=[
                        AptPkg(
                            name="zlib1g-dev",
                            version="1:1.3.1-1",
                            arch="amd64",
                        ),
                        AptPkg(
                            name="zlib1g", version="1:1.3.1-1", arch="amd64"
                        ),
                    ],
                    conan_packages=[
                        ConanPkg(name="fmt", version="10.2.1", arch="x86_64")
                    ],
                ),
            )
            project.save(root)

            apt_root = root / "__exodus_cache" / "apt"
            apt_dev = apt_root / "zlib1g-dev" / "amd64" / "1:1.3.1-1"
            apt_runtime = apt_root / "zlib1g" / "amd64" / "1:1.3.1-1"
            apt_dev.mkdir(parents=True)
            apt_runtime.mkdir(parents=True)
            (apt_dev / "_download").mkdir()
            (apt_runtime / "_download").mkdir()
            (apt_dev / "_download" / "zlib1g-dev.deb").write_text(
                "", encoding="utf-8"
            )
            (apt_runtime / "_download" / "zlib1g.deb").write_text(
                "", encoding="utf-8"
            )
            (apt_dev / "aptpkg.json").write_text(
                json.dumps(
                    {
                        "name": "zlib1g-dev",
                        "arch": "amd64",
                        "version": "1:1.3.1-1",
                        "digest": "devdigest",
                        "depends": ["zlib1g"],
                    }
                ),
                encoding="utf-8",
            )
            (apt_runtime / "aptpkg.json").write_text(
                json.dumps(
                    {
                        "name": "zlib1g",
                        "arch": "amd64",
                        "version": "1:1.3.1-1",
                        "digest": "runtimedigest",
                        "depends": [],
                    }
                ),
                encoding="utf-8",
            )

            conan_root = (
                root / "__exodus_cache" / "conan" / "fmt" / "x86_64" / "10.2.1"
            )
            conan_root.mkdir(parents=True)
            (conan_root / "graph.json").write_text(
                json.dumps(
                    {
                        "graph": {
                            "nodes": {
                                "0": {
                                    "ref": "conanfile",
                                    "dependencies": {
                                        "1": {"ref": "fmt/10.2.1"}
                                    },
                                },
                                "1": {
                                    "ref": "fmt/10.2.1",
                                    "name": "fmt",
                                    "version": "10.2.1",
                                    "package_id": "pkgidfmt",
                                    "settings": {
                                        "arch": "x86_64",
                                        "os": "Linux",
                                    },
                                    "options": {"shared": "False"},
                                    "dependencies": {
                                        "2": {"ref": "zlib/1.3.1"}
                                    },
                                },
                                "2": {
                                    "ref": "zlib/1.3.1",
                                    "name": "zlib",
                                    "version": "1.3.1",
                                    "package_id": "pkgidzlib",
                                    "settings": {
                                        "arch": "x86_64",
                                        "os": "Linux",
                                    },
                                    "options": {},
                                    "dependencies": {},
                                },
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            args = _Args()
            args.action = "resolve"
            old_cwd = Path.cwd()
            try:
                import os

                os.chdir(root)
                with (
                    patch.object(
                        SbomTool,
                        "_deb_purl_context",
                        return_value=("ubuntu", "noble"),
                    ),
                    patch.object(
                        SbomTool,
                        "_dpkg_field",
                        side_effect=lambda path, field: {
                            ("zlib1g-dev.deb", "Homepage"): "https://zlib.net",
                            (
                                "zlib1g-dev.deb",
                                "Description",
                            ): "zlib development files",
                            (
                                "zlib1g-dev.deb",
                                "Maintainer",
                            ): "Ubuntu Developers",
                            ("zlib1g-dev.deb", "Section"): "libdevel",
                            ("zlib1g-dev.deb", "Source"): "zlib",
                            ("zlib1g.deb", "Homepage"): "https://zlib.net",
                            (
                                "zlib1g.deb",
                                "Description",
                            ): "zlib runtime library",
                            ("zlib1g.deb", "Maintainer"): "Ubuntu Developers",
                            ("zlib1g.deb", "Section"): "libs",
                            ("zlib1g.deb", "Source"): "zlib",
                        }.get((Path(path).name, field)),
                    ),
                ):
                    rc = SbomTool(args).run()
            finally:
                os.chdir(old_cwd)

            self.assertEqual(rc, 0)
            sbom_path = root / "out" / "demo" / "resolved.sbom.json"
            self.assertTrue(sbom_path.exists())

            payload = json.loads(sbom_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["specVersion"], "1.6")
            self.assertEqual(
                payload["properties"][-1],
                {"name": "exodus:sbom_kind", "value": "resolved"},
            )
            components = {
                component["name"]: component
                for component in payload["components"]
            }
            self.assertIn("fmt", components)
            self.assertIn("zlib", components)
            self.assertIn("zlib1g-dev", components)
            self.assertEqual(
                components["fmt"]["purl"],
                "pkg:conan/fmt@10.2.1?arch=x86_64&option_shared=False&os=Linux",
            )
            self.assertEqual(
                components["zlib1g-dev"]["hashes"],
                [{"alg": "SHA-256", "content": "devdigest"}],
            )
            self.assertEqual(
                components["zlib1g-dev"]["description"],
                "zlib development files",
            )
            self.assertEqual(
                components["zlib1g-dev"]["publisher"],
                "Ubuntu Developers",
            )
            self.assertEqual(
                components["zlib1g-dev"]["externalReferences"],
                [{"type": "website", "url": "https://zlib.net"}],
            )
            dependency_map = {
                entry["ref"]: entry["dependsOn"]
                for entry in payload["dependencies"]
            }
            self.assertIn("conan:fmt@10.2.1#pkgidfmt", dependency_map)
            self.assertIn("apt:zlib1g-dev@1:1.3.1-1/amd64", dependency_map)
            self.assertEqual(
                dependency_map["conan:fmt@10.2.1#pkgidfmt"],
                ["conan:zlib@1.3.1#pkgidzlib"],
            )
            self.assertEqual(
                dependency_map["apt:zlib1g-dev@1:1.3.1-1/amd64"],
                ["apt:zlib1g@1:1.3.1-1/amd64"],
            )


if __name__ == "__main__":
    unittest.main()
