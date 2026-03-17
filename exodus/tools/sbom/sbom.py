"""Manifest SBOM generation for Exodus projects."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlencode

from exodus.core.logger import get_logger
from exodus.models.project import Project


class SbomTool:
    """Generate a CycloneDX 1.6 manifest SBOM from exodus.json."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    @staticmethod
    def _project_build_root(project: Project) -> Path:
        project_name = (project.config.name or "project").strip() or "project"
        safe_name = "".join(
            ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
            for ch in project_name
        )
        return project.config.build_root / safe_name

    @staticmethod
    def _cache_root(project: Project) -> Path:
        env = os.environ.get("EXODUS_CACHE")
        if env:
            return Path(env).expanduser().resolve()
        return (project.root / "__exodus_cache").resolve()

    @staticmethod
    def _stringify(value: Any) -> Any:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return [SbomTool._stringify(item) for item in value]
        if isinstance(value, dict):
            return {
                str(key): SbomTool._stringify(item)
                for key, item in value.items()
            }
        return value

    @staticmethod
    def _encode_purl_part(value: str) -> str:
        return quote(value, safe=".+-_~")

    @staticmethod
    def _os_release() -> dict[str, str]:
        data: dict[str, str] = {}
        path = Path("/etc/os-release")
        if not path.exists():
            return data
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
        return data

    @classmethod
    def _deb_purl_context(cls) -> tuple[str | None, str | None]:
        os_release = cls._os_release()
        namespace = os_release.get("ID") or None
        distro = (
            os_release.get("VERSION_CODENAME")
            or os_release.get("UBUNTU_CODENAME")
            or os_release.get("VERSION_ID")
            or None
        )
        return namespace, distro

    @classmethod
    def _build_purl(
        cls,
        purl_type: str,
        name: str,
        *,
        version: str | None = None,
        namespace: str | None = None,
        qualifiers: dict[str, str] | None = None,
    ) -> str:
        segments = ["pkg:", purl_type, "/"]
        if namespace:
            ns = "/".join(
                cls._encode_purl_part(part)
                for part in namespace.split("/")
                if part
            )
            if ns:
                segments.extend([ns, "/"])
        segments.append(cls._encode_purl_part(name))
        if version:
            segments.extend(["@", cls._encode_purl_part(version)])
        if qualifiers:
            rendered = urlencode(sorted(qualifiers.items()))
            if rendered:
                segments.extend(["?", rendered])
        return "".join(segments)

    @classmethod
    def _component_purl(
        cls, component_type: str, payload: dict[str, Any]
    ) -> str | None:
        name = payload.get("name")
        version = payload.get("version")
        if not name:
            return None

        if component_type == "apt":
            qualifiers: dict[str, str] = {}
            arch = payload.get("arch")
            if arch:
                qualifiers["arch"] = str(arch)
            namespace, distro = cls._deb_purl_context()
            if distro:
                qualifiers["distro"] = distro
            return cls._build_purl(
                "deb",
                str(name),
                version=str(version) if version else None,
                namespace=namespace,
                qualifiers=qualifiers or None,
            )

        if component_type == "conan":
            qualifiers = {}
            channel = payload.get("channel")
            if channel:
                qualifiers["channel"] = str(channel)
            settings = payload.get("settings") or {}
            for source_key, target_key in (
                ("arch", "arch"),
                ("os", "os"),
                ("build_type", "build_type"),
                ("compiler", "compiler"),
                ("compiler.version", "compiler_version"),
                ("compiler.cppstd", "compiler_cppstd"),
                ("compiler.libcxx", "compiler_libcxx"),
            ):
                value = settings.get(source_key)
                if value is not None:
                    qualifiers[target_key] = str(value)
            if "arch" not in qualifiers and payload.get("arch") is not None:
                qualifiers["arch"] = str(payload["arch"])
            options = payload.get("options") or {}
            for source_key, target_key in (
                ("shared", "option_shared"),
                ("fPIC", "option_fpic"),
            ):
                value = options.get(source_key)
                if value is not None:
                    qualifiers[target_key] = str(value)
            namespace = payload.get("user")
            return cls._build_purl(
                "conan",
                str(name),
                version=str(version) if version else None,
                namespace=str(namespace) if namespace else None,
                qualifiers=qualifiers or None,
            )

        return cls._build_purl(
            "generic",
            str(name),
            version=str(version) if version else None,
        )

    @staticmethod
    def _conan_remote_reference(
        remote: str | None,
    ) -> tuple[str | None, str | None]:
        if not remote:
            return None, None
        if remote.startswith(("http://", "https://")):
            return None, remote
        return remote, None

    def _component_external_references(
        self, component_type: str, payload: dict[str, Any]
    ) -> list[dict[str, str]]:
        references: list[dict[str, str]] = []
        if component_type == "conan":
            _, remote_url = self._conan_remote_reference(
                str(payload.get("remote")) if payload.get("remote") else None
            )
            if remote_url:
                references.append(
                    {
                        "type": "distribution",
                        "url": remote_url,
                        "comment": "Conan remote",
                    }
                )
        return references

    @staticmethod
    def _apt_cache_dir(
        project: Project, name: str, arch: str, version: str
    ) -> Path:
        return SbomTool._cache_root(project) / "apt" / name / arch / version

    @staticmethod
    def _conan_cache_dir(
        project: Project, name: str, arch: str, version: str
    ) -> Path:
        return SbomTool._cache_root(project) / "conan" / name / arch / version

    @staticmethod
    def _component_properties(
        component: dict[str, Any],
    ) -> list[dict[str, str]]:
        props = component.get("properties")
        if isinstance(props, list):
            return cast(list[dict[str, str]], props)
        new_props: list[dict[str, str]] = []
        component["properties"] = new_props
        return new_props

    @staticmethod
    def _component_external_refs(
        component: dict[str, Any],
    ) -> list[dict[str, str]]:
        refs = component.get("externalReferences")
        if isinstance(refs, list):
            return cast(list[dict[str, str]], refs)
        new_refs: list[dict[str, str]] = []
        component["externalReferences"] = new_refs
        return new_refs

    def _component_from_dependency(
        self, dependency: Any, component_type: str
    ) -> dict[str, Any]:
        payload = dependency.model_dump(mode="python")
        payload = self._stringify(payload)
        bom_ref = f"{component_type}:{payload.get('name', 'unknown')}"
        version = payload.get("version")
        if version:
            bom_ref = f"{bom_ref}@{version}"
        arch = payload.get("arch")
        if arch:
            bom_ref = f"{bom_ref}/{arch}"
        properties = [
            {
                "name": f"exodus:{key}",
                "value": (
                    json.dumps(value)
                    if isinstance(value, (dict, list))
                    else str(value)
                ),
            }
            for key, value in payload.items()
            if value is not None
        ]
        component = {
            "bom_ref": bom_ref,
            "type": "library",
            "name": payload.get("name"),
            "version": version,
            "properties": properties,
        }
        if payload.get("required") is not None:
            component["scope"] = (
                "required" if bool(payload["required"]) else "optional"
            )
        if component_type == "conan":
            remote_name, _ = self._conan_remote_reference(
                str(payload.get("remote")) if payload.get("remote") else None
            )
            if remote_name:
                self._component_properties(component).append(
                    {"name": "exodus:repository_name", "value": remote_name}
                )
        purl = self._component_purl(component_type, payload)
        if purl:
            component["purl"] = purl
        external_references = self._component_external_references(
            component_type, payload
        )
        if external_references:
            component["externalReferences"] = external_references
        return component

    def _base_document(
        self, project: Project, config_name: str
    ) -> tuple[str, dict[str, Any]]:
        project_ref = f"project:{project.config.name}@{project.config.version}"
        document = {
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "exodus",
                            "version": "0.1.0",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "bom-ref": project_ref,
                    "name": project.config.name,
                    "version": project.config.version,
                    "properties": [
                        {"name": "exodus:config_file", "value": config_name},
                        {
                            "name": "exodus:output_type",
                            "value": project.config.output_type,
                        },
                        {"name": "exodus:root", "value": str(project.root)},
                    ]
                    + [
                        {"name": "exodus:license", "value": license_name}
                        for license_name in project.config.license
                    ],
                },
                "lifecycles": [{"phase": "build"}],
            },
            "properties": [
                {
                    "name": "exodus:toolchain:architecture",
                    "value": json.dumps(
                        self._stringify(
                            project.config.architecture.model_dump(
                                mode="python"
                            )
                        ),
                        sort_keys=True,
                    ),
                },
                {
                    "name": "exodus:toolchain:compiler",
                    "value": json.dumps(
                        self._stringify(
                            project.config.compiler.model_dump(mode="python")
                        ),
                        sort_keys=True,
                    ),
                },
                {
                    "name": "exodus:toolchain:linker",
                    "value": json.dumps(
                        self._stringify(
                            project.config.linker.model_dump(mode="python")
                        ),
                        sort_keys=True,
                    ),
                },
                {
                    "name": "exodus:search_paths",
                    "value": json.dumps(
                        self._stringify(project.config.search_paths),
                        sort_keys=True,
                    ),
                },
                {
                    "name": "exodus:sources",
                    "value": json.dumps(list(project.config.sources)),
                },
                {
                    "name": "exodus:defines",
                    "value": json.dumps(
                        self._stringify(project.config.defines),
                        sort_keys=True,
                    ),
                },
            ],
        }
        return project_ref, document

    def _document(self, project: Project, config_name: str) -> dict[str, Any]:
        project_ref, document = self._base_document(project, config_name)
        components: list[dict[str, Any]] = []
        dependencies: list[dict[str, Any]] = [
            {"ref": project_ref, "dependsOn": []}
        ]

        for dependency in project.config.dependencies:
            component = self._component_from_dependency(
                dependency, "dependency"
            )
            components.append(component)
            dependencies[0]["dependsOn"].append(component["bom_ref"])

        for apt_package in project.config.apt_packages:
            component = self._component_from_dependency(apt_package, "apt")
            components.append(component)
            dependencies[0]["dependsOn"].append(component["bom_ref"])

        for conan_package in project.config.conan_packages:
            component = self._component_from_dependency(conan_package, "conan")
            self._component_properties(component).append(
                {
                    "name": "exodus:reference",
                    "value": conan_package.reference(),
                }
            )
            components.append(component)
            dependencies[0]["dependsOn"].append(component["bom_ref"])

        document["components"] = components
        document["dependencies"] = dependencies
        document["properties"].append(
            {"name": "exodus:sbom_kind", "value": "manifest"}
        )
        return document

    @staticmethod
    def _dpkg_field(deb_path: Path, field: str) -> str | None:
        proc = subprocess.run(
            ["dpkg-deb", "--field", str(deb_path), field],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return proc.stdout.strip()

    @staticmethod
    def _parse_apt_dep_names(depends_field: str | None) -> list[str]:
        if not depends_field:
            return []
        names: list[str] = []
        for group in depends_field.split(","):
            first_alt = group.split("|")[0].strip()
            first_alt = first_alt.split(":")[0].strip()
            token = first_alt.split(" ", 1)[0].strip()
            if token:
                names.append(token.lower())
        return names

    def _resolved_apt(
        self, project: Project
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        components: list[dict[str, Any]] = []
        dependencies: list[dict[str, Any]] = []
        by_name: dict[str, str] = {}

        for package in project.config.apt_packages:
            cache_dir = self._apt_cache_dir(
                project, package.name, package.arch, package.version
            )
            manifest_path = cache_dir / "aptpkg.json"
            manifest: dict[str, Any] = {}
            if manifest_path.exists():
                raw_manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
                if isinstance(raw_manifest, dict):
                    manifest = cast(dict[str, Any], raw_manifest)
            component = self._component_from_dependency(package, "apt")
            bom_ref = component["bom_ref"]
            by_name[package.name.lower()] = bom_ref

            digest = manifest.get("digest")
            if isinstance(digest, str) and digest:
                component["hashes"] = [{"alg": "SHA-256", "content": digest}]
                self._component_properties(component).append(
                    {"name": "exodus:digest", "value": digest}
                )

            debs = sorted((cache_dir / "_download").glob("*.deb"))
            if debs:
                homepage = self._dpkg_field(debs[0], "Homepage")
                description = self._dpkg_field(debs[0], "Description")
                maintainer = self._dpkg_field(debs[0], "Maintainer")
                section = self._dpkg_field(debs[0], "Section")
                source = self._dpkg_field(debs[0], "Source")
                if homepage:
                    self._component_external_refs(component).append(
                        {"type": "website", "url": homepage}
                    )
                if description:
                    component["description"] = description.splitlines()[0]
                if maintainer:
                    component["publisher"] = maintainer
                if section:
                    self._component_properties(component).append(
                        {"name": "exodus:section", "value": section}
                    )
                if source:
                    self._component_properties(component).append(
                        {"name": "exodus:source_package", "value": source}
                    )
            components.append(component)

            raw_depends = manifest.get("depends")
            depends: list[Any] = (
                raw_depends if isinstance(raw_depends, list) else []
            )
            dependencies.append(
                {
                    "ref": bom_ref,
                    "dependsOn": [],
                    "_apt_dep_names": [str(dep).lower() for dep in depends],
                }
            )

        for dep_entry in dependencies:
            names = dep_entry.pop("_apt_dep_names", [])
            dep_entry["dependsOn"] = [
                by_name[name] for name in names if name in by_name
            ]

        return components, dependencies

    def _resolved_conan(
        self, project: Project
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        components: dict[str, dict[str, Any]] = {}
        dependencies: dict[str, list[str]] = {}
        root_depends: list[str] = []

        for package in project.config.conan_packages:
            cache_dir = self._conan_cache_dir(
                project, package.name, package.arch, package.version
            )
            graph_path = cache_dir / "graph.json"
            if not graph_path.exists():
                continue
            raw_payload = json.loads(graph_path.read_text(encoding="utf-8"))
            payload = (
                cast(dict[str, Any], raw_payload)
                if isinstance(raw_payload, dict)
                else {}
            )
            graph = payload.get("graph") if isinstance(payload, dict) else {}
            nodes = graph.get("nodes") if isinstance(graph, dict) else {}
            if not isinstance(nodes, dict):
                continue

            root_id = None
            for node_id, node in nodes.items():
                if isinstance(node, dict) and node.get("ref") == "conanfile":
                    root_id = node_id
                    break

            node_ref_map: dict[str, str] = {}
            for node_id, node in nodes.items():
                if not isinstance(node, dict):
                    continue
                ref = node.get("ref")
                if not ref or ref == "conanfile":
                    continue
                name = node.get("name") or str(ref).split("/", 1)[0]
                version = node.get("version")
                package_id = node.get("package_id")
                bom_ref = f"conan:{name}"
                if version:
                    bom_ref += f"@{version}"
                if package_id:
                    bom_ref += f"#{package_id}"
                node_ref_map[node_id] = bom_ref
                if bom_ref in components:
                    continue

                component = {
                    "bom_ref": bom_ref,
                    "type": "library",
                    "name": name,
                    "version": version,
                    "purl": self._component_purl(
                        "conan",
                        {
                            "name": name,
                            "version": version,
                            "user": node.get("user"),
                            "channel": node.get("channel"),
                            "arch": (node.get("settings") or {}).get("arch"),
                            "settings": node.get("settings") or {},
                            "options": node.get("options") or {},
                            "remote": node.get("remote"),
                        },
                    ),
                    "properties": [
                        {"name": "exodus:reference", "value": str(ref)},
                        {
                            "name": "exodus:package_id",
                            "value": str(package_id),
                        },
                    ],
                }
                remote = node.get("remote")
                if remote:
                    remote_name, remote_url = self._conan_remote_reference(
                        str(remote)
                    )
                    if remote_name:
                        self._component_properties(component).append(
                            {
                                "name": "exodus:repository_name",
                                "value": remote_name,
                            }
                        )
                    if remote_url:
                        component["externalReferences"] = [
                            {
                                "type": "distribution",
                                "url": remote_url,
                                "comment": "Conan remote",
                            }
                        ]
                package_folder = node.get("package_folder")
                if package_folder:
                    self._component_properties(component).append(
                        {
                            "name": "exodus:package_folder",
                            "value": str(package_folder),
                        }
                    )
                components[bom_ref] = component

            for node_id, node in nodes.items():
                if not isinstance(node, dict) or node_id not in node_ref_map:
                    continue
                current_ref = node_ref_map[node_id]
                dep_ids: list[str] = []
                node_deps = node.get("dependencies")
                if isinstance(node_deps, dict):
                    dep_ids = [
                        dep_id
                        for dep_id in node_deps.keys()
                        if dep_id in node_ref_map
                    ]
                dependencies[current_ref] = [
                    node_ref_map[dep_id] for dep_id in dep_ids
                ]

            if root_id is not None:
                root_node = nodes.get(root_id)
                if isinstance(root_node, dict):
                    root_deps = root_node.get("dependencies")
                    if isinstance(root_deps, dict):
                        for dep_id in root_deps.keys():
                            if (
                                dep_id in node_ref_map
                                and node_ref_map[dep_id] not in root_depends
                            ):
                                root_depends.append(node_ref_map[dep_id])

        dep_entries = [
            {"ref": ref, "dependsOn": sorted(dep_refs)}
            for ref, dep_refs in sorted(dependencies.items())
        ]
        return list(components.values()), dep_entries, root_depends

    def _resolved_document(
        self, project: Project, config_name: str
    ) -> dict[str, Any]:
        project_ref, document = self._base_document(project, config_name)
        root_depends: list[str] = []

        apt_components, apt_dependencies = self._resolved_apt(project)
        conan_components, conan_dependencies, conan_root_depends = (
            self._resolved_conan(project)
        )

        root_depends.extend(
            component["bom_ref"] for component in apt_components
        )
        root_depends.extend(conan_root_depends)

        document["components"] = apt_components + conan_components
        document["dependencies"] = [
            {"ref": project_ref, "dependsOn": sorted(set(root_depends))}
        ]
        document["dependencies"].extend(apt_dependencies)
        document["dependencies"].extend(conan_dependencies)
        document["properties"].append(
            {"name": "exodus:sbom_kind", "value": "resolved"}
        )
        return document

    def run(self) -> int:
        if getattr(self.args, "all", False):
            config_names = Project.discover_config_names(Path.cwd())
            if not config_names:
                self.logger.error(
                    "No Exodus project config JSON files found in %s.",
                    Path.cwd(),
                )
                return 1

            failures = 0
            for config_name in config_names:
                self.logger.info(
                    "generating %s SBOM for %s",
                    getattr(self.args, "action", "manifest"),
                    config_name,
                )
                rc = self._run_config(config_name)
                if rc != 0:
                    failures += 1
            if failures:
                self.logger.error(
                    "SBOM generation finished with %d failing config(s).",
                    failures,
                )
                return 1
            return 0

        config_name = (
            getattr(self.args, "config", "exodus.json") or "exodus.json"
        )
        return self._run_config(config_name)

    def _run_config(self, config_name: str) -> int:
        project = Project.load(Path.cwd(), config_name=config_name)
        output_dir = self._project_build_root(project)
        output_dir.mkdir(parents=True, exist_ok=True)
        action = getattr(self.args, "action", "manifest") or "manifest"
        if action == "resolve":
            output_file = output_dir / "resolved.sbom.json"
            document = self._resolved_document(project, config_name)
        else:
            output_file = output_dir / "manifest.sbom.json"
            document = self._document(project, config_name)
        output_file.write_text(
            json.dumps(document, indent=4), encoding="utf-8"
        )
        self.logger.info("wrote %s SBOM to %s", action, output_file)
        return 0
