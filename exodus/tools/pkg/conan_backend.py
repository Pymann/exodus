"""Conan 2 backend for Exodus package management."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, Iterator, List, Optional, Tuple

from exodus.core.logger import get_logger
from exodus.models.packages import ConanPkg
from exodus.models.project import Project


class ConanApiCommandRunner:
    """Execute Conan commands in-process via Conan Python API classes."""

    def __init__(self, logger: Any) -> None:
        self.logger = logger

    @staticmethod
    @contextmanager
    def _temporary_env(overrides: dict[str, str]) -> Iterator[None]:
        old_values: dict[str, Optional[str]] = {}
        try:
            for key, value in overrides.items():
                old_values[key] = os.environ.get(key)
                os.environ[key] = value
            yield
        finally:
            for key, old in old_values.items():
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old

    def _new_api(self, cache_folder: Path) -> Any:
        try:
            from conan.api.conan_api import ConanAPI  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                "Conan Python API is not available. Install conan>=2 in the active environment."
            ) from exc

        # Conan API changed initialization details across 2.x.
        # Prefer factory() when present, otherwise instantiate directly.
        factory = getattr(ConanAPI, "factory", None)
        if callable(factory):
            built = factory(str(cache_folder))
            if isinstance(built, tuple):
                return built[0]
            return built
        return ConanAPI(str(cache_folder))

    def _ensure_default_profile(
        self,
        *,
        conan_home: Path,
        cwd: Path,
    ) -> Tuple[int, str, str]:
        default_profile = conan_home / "profiles" / "default"
        if default_profile.exists():
            return 0, "", ""
        try:
            conan_api = self._new_api(conan_home)
            detected_profile = conan_api.profiles.detect()
            profile_path = Path(
                conan_api.profiles.get_path("default", str(cwd), exists=False)
            )
            profile_path.parent.mkdir(parents=True, exist_ok=True)
            profile_path.write_text(detected_profile.dumps(), encoding="utf-8")
            return 0, detected_profile.dumps(), ""
        except Exception as exc:
            return 1, "", str(exc)

    def _run_with_command_api(
        self, conan_api: Any, args: List[str]
    ) -> Tuple[str, str]:
        from conan.api.output import ConanOutput  # type: ignore
        from conan.cli.cli import Cli  # type: ignore

        cli = Cli(conan_api)
        cli.add_commands()
        cmd_api = getattr(conan_api, "command", None)
        if cmd_api is None:
            raise RuntimeError("ConanAPI.command subapi not available.")

        if not args:
            raise RuntimeError("No Conan command provided.")
        current_cmd = args[0]
        try:
            command = cli._commands[current_cmd]
        except KeyError as exc:
            raise RuntimeError(
                f"Command {current_cmd} does not exist."
            ) from exc

        stdout = StringIO()
        stderr = StringIO()
        _conan_output_level = ConanOutput._conan_output_level
        _silent_warn_tags = ConanOutput._silent_warn_tags
        _warnings_as_errors = ConanOutput._warnings_as_errors
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = command.run(conan_api, args[1:])
            finally:
                ConanOutput._conan_output_level = _conan_output_level
                ConanOutput._silent_warn_tags = _silent_warn_tags
                ConanOutput._warnings_as_errors = _warnings_as_errors
        if (
            isinstance(result, str)
            and result.strip()
            and not stdout.getvalue().strip()
        ):
            stdout.write(result)
        return stdout.getvalue(), stderr.getvalue()

    def run(
        self, args: List[str], *, conan_home: Path, cwd: Path
    ) -> Tuple[int, str, str]:
        profile_rc, profile_stdout, profile_stderr = (
            self._ensure_default_profile(
                conan_home=conan_home,
                cwd=cwd,
            )
        )
        if profile_rc != 0:
            return profile_rc, profile_stdout, profile_stderr

        with self._temporary_env({"CONAN_HOME": str(conan_home)}):
            old_cwd = Path.cwd()
            try:
                os.chdir(cwd)
                conan_api = self._new_api(conan_home)
                stdout, stderr = self._run_with_command_api(conan_api, args)
                return 0, stdout, stderr
            except Exception as exc:
                return 1, "", str(exc)
            finally:
                os.chdir(old_cwd)


class ConanBackend:
    """Handle Conan package operations without mixing APT-specific logic."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)
        self.command_runner = ConanApiCommandRunner(self.logger)

    def _cache_root(self) -> Path:
        env = os.environ.get("EXODUS_CACHE")
        if env:
            root = Path(env).expanduser().resolve()
        else:
            root = (Path.cwd() / "__exodus_cache").resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _pkg_cache_dir(self, pkg: ConanPkg) -> Path:
        return self._cache_root() / "conan" / pkg.name / pkg.arch / pkg.version

    @staticmethod
    def _to_relative(project_root: Path, path: Path) -> Path:
        return Path(os.path.relpath(path, project_root))

    @staticmethod
    def _append_project_path(paths: List[Path], candidate: Path) -> bool:
        if not candidate.exists():
            return False
        if candidate not in paths:
            paths.append(candidate)
            return True
        return False

    @staticmethod
    def _json_digest(payload: object) -> str:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _find_pkg_index(
        project: Project,
        name: str,
        arch: str,
        version: str,
    ) -> Optional[int]:
        lname = name.lower()
        larch = arch.lower()
        for idx, pkg in enumerate(project.config.conan_packages):
            if (
                pkg.name.lower() == lname
                and pkg.arch.lower() == larch
                and pkg.version == version
            ):
                return idx
        return None

    def add(self, project: Project, config_name: str = "exodus.json") -> int:
        pkg = ConanPkg(
            name=self.args.name.strip(),
            arch=self.args.arch.strip(),
            version=self.args.version.strip(),
            user=(self.args.user.strip() if self.args.user else None),
            channel=(self.args.channel.strip() if self.args.channel else None),
            profile=(self.args.profile.strip() if self.args.profile else None),
            build_profile=(
                self.args.build_profile.strip()
                if self.args.build_profile
                else None
            ),
            remote=(self.args.remote.strip() if self.args.remote else None),
        )

        idx = self._find_pkg_index(project, pkg.name, pkg.arch, pkg.version)
        if idx is not None:
            self.logger.error(
                "Conan package '%s/%s/%s' already exists.",
                pkg.name,
                pkg.arch,
                pkg.version,
            )
            return 1

        project.config.conan_packages.append(pkg)
        project.save(project.root, config_name=config_name)
        self.logger.info(
            "Added Conan package '%s' arch='%s' version='%s'.",
            pkg.name,
            pkg.arch,
            pkg.version,
        )
        return 0

    def remove(
        self, project: Project, config_name: str = "exodus.json"
    ) -> int:
        name = self.args.name.strip().lower()
        arch = self.args.arch.strip().lower() if self.args.arch else None
        version = self.args.version.strip() if self.args.version else None

        before = len(project.config.conan_packages)
        filtered = []
        for pkg in project.config.conan_packages:
            match = pkg.name.lower() == name
            if arch is not None:
                match = match and pkg.arch.lower() == arch
            if version is not None:
                match = match and pkg.version == version
            if not match:
                filtered.append(pkg)

        removed = before - len(filtered)
        if removed <= 0:
            self.logger.error("No matching conan package found for removal.")
            return 1

        project.config.conan_packages = filtered
        project.save(project.root, config_name=config_name)
        self.logger.info("Removed %d conan package entr(y/ies).", removed)
        return 0

    def _build_conan_args(self, pkg: ConanPkg, install_dir: Path) -> List[str]:
        args: List[str] = [
            "install",
            f"--requires={pkg.reference()}",
            "--output-folder",
            str(install_dir),
            "--build",
            getattr(self.args, "build", "missing"),
            "--format=json",
            "-s",
            f"arch={pkg.arch}",
            "-s",
            "build_type=Release",
        ]
        if pkg.profile:
            args.extend(["-pr:h", pkg.profile])
        if pkg.build_profile:
            args.extend(["-pr:b", pkg.build_profile])
        if pkg.remote:
            args.extend(["-r", pkg.remote])
        for key, value in pkg.settings.items():
            args.extend(["-s", f"{key}={value}"])
        for key, value in pkg.options.items():
            args.extend(["-o", f"{key}={value}"])
        return args

    def _extract_paths_from_json(
        self,
        payload: dict[str, Any],
    ) -> Tuple[List[Path], List[Path]]:
        include_dirs: List[Path] = []
        lib_dirs: List[Path] = []
        seen_inc: set[Path] = set()
        seen_lib: set[Path] = set()

        graph = payload.get("graph") if isinstance(payload, dict) else None
        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        iter_nodes = nodes.values() if isinstance(nodes, dict) else []

        for node in iter_nodes:
            if not isinstance(node, dict):
                continue
            package_folder_raw = node.get("package_folder")
            base = Path(package_folder_raw) if package_folder_raw else None
            raw_cpp_info = node.get("cpp_info")
            cpp_info: dict[str, Any]
            if isinstance(raw_cpp_info, dict):
                cpp_info = raw_cpp_info
            else:
                cpp_info = {}

            for component in cpp_info.values():
                if not isinstance(component, dict):
                    continue

                for rel_inc in component.get("includedirs", []) or []:
                    p = Path(rel_inc)
                    if not p.is_absolute() and base is not None:
                        p = (base / p).resolve()
                    if p.exists() and p not in seen_inc:
                        seen_inc.add(p)
                        include_dirs.append(p)

                for rel_lib in component.get("libdirs", []) or []:
                    p = Path(rel_lib)
                    if not p.is_absolute() and base is not None:
                        p = (base / p).resolve()
                    if p.exists() and p not in seen_lib:
                        seen_lib.add(p)
                        lib_dirs.append(p)

        return sorted(include_dirs), sorted(lib_dirs)

    def _scan_install_dir_fallback(
        self,
        install_dir: Path,
    ) -> Tuple[List[Path], List[Path]]:
        include_dirs: List[Path] = []
        lib_dirs: List[Path] = []
        seen_inc: set[Path] = set()
        seen_lib: set[Path] = set()

        for path in install_dir.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in {".h", ".hpp", ".hh", ".hxx"}:
                for parent in path.parents:
                    if parent.name == "include":
                        if parent not in seen_inc:
                            seen_inc.add(parent)
                            include_dirs.append(parent)
                        break
            name = path.name
            if name.startswith("lib") and (".so" in name or suffix == ".a"):
                for parent in path.parents:
                    if parent.name in {"lib", "lib64"}:
                        if parent not in seen_lib:
                            seen_lib.add(parent)
                            lib_dirs.append(parent)
                        break

        return sorted(include_dirs), sorted(lib_dirs)

    def _install_one(self, project: Project, pkg: ConanPkg) -> int:
        cache_dir = self._pkg_cache_dir(pkg)
        install_dir = cache_dir / "install"
        force = bool(getattr(self.args, "force", False))

        if cache_dir.exists() and force:
            self.logger.info(
                "Force reinstall requested, removing %s", cache_dir
            )
            shutil.rmtree(cache_dir)

        cache_dir.mkdir(parents=True, exist_ok=True)
        install_dir.mkdir(parents=True, exist_ok=True)

        conan_home = cache_dir / "conan_home"
        conan_home.mkdir(parents=True, exist_ok=True)

        args = self._build_conan_args(pkg, install_dir)
        rc, stdout, stderr = self.command_runner.run(
            args,
            conan_home=conan_home,
            cwd=project.root,
        )
        if rc != 0:
            self.logger.error("Conan install failed for %s", pkg.reference())
            if stderr.strip():
                self.logger.error(stderr.strip())
            return 1

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError:
            self.logger.error(
                "Conan returned non-JSON output for %s", pkg.reference()
            )
            if stderr.strip():
                self.logger.error(stderr.strip())
            return 1

        include_dirs, lib_dirs = self._extract_paths_from_json(result)
        if not include_dirs and not lib_dirs:
            include_dirs, lib_dirs = self._scan_install_dir_fallback(
                install_dir
            )

        added_inc = 0
        added_lib = 0
        for inc in include_dirs:
            rel_inc = self._to_relative(project.root, inc)
            if self._append_project_path(project.config.search_paths, rel_inc):
                added_inc += 1
        for lib in lib_dirs:
            rel_lib = self._to_relative(project.root, lib)
            if self._append_project_path(
                project.config.linker.library_paths, rel_lib
            ):
                added_lib += 1

        pkg.digest = self._json_digest(result)
        (cache_dir / "graph.json").write_text(
            json.dumps(result, indent=2),
            encoding="utf-8",
        )
        (cache_dir / "conanpkg.json").write_text(
            json.dumps(
                {
                    "reference": pkg.reference(),
                    "arch": pkg.arch,
                    "digest": pkg.digest,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        self.logger.info(
            "Installed Conan %s -> %s (search_paths +%d, linker.library_paths +%d)",
            pkg.reference(),
            cache_dir,
            added_inc,
            added_lib,
        )
        return 0

    def install(
        self, project: Project, config_name: str = "exodus.json"
    ) -> int:
        pkgs = project.config.conan_packages
        if not pkgs:
            self.logger.info("No conan packages configured.")
            return 0

        selected: List[ConanPkg] = []
        if self.args.name:
            wanted_name = self.args.name.strip().lower()
            wanted_arch = (
                self.args.arch.strip().lower() if self.args.arch else None
            )
            wanted_version = (
                self.args.version.strip() if self.args.version else None
            )
            for pkg in pkgs:
                if pkg.name.lower() != wanted_name:
                    continue
                if wanted_arch and pkg.arch.lower() != wanted_arch:
                    continue
                if wanted_version and pkg.version != wanted_version:
                    continue
                selected.append(pkg)
        else:
            selected = list(pkgs)

        if not selected:
            self.logger.error(
                "No matching conan package entries selected for install."
            )
            return 1

        failures = 0
        for pkg in selected:
            rc = self._install_one(project, pkg)
            if rc != 0:
                failures += 1

        project.save(project.root, config_name=config_name)
        if failures:
            self.logger.error(
                "Conan installation finished with %d failure(s).", failures
            )
            return 1
        self.logger.info("Conan installation finished successfully.")
        return 0

    def install_standalone(self) -> int:
        pkg = ConanPkg(
            name=self.args.name.strip(),
            version=self.args.version.strip(),
            arch=self.args.arch.strip(),
            user=(self.args.user.strip() if self.args.user else None),
            channel=(self.args.channel.strip() if self.args.channel else None),
            profile=(self.args.profile.strip() if self.args.profile else None),
            build_profile=(
                self.args.build_profile.strip()
                if self.args.build_profile
                else None
            ),
            remote=(self.args.remote.strip() if self.args.remote else None),
        )

        fake_project = Project.load(Path.cwd())
        rc = self._install_one(fake_project, pkg)
        if rc != 0:
            return rc

        self.logger.info(
            "Standalone conan package ready: %s", self._pkg_cache_dir(pkg)
        )
        return 0
