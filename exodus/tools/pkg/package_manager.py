"""Package manager tool implementation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import os.path
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from exodus.core.logger import get_logger
from exodus.models.packages import AptPkg
from exodus.models.project import Project
from exodus.tools.pkg.conan_backend import ConanBackend

# Matches directory names that end with an optional dash and a version number,
# e.g. "llvm-18", "clang-18", "llvm-c-18".  These are versioned include
# sub-directories that Ubuntu/Debian packages install under usr/include/ and
# that must be placed on the compiler's include search path individually
# (rather than their parent usr/include/ directory).
_VERSIONED_SUBDIR_RE = re.compile(r"-\d+$")

# Matches GNU multiarch triplet directory names such as "x86_64-linux-gnu",
# "aarch64-linux-gnu", "arm-linux-gnueabihf", etc.  Debian/Ubuntu packages
# install their libraries under usr/lib/<triplet>/ rather than directly under
# usr/lib/, so the triplet sub-directory must be placed on the linker's search
# path instead of the bare "lib" root.
_MULTIARCH_SUBDIR_RE = re.compile(r"^[a-z0-9_]+-[a-z]+-[a-z0-9_]+$")

# Matches the package name at the start of a Depends entry, e.g.:
#   "libassimp5 (>= 5.2)"  →  "libassimp5"
#   "libgcc1 (>= 1:3.0) | libgcc-s1"  →  "libgcc1"
#   "python3:any"  →  "python3"
_DEP_NAME_RE = re.compile(r"^([a-z0-9][a-z0-9.+\-]*)", re.IGNORECASE)

# These fundamental packages are always present on any Linux system.
# Adding them to the cache would shadow system libraries unnecessarily.
_SKIP_AUTO_DEP_NAMES: frozenset[str] = frozenset(
    {
        "libc6",
        "libgcc-s1",
        "libgcc1",
        "libstdc++6",
        "libm6",
        "multiarch-support",
        "gcc-12-base",
        "gcc-13-base",
        "gcc-14-base",
        "libc-bin",
    }
)


class PackageManager:
    """Manage APT package entries and cache installation artifacts."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)
        self.conan = ConanBackend(args)

    def _load_project(self, config_name: str = "exodus.json") -> Project:
        return Project.load(Path.cwd(), config_name=config_name)

    def _cache_root(self) -> Path:
        env = os.environ.get("EXODUS_CACHE")
        if env:
            root = Path(env).expanduser().resolve()
        else:
            root = (Path.cwd() / "__exodus_cache").resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _pkg_cache_dir(self, pkg: AptPkg) -> Path:
        return self._cache_root() / "apt" / pkg.name / pkg.arch / pkg.version

    def _pkg_cache_dir_values(
        self, name: str, arch: str, version: str
    ) -> Path:
        return self._cache_root() / "apt" / name / arch / version

    @staticmethod
    def _append_unique_path(paths: List[Path], candidate: Path) -> None:
        if candidate not in paths:
            paths.append(candidate)

    @staticmethod
    def _append_project_path(paths: List[Path], candidate: Path) -> bool:
        if not candidate.exists():
            return False
        if candidate not in paths:
            paths.append(candidate)
            return True
        return False

    @staticmethod
    def _to_relative(project_root: Path, path: Path) -> Path:
        return Path(os.path.relpath(path, project_root))

    def _find_pkg_index(
        self, project: Project, name: str, arch: str, version: str
    ) -> Optional[int]:
        lname = name.lower()
        larch = arch.lower()
        for idx, pkg in enumerate(project.config.apt_packages):
            if (
                pkg.name.lower() == lname
                and pkg.arch.lower() == larch
                and pkg.version == version
            ):
                return idx
        return None

    def _list(self, project: Project) -> int:
        pkg_type = getattr(self.args, "type", "all")
        apt_pkgs = (
            project.config.apt_packages if pkg_type in {"all", "apt"} else []
        )
        conan_pkgs = (
            project.config.conan_packages
            if pkg_type in {"all", "conan"}
            else []
        )
        if getattr(self.args, "json", False):
            payload = {
                "apt": [pkg.model_dump(mode="json") for pkg in apt_pkgs],
                "conan": [pkg.model_dump(mode="json") for pkg in conan_pkgs],
            }
            print(json.dumps(payload, indent=2))
            return 0

        if not apt_pkgs and not conan_pkgs:
            self.logger.info("No packages configured.")
            return 0

        if apt_pkgs:
            self.logger.info("Configured apt packages (%d):", len(apt_pkgs))
            for pkg in apt_pkgs:
                digest = pkg.digest if pkg.digest else "-"
                print(f"apt\t{pkg.name}\t{pkg.arch}\t{pkg.version}\t{digest}")
        if conan_pkgs:
            self.logger.info(
                "Configured conan packages (%d):", len(conan_pkgs)
            )
            for conan_pkg in conan_pkgs:
                digest = conan_pkg.digest if conan_pkg.digest else "-"
                print(
                    f"conan\t{conan_pkg.name}\t{conan_pkg.arch}\t"
                    f"{conan_pkg.version}\t{digest}"
                )
        return 0

    def _add(self, project: Project, config_name: str = "exodus.json") -> int:
        pkg = AptPkg(
            name=self.args.name.strip(),
            arch=self.args.arch.strip(),
            version=self.args.version.strip(),
        )

        if not pkg.name or not pkg.arch or not pkg.version:
            self.logger.error("name, arch and version are required.")
            return 1

        idx = self._find_pkg_index(project, pkg.name, pkg.arch, pkg.version)
        if idx is not None:
            self.logger.error(
                "APT package '%s/%s/%s' already exists.",
                pkg.name,
                pkg.arch,
                pkg.version,
            )
            return 1

        project.config.apt_packages.append(pkg)
        project.save(project.root, config_name=config_name)
        self.logger.info(
            "Added apt package '%s' arch='%s' version='%s'.",
            pkg.name,
            pkg.arch,
            pkg.version,
        )
        return 0

    def _remove(
        self, project: Project, config_name: str = "exodus.json"
    ) -> int:
        name = self.args.name.strip().lower()
        arch = self.args.arch.strip().lower() if self.args.arch else None
        version = self.args.version.strip() if self.args.version else None

        before = len(project.config.apt_packages)
        filtered = []
        for pkg in project.config.apt_packages:
            match = pkg.name.lower() == name
            if arch is not None:
                match = match and pkg.arch.lower() == arch
            if version is not None:
                match = match and pkg.version == version
            if not match:
                filtered.append(pkg)

        removed = before - len(filtered)
        if removed <= 0:
            self.logger.error("No matching apt package found for removal.")
            return 1

        project.config.apt_packages = filtered
        project.save(project.root, config_name=config_name)
        self.logger.info("Removed %d apt package entr(y/ies).", removed)
        return 0

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fobj:
            for chunk in iter(lambda: fobj.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _resolve_highest_available_version(
        self, name: str, arch: str
    ) -> Optional[str]:
        proc = subprocess.run(
            ["apt-cache", "madison", f"{name}:{arch}"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = proc.stdout.splitlines() if proc.returncode == 0 else []
        versions: List[str] = []
        for line in lines:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[1]:
                versions.append(parts[1])
        if versions:
            return versions[0]

        proc_no_arch = subprocess.run(
            ["apt-cache", "madison", name],
            capture_output=True,
            text=True,
            check=False,
        )
        lines_no_arch = (
            proc_no_arch.stdout.splitlines()
            if proc_no_arch.returncode == 0
            else []
        )
        for line in lines_no_arch:
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2 and parts[1]:
                return parts[1]
        return None

    def _download_extract_to_cache(
        self, *, name: str, arch: str, version: str, force: bool
    ) -> Tuple[int, Optional[str], Optional[Path]]:
        cache_dir = self._pkg_cache_dir_values(name, arch, version)
        download_dir = cache_dir / "_download"
        payload_dir = cache_dir / "payload"
        target = f"{name}:{arch}={version}"

        if cache_dir.exists() and not force:
            debs = sorted(download_dir.glob("*.deb"))
            if payload_dir.exists() and debs:
                digest = self._sha256_file(debs[0])
                self.logger.info(
                    "Using existing cache for %s -> %s", target, cache_dir
                )
                return 0, digest, cache_dir
            self.logger.warning(
                "Incomplete cache for %s at %s, reinstalling.",
                target,
                cache_dir,
            )
            shutil.rmtree(cache_dir)
        elif cache_dir.exists() and force:
            self.logger.info(
                "Force reinstall requested, removing %s", cache_dir
            )
            shutil.rmtree(cache_dir)

        download_dir.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            ["apt-get", "download", target],
            cwd=download_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            self.logger.error("apt-get download failed for %s", target)
            if proc.stderr.strip():
                self.logger.error(proc.stderr.strip())
            return 1, None, None

        debs = sorted(download_dir.glob("*.deb"))
        if not debs:
            self.logger.error("No .deb downloaded for %s", target)
            return 1, None, None

        deb_path = debs[0]
        payload_dir.mkdir(parents=True, exist_ok=True)
        proc_extract = subprocess.run(
            ["dpkg-deb", "-x", str(deb_path), str(payload_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc_extract.returncode != 0:
            self.logger.error(
                "dpkg-deb extraction failed for %s", deb_path.name
            )
            if proc_extract.stderr.strip():
                self.logger.error(proc_extract.stderr.strip())
            return 1, None, None

        digest = self._sha256_file(deb_path)
        self.logger.info("Installed %s -> %s", target, cache_dir)
        return 0, digest, cache_dir

    @staticmethod
    def _nearest_named_ancestor(path: Path, name: str) -> Optional[Path]:
        for parent in path.parents:
            if parent.name == name:
                return parent
        return None

    def _scan_payload(
        self, payload_root: Path
    ) -> tuple[List[Path], List[Path]]:
        include_roots: List[Path] = []
        # Tracks bare include roots that have at least one versioned sub-directory
        # (e.g. usr/include when usr/include/llvm-18 is also present).  These
        # bare roots are suppressed from the final result so that only the more
        # specific versioned paths end up on the compiler search path.
        bare_roots_with_versioned_children: set[Path] = set()

        lib_roots: List[Path] = []
        # Tracks bare lib roots that have a multiarch sub-directory
        # (e.g. usr/lib when usr/lib/x86_64-linux-gnu is also present).
        bare_lib_roots_with_arch_children: set[Path] = set()

        for file_path in payload_root.rglob("*"):
            # Broken symlinks (is_symlink() but not exists()) are skipped by
            # is_file().  For library symlinks (libassimp.so -> libassimp.so.5)
            # we still want to register the directory so the linker -L path is
            # present; the symlink will be repaired by _fix_broken_symlinks().
            if file_path.is_symlink() and not file_path.exists():
                name_sl = file_path.name
                if name_sl.startswith("lib") and ".so" in name_sl:
                    for lib_root_name in ("lib", "lib64"):
                        lib_root = self._nearest_named_ancestor(
                            file_path, lib_root_name
                        )
                        if lib_root is not None:
                            self._append_unique_path(lib_roots, lib_root)
                            try:
                                rel = file_path.relative_to(lib_root)
                                if len(rel.parts) >= 2:
                                    first_subdir = rel.parts[0]
                                    if _MULTIARCH_SUBDIR_RE.match(
                                        first_subdir
                                    ):
                                        arch_root = lib_root / first_subdir
                                        self._append_unique_path(
                                            lib_roots, arch_root
                                        )
                                        bare_lib_roots_with_arch_children.add(
                                            lib_root
                                        )
                            except ValueError:
                                pass
                            break
                continue

            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()
            if suffix in {".h", ".hpp", ".hh", ".hxx"}:
                include_root = self._nearest_named_ancestor(
                    file_path, "include"
                )
                if include_root is not None:
                    self._append_unique_path(include_roots, include_root)

                    # Some packages (e.g. llvm-18-dev) install their headers
                    # under a versioned sub-directory of usr/include/, such as
                    #   usr/include/llvm-18/llvm/IR/LLVMContext.h
                    # In that case the compiler needs usr/include/llvm-18 on
                    # the search path, not just usr/include.  Detect this by
                    # checking whether the path from the include root to the
                    # header file is ≥ 3 components deep and the first
                    # component looks like a versioned name (ends with -N).
                    try:
                        rel = file_path.relative_to(include_root)
                        if len(rel.parts) >= 3:
                            first_subdir = rel.parts[0]
                            if _VERSIONED_SUBDIR_RE.search(first_subdir):
                                versioned_root = include_root / first_subdir
                                self._append_unique_path(
                                    include_roots, versioned_root
                                )
                                bare_roots_with_versioned_children.add(
                                    include_root
                                )
                    except ValueError:
                        pass

            name = file_path.name
            if name.startswith("lib") and (".so" in name or suffix == ".a"):
                for lib_root_name in ("lib", "lib64"):
                    lib_root = self._nearest_named_ancestor(
                        file_path, lib_root_name
                    )
                    if lib_root is not None:
                        self._append_unique_path(lib_roots, lib_root)

                        # Debian/Ubuntu place libraries under a multiarch triplet
                        # sub-directory, e.g. usr/lib/x86_64-linux-gnu/libz.so.
                        # The linker needs that triplet path, not the bare lib root.
                        try:
                            rel = file_path.relative_to(lib_root)
                            if len(rel.parts) >= 2:
                                first_subdir = rel.parts[0]
                                if _MULTIARCH_SUBDIR_RE.match(first_subdir):
                                    arch_root = lib_root / first_subdir
                                    self._append_unique_path(
                                        lib_roots, arch_root
                                    )
                                    bare_lib_roots_with_arch_children.add(
                                        lib_root
                                    )
                        except ValueError:
                            pass
                        break

        # Drop bare include roots whose only headers live under versioned
        # sub-directories — the versioned paths are already on the list.
        filtered_include_roots = [
            p
            for p in include_roots
            if p not in bare_roots_with_versioned_children
        ]
        # Drop bare lib roots whose libraries live under a multiarch sub-directory.
        filtered_lib_roots = [
            p for p in lib_roots if p not in bare_lib_roots_with_arch_children
        ]
        return sorted(filtered_include_roots), sorted(filtered_lib_roots)

    def _update_project_paths(
        self, project: Project, include_dirs: List[Path], lib_dirs: List[Path]
    ) -> tuple[int, int]:
        added_inc = 0
        added_lib_dirs = 0
        for inc in include_dirs:
            rel_inc = self._to_relative(project.root, inc)
            if self._append_project_path(project.config.search_paths, rel_inc):
                added_inc += 1
        for lib_dir in lib_dirs:
            rel_lib = self._to_relative(project.root, lib_dir)
            if self._append_project_path(
                project.config.linker.library_paths, rel_lib
            ):
                added_lib_dirs += 1
        return added_inc, added_lib_dirs

    def _install_one(
        self,
        project: Project,
        pkg: AptPkg,
        _seen: Optional[set[str]] = None,
    ) -> int:
        if _seen is None:
            _seen = set()
        pkg_key = f"{pkg.name.lower()}:{pkg.arch.lower()}"
        if pkg_key in _seen:
            return 0
        _seen.add(pkg_key)

        force = bool(getattr(self.args, "force", False))
        rc, digest, cache_dir = self._download_extract_to_cache(
            name=pkg.name,
            arch=pkg.arch,
            version=pkg.version,
            force=force,
        )
        if rc != 0 or cache_dir is None:
            return 1
        payload_dir = cache_dir / "payload"
        debs = sorted((cache_dir / "_download").glob("*.deb"))
        deb_path = debs[0] if debs else None

        # Auto-detect and install runtime dependencies before scanning paths,
        # so that cross-package symlinks are resolved by _fix_broken_symlinks.
        depends: list[str] = []
        if deb_path is not None:
            depends = self._get_deb_depends(deb_path)
            self._auto_install_deps(project, deb_path, pkg, _seen)

        include_dirs, lib_dirs = self._scan_payload(payload_dir)
        pkg.digest = digest
        (cache_dir / "aptpkg.json").write_text(
            json.dumps(
                {
                    "name": pkg.name,
                    "arch": pkg.arch,
                    "version": pkg.version,
                    "digest": digest,
                    "depends": depends,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        added_inc, added_lib_dirs = self._update_project_paths(
            project, include_dirs, lib_dirs
        )

        self.logger.info(
            "Installed %s:%s=%s -> %s (search_paths +%d, linker.library_paths +%d)",
            pkg.name,
            pkg.arch,
            pkg.version,
            cache_dir,
            added_inc,
            added_lib_dirs,
        )
        return 0

    def _install_apt_standalone(self) -> int:
        name = self.args.name.strip()
        arch = self.args.arch.strip()
        version = self.args.version.strip() if self.args.version else None
        force = bool(getattr(self.args, "force", False))

        if not name or not arch:
            self.logger.error("name and arch are required.")
            return 1

        if not version:
            version = self._resolve_highest_available_version(name, arch)
            if not version:
                self.logger.error(
                    "Could not resolve highest available version for %s:%s",
                    name,
                    arch,
                )
                return 1
            self.logger.info(
                "Resolved highest available version for %s:%s -> %s",
                name,
                arch,
                version,
            )

        rc, digest, cache_dir = self._download_extract_to_cache(
            name=name, arch=arch, version=version, force=force
        )
        if rc != 0 or cache_dir is None:
            return 1

        manifest = {
            "name": name,
            "arch": arch,
            "version": version,
            "digest": digest,
        }
        (cache_dir / "aptpkg.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        self.logger.info(
            "Standalone apt package ready: %s (digest=%s)",
            cache_dir,
            digest if digest else "-",
        )
        return 0

    def _fix_broken_symlinks(self, project: Project) -> None:
        """Resolve broken cross-package symlinks in all installed payloads.

        Dev packages (e.g. libassimp-dev) typically ship a bare .so symlink
        (libassimp.so -> libassimp.so.5) that points to a file living in the
        corresponding runtime package (libassimp5).  After extraction into
        separate cache directories the relative symlink is broken.

        Strategy:
        1. Build an index of every file (including working symlinks) across all
           installed package payloads.
        2. For each broken symlink, look up the target filename in that index.
        3. If not found in the cache, fall back to well-known system library
           directories (covers system-only libraries like libGL, libssl, libz).
        4. Re-create the broken symlink as an absolute symlink to the found file.
        """
        # Build index: filename -> absolute path.
        # Include working symlinks (e.g. libassimp.so.5 -> libassimp.so.5.3.0)
        # because a dev package may point to the versioned symlink, not the
        # fully qualified real file.
        file_index: dict[str, Path] = {}
        for pkg in project.config.apt_packages:
            payload_dir = self._pkg_cache_dir(pkg) / "payload"
            if not payload_dir.exists():
                continue
            for p in payload_dir.rglob("*"):
                if p.is_file():  # True for real files and working symlinks
                    file_index.setdefault(p.name, p)

        cache_root = self._cache_root()

        # Find broken symlinks and repair them.  Also re-home working symlinks
        # that currently point outside the cache (system paths) when a cache
        # alternative now exists — e.g. libssl.so was previously fixed to
        # /usr/lib/.../libssl.so.3 but libssl3t64 was just added to the cache.
        fixed = 0
        rehomed = 0
        unresolved = 0
        for pkg in project.config.apt_packages:
            payload_dir = self._pkg_cache_dir(pkg) / "payload"
            if not payload_dir.exists():
                continue
            for p in payload_dir.rglob("*"):
                if not p.is_symlink():
                    continue
                is_broken = not p.exists()
                # Working symlink pointing outside the cache — candidate for
                # re-homing to cache if a better (cache-local) target exists.
                if not is_broken:
                    try:
                        p.resolve().relative_to(cache_root)
                        continue  # already inside cache, leave it alone
                    except ValueError:
                        pass  # outside cache — try to re-home below
                target_name = Path(os.readlink(p)).name
                real_file = file_index.get(target_name)

                if real_file is not None:
                    p.unlink()
                    p.symlink_to(real_file)
                    if is_broken:
                        self.logger.info(
                            "Fixed broken symlink: %s -> %s", p, real_file
                        )
                        fixed += 1
                    else:
                        self.logger.info(
                            "Re-homed system symlink: %s -> %s", p, real_file
                        )
                        rehomed += 1
                elif is_broken:
                    self.logger.error(
                        "Removing unresolvable broken symlink %s -> %s "
                        "(runtime package not in cache — add it to exodus.json)",
                        p,
                        os.readlink(p),
                    )
                    p.unlink()
                    unresolved += 1

        if fixed:
            self.logger.info("Repaired %d broken symlink(s).", fixed)
        if rehomed:
            self.logger.info(
                "Re-homed %d system symlink(s) to cache.", rehomed
            )
        if unresolved:
            self.logger.error(
                "%d broken symlink(s) removed — "
                "add the missing runtime package(s) to exodus.json and re-run install.",
                unresolved,
            )

    @staticmethod
    def _parse_dep_names(depends_field: str) -> list[str]:
        """Return the list of package names from a Debian ``Depends:`` field.

        Version constraints ``(>= x.y)`` and arch qualifiers ``:any`` are
        stripped.  When a dependency group offers alternatives (``a | b``)
        only the first alternative is used.
        """
        names: list[str] = []
        for group in depends_field.split(","):
            first_alt = group.split("|")[0].strip()
            # Strip arch qualifier ":any" / ":amd64" etc.
            first_alt = first_alt.split(":")[0].strip()
            m = _DEP_NAME_RE.match(first_alt)
            if m:
                names.append(m.group(1).lower())
        return names

    def _get_deb_depends(self, deb_path: Path) -> list[str]:
        """Return dependency package names from a .deb's ``Depends`` field."""
        proc = subprocess.run(
            ["dpkg-deb", "--field", str(deb_path), "Depends"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        return self._parse_dep_names(proc.stdout.strip())

    def _system_pkg_version(self, name: str, arch: str) -> Optional[str]:
        """Return the installed version of *name* on this system, or ``None``."""
        for target in (f"{name}:{arch}", name):
            proc = subprocess.run(
                ["dpkg-query", "-W", "--showformat=${Version}", target],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        return None

    def _auto_install_deps(
        self,
        project: Project,
        deb_path: Path,
        parent_pkg: AptPkg,
        seen: set[str],
    ) -> None:
        """Detect and install missing runtime dependencies of *parent_pkg*.

        Reads the ``Depends`` field from *deb_path*, checks which packages are
        not yet configured in the project, looks up their installed version via
        ``dpkg-query``, adds them to the project config, and installs them
        (recursively, so transitive deps are also pulled in).

        Packages that end in ``-dev`` are skipped — they are almost always
        already installed system-wide and only provide headers/static libs.
        Packages in ``_SKIP_AUTO_DEP_NAMES`` (core libc/gcc) are also skipped.
        """
        dep_names = self._get_deb_depends(deb_path)
        for dep_name in dep_names:
            # Skip dev packages and known base packages.
            if dep_name.endswith("-dev"):
                continue
            if dep_name in _SKIP_AUTO_DEP_NAMES:
                continue

            # Already configured in the project?
            if any(
                p.name.lower() == dep_name for p in project.config.apt_packages
            ):
                continue

            # Find the installed version on this system.
            version = self._system_pkg_version(dep_name, parent_pkg.arch)
            if version is None:
                self.logger.debug(
                    "Auto-dep '%s' not found on system, skipping.", dep_name
                )
                continue

            dep_pkg = AptPkg(
                name=dep_name, arch=parent_pkg.arch, version=version
            )
            project.config.apt_packages.append(dep_pkg)
            self.logger.info(
                "Auto-adding dependency: %s  arch=%s  version=%s",
                dep_name,
                parent_pkg.arch,
                version,
            )
            rc = self._install_one(project, dep_pkg, _seen=seen)
            if rc != 0:
                self.logger.warning(
                    "Failed to install auto-dep '%s'.", dep_name
                )

    def _install(
        self, project: Project, config_name: str = "exodus.json"
    ) -> int:
        pkgs = project.config.apt_packages
        if not pkgs:
            self.logger.info("No apt packages configured.")
            return 0

        selected: List[AptPkg] = []
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
                "No matching apt package entries selected for install."
            )
            return 1

        failures = 0
        seen: set[str] = set()
        for pkg in selected:
            rc = self._install_one(project, pkg, _seen=seen)
            if rc != 0:
                failures += 1

        self._fix_broken_symlinks(project)
        project.save(project.root, config_name=config_name)
        if failures:
            self.logger.error(
                "Package installation finished with %d failure(s).", failures
            )
            return 1
        self.logger.info("Package installation finished successfully.")
        return 0

    def run(self) -> int:
        """Executes the pkg command."""
        action = self.args.action
        if action == "install-apt":
            return self._install_apt_standalone()
        if action == "install-conan":
            return self.conan.install_standalone()
        if action in {"install", "install-conan-configured"} and getattr(
            self.args, "all", False
        ):
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
                    "processing package install for %s", config_name
                )
                project = self._load_project(config_name)
                if action == "install":
                    rc = self._install(project, config_name=config_name)
                else:
                    rc = self.conan.install(project, config_name=config_name)
                if rc != 0:
                    failures += 1
            if failures:
                self.logger.error(
                    "Package installation finished with %d failing config(s).",
                    failures,
                )
                return 1
            return 0

        project = self._load_project()
        handlers = {
            "list": lambda: self._list(project),
            "add": lambda: self._add(project),
            "remove": lambda: self._remove(project),
            "install": lambda: self._install(project),
            "add-conan": lambda: self.conan.add(project),
            "remove-conan": lambda: self.conan.remove(project),
            "install-conan-configured": lambda: self.conan.install(project),
        }
        handler = handlers.get(action)
        if handler is None:
            self.logger.error("Unknown pkg action: %s", action)
            return 1
        return handler()
