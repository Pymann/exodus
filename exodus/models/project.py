"""
Project model definitions.
"""

import os
from pathlib import Path
import json
from typing import Any, List, Dict, Optional, Literal
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from exodus.models.misra import MisraHeuristicsConfig
from exodus.models.packages import AptPkg, ConanPkg

EXODUS_PROJECT_SCHEMA = "exodus.project.config-1.0"


def _env_path(var_name: str) -> Optional[Path]:
    raw = os.environ.get(var_name, "").strip()
    if not raw:
        return None
    return Path(raw).expanduser()


def _env_int(var_name: str, default: int) -> int:
    raw = os.environ.get(var_name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(var_name: str, default: bool) -> bool:
    raw = os.environ.get(var_name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


class CompilerConfig(BaseModel):
    """Configuration for a C/C++ compiler."""

    name: str = "gcc"
    path: Optional[Path] = None
    lang_standard: Optional[str] = None
    flags: List[str] = Field(default_factory=list)
    additional_compilers: List[str] = Field(
        default_factory=list,
        description="Optional list of additional compilers used for this project.",
    )
    common_interface_defined: bool = Field(
        default=True,
        description=(
            "Set to false if multiple compilers are used without a defined common interface "
            "(MISRA C++:2008 Rule 1-0-2)."
        ),
    )
    integer_division_documented: bool = Field(
        default=False,
        description=(
            "Set to true when integer division behavior of the chosen compiler/toolchain "
            "is explicitly documented and accounted for (MISRA C++:2008 Rule 1-0-3)."
        ),
    )


class LinkerConfig(BaseModel):
    """Configuration for the linker."""

    name: Optional[str] = None
    path: Optional[Path] = None
    script: Optional[Path] = Field(
        default=None, description="Linker script (.ld file)"
    )
    map_file: Optional[Path] = Field(
        default=None, description="Path to generate map file"
    )
    flags: List[str] = Field(default_factory=list)
    libraries: List[str] = Field(default_factory=list)
    library_paths: List[Path] = Field(default_factory=list)
    rpath: bool = Field(
        default=True,
        description="Auto-add -Wl,-rpath for each library_path (skips paths containing ':' which is the rpath separator)",
    )


class TargetArchitecture(BaseModel):
    """Target architecture configuration."""

    arch: str = "x86_64"  # e.g., armv7e-m, x86_64
    cpu: Optional[str] = None  # e.g., cortex-m4
    fpu: Optional[str] = None  # e.g., fpv4-sp-d16
    float_abi: Optional[Literal["soft", "hard", "softfp"]] = None


class Dependency(BaseModel):
    """Project dependency definition."""

    name: str
    version: Optional[str] = None
    url: Optional[str] = None
    # Add other dependency fields as needed


class ProjectConfig(BaseModel):
    """Main project configuration."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: str = Field(
        default=EXODUS_PROJECT_SCHEMA,
        alias="$schema",
        validation_alias=AliasChoices("$schema", "schema"),
    )
    name: str
    version: str = "0.1.0"
    license: List[str] = Field(
        default_factory=list, description="List of licenses"
    )
    dependencies: List[Dependency] = Field(
        default_factory=list, description="Project dependencies"
    )
    apt_packages: List[AptPkg] = Field(
        default_factory=list,
        description="APT package dependencies managed by the package manager.",
    )
    conan_packages: List[ConanPkg] = Field(
        default_factory=list,
        description="Conan package dependencies managed by the package manager.",
    )

    # Configuration
    output_type: Literal["executable", "static_lib", "shared_lib"] = (
        "executable"
    )
    artifact_in_cwd: bool = Field(
        default=False,
        description=(
            "When true, write the final linked artifact into the current "
            "working directory instead of the project build directory."
        ),
    )
    optimization: Literal["0", "1", "2", "3", "s", "g"] = "0"
    debug: bool = True
    warnings: List[str] = Field(
        default_factory=lambda: ["all", "extra"],
        description="Warning flags (without -W prefix)",
    )
    werror: bool = Field(default=False, description="Treat warnings as errors")
    misra_profile: Literal["c2012", "c2023", "cpp2008", "cpp2023"] = "cpp2008"
    misra_heuristics: MisraHeuristicsConfig = Field(
        default_factory=MisraHeuristicsConfig
    )
    clang_library_file: Optional[Path] = Field(
        default_factory=lambda: _env_path("EXODUS_LIBCLANG"),
        description=(
            "Path to libclang shared library used by analyze. "
            "Defaults from EXODUS_LIBCLANG when present."
        ),
    )
    clang_node_limit: int = Field(
        default_factory=lambda: _env_int("EXODUS_CLANG_NODE_LIMIT", 50000),
        description=(
            "Maximum number of AST nodes visited per translation unit during clang-based analysis. "
            "Defaults from EXODUS_CLANG_NODE_LIMIT, otherwise 50000."
        ),
    )
    clang_worker_timeout_sec: int = Field(
        default_factory=lambda: _env_int("EXODUS_CLANG_WORKER_TIMEOUT_SEC", 30),
        description=(
            "Maximum runtime in seconds for one clang analysis worker subprocess. "
            "Defaults from EXODUS_CLANG_WORKER_TIMEOUT_SEC, otherwise 30."
        ),
    )
    clang_worker_parallelism: int = Field(
        default_factory=lambda: _env_int(
            "EXODUS_CLANG_WORKER_PARALLELISM", 4
        ),
        description=(
            "Maximum number of concurrent clang worker subprocesses. "
            "Defaults from EXODUS_CLANG_WORKER_PARALLELISM, otherwise 4."
        ),
    )
    clang_parse_only_on_timeout: bool = Field(
        default_factory=lambda: _env_bool(
            "EXODUS_CLANG_PARSE_ONLY_ON_TIMEOUT", True
        ),
        description=(
            "Retry a timed-out clang worker once in parse-only mode to keep "
            "cross-TU facts while skipping AST heuristic checks for that file."
        ),
    )
    clang_parse_only_on_crash: bool = Field(
        default_factory=lambda: _env_bool(
            "EXODUS_CLANG_PARSE_ONLY_ON_CRASH", True
        ),
        description=(
            "Retry a crashed clang worker once in parse-only mode to keep "
            "cross-TU facts while skipping AST heuristic checks for that file."
        ),
    )
    project_headers_only: bool = Field(
        default_factory=lambda: _env_bool(
            "EXODUS_PROJECT_HEADERS_ONLY", True
        ),
        description=(
            "Restrict C++ header scanning to project-local headers reachable "
            "from the configured source files. Defaults from "
            "EXODUS_PROJECT_HEADERS_ONLY, otherwise true."
        ),
    )

    source_root: Path = Path(".")
    build_root: Path = Path("out")

    # Paths
    search_paths: List[Path] = Field(
        default_factory=list, description="Include directories"
    )
    sources: List[str] = Field(
        default_factory=list, description="Source file patterns (globs)"
    )
    src_pattern_for_headers: List[str] = Field(
        default_factory=list,
        description=(
            "Optional glob patterns that limit which project headers are scanned "
            "during analyze. If unset, Exodus derives header globs from the "
            "configured source patterns by replacing source suffixes with "
            "header suffixes."
        ),
    )

    # Build Settings
    defines: Dict[str, Optional[str]] = Field(
        default_factory=dict, description="Preprocessor definitions"
    )
    env: Dict[str, str] = Field(
        default_factory=dict, description="Extra environment variables passed to compiler and linker subprocesses"
    )
    pre_compilation: Optional[Path] = Field(
        default=None, description="Script to run before compilation"
    )
    pre_linkage: Optional[Path] = Field(
        default=None, description="Script to run before linking"
    )

    # Toolchain
    architecture: TargetArchitecture = Field(
        default_factory=TargetArchitecture
    )
    compiler: CompilerConfig = Field(default_factory=CompilerConfig)

    linker: LinkerConfig = Field(default_factory=LinkerConfig)


class Project:
    """
    Wrapper class for the project configuration and logic.
    """

    def __init__(self, root: Path, config: Optional[ProjectConfig] = None):
        self.root = root
        self.config = config or ProjectConfig(name=root.name)

    @classmethod
    def load(cls, path: Path, config_name: str = "exodus.json") -> "Project":
        """Loads a project from a directory."""
        config_file = path / config_name
        if config_file.exists():
            with open(
                config_file, "r", encoding="utf-8", newline="\n"
            ) as fobj:
                config_data = json.load(fobj)
            return cls(path, ProjectConfig(**config_data))

        # Default fallback
        return cls(path, ProjectConfig(name=path.name))

    @staticmethod
    def _matches_project_schema(config_data: Any) -> bool:
        if not isinstance(config_data, dict):
            return False
        schema_value = config_data.get("$schema", config_data.get("schema"))
        return schema_value == EXODUS_PROJECT_SCHEMA

    @classmethod
    def discover_config_names(cls, path: Path) -> List[str]:
        """Returns all JSON config files in *path* that declare the Exodus schema."""
        config_names: List[str] = []
        for candidate in sorted(path.glob("*.json")):
            try:
                with candidate.open(
                    "r", encoding="utf-8", newline="\n"
                ) as fobj:
                    config_data = json.load(fobj)
            except (OSError, json.JSONDecodeError):
                continue
            if cls._matches_project_schema(config_data):
                config_names.append(candidate.name)
        return config_names

    def save(self, path: Path, config_name: str = "exodus.json") -> None:
        """Saves the project configuration to a file."""
        config_file = path / config_name
        with open(config_file, "w", encoding="utf-8", newline="\n") as fobj:
            fobj.write(self.config.model_dump_json(indent=4, by_alias=True))
