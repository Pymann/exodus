"""
Project model definitions.
"""

from pathlib import Path
import json
from typing import Any, List, Dict, Optional, Literal
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from exodus.models.packages import AptPkg, ConanPkg, GitPkg
from exodus.models.version_pin import VersionRange

EXODUS_PROJECT_SCHEMA = "exodus.project.config-1.0"


class CompilerConfig(BaseModel):
    """Configuration for a C/C++ compiler."""

    name: str = "gcc"
    version: Optional[VersionRange] = Field(
        default=None,
        description=(
            "Version pin of the compiler (aiml spec/68 F68-114): an object of"
            " eq/gt/ge/lt/le.  A mismatch warns and does not stop the build."
        ),
    )
    path: Optional[Path] = None
    lang_standard: Optional[str] = None
    flags: List[str] = Field(default_factory=list)
    additional_compilers: List[str] = Field(
        default_factory=list,
        description=(
            "Optional list of additional compilers used for this project."
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
        description=(
            "Auto-add -Wl,-rpath for each library_path. A cache path with ':'"
            " (a Debian epoch; ':' separates rpath entries) is added through a"
            " colon-free symlink under <cache>/rpath/"
        ),
    )


class TargetArchitecture(BaseModel):
    """Target architecture configuration."""

    arch: str = "x86_64"  # e.g., armv7e-m, x86_64
    cpu: Optional[str] = None  # e.g., cortex-m4
    fpu: Optional[str] = None  # e.g., fpv4-sp-d16
    float_abi: Optional[Literal["soft", "hard", "softfp"]] = None


class Dependency(BaseModel):
    """Project dependency definition.

    ``digest`` pins the sha256 of a source package's archive.  Planned (not
    implemented yet): with a ``url`` — kontor's exodus repository
    (``<kontor>/exodus/<name>/<version>/package``), a full ``…/package`` URL or a
    local ``.tar.gz`` / directory — ``exodus deps install`` will fetch the package
    into ``__exodus_cache/deps/<name>/<sha256>/``, list it in ``aiml.packages.json``
    for ``@name/…`` imports (aiml spec/21 §3.1) and write ``digest`` back when it
    was empty.
    """

    name: str
    version: Optional[VersionRange] = Field(
        default=None,
        description=(
            "Version pin of the dependency (aiml spec/68 F68-114): an object of"
            " eq/gt/ge/lt/le, checked against the active aiml venv."
        ),
    )
    url: Optional[str] = None
    digest: Optional[str] = Field(
        default=None,
        description="sha256 of the package archive (to be filled by `exodus deps install`, planned).",
    )


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
        description=(
            "Conan package dependencies managed by the package manager."
        ),
    )
    git_packages: List[GitPkg] = Field(
        default_factory=list,
        description=(
            "Git-cloned dependencies installed into the exodus cache. "
            "Suited for toolchains not packaged via apt/conan, like emsdk."
        ),
    )

    # Configuration
    output_type: Literal["executable", "static_lib", "shared_lib", "wasm"] = (
        "executable"
    )
    asset_directories: List[Path] = Field(
        default_factory=list,
        description=(
            "Directories whose contents are packaged with the binary. "
            "For output_type='wasm' these are passed to emcc as "
            "--preload-file."
        ),
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

    source_root: Path = Path(".")
    build_root: Path = Path("out")

    # Paths
    search_paths: List[Path] = Field(
        default_factory=list, description="Include directories"
    )
    sources: List[str] = Field(
        default_factory=list, description="Source file patterns (globs)"
    )

    # Build Settings
    defines: Dict[str, Optional[str]] = Field(
        default_factory=dict, description="Preprocessor definitions"
    )
    env: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Extra environment variables passed to compiler and linker"
            " subprocesses"
        ),
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
        return bool(schema_value == EXODUS_PROJECT_SCHEMA)

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
