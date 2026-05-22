"""Package/dependency models."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class AptPkg(BaseModel):
    """APT package dependency entry for Exodus package management."""

    name: str = Field(description="APT package name (e.g., libgl1-mesa-dev).")
    version: str = Field(description="Requested APT package version.")
    arch: str = Field(
        description="Package architecture (e.g., amd64, i386).",
    )
    required: bool = Field(
        default=True,
        description="Whether this package is required for successful build/install.",
    )
    digest: Optional[str] = Field(
        default=None,
        description="Content digest for the installed cache payload.",
    )


class ConanPkg(BaseModel):
    """Conan 2 package dependency entry for Exodus package management."""

    name: str = Field(
        description="Conan package name (e.g., fmt).",
    )
    version: str = Field(
        description="Requested Conan package version (e.g., 10.2.1).",
    )
    arch: str = Field(
        description="Target architecture setting passed to Conan (e.g., x86_64).",
    )
    user: Optional[str] = Field(
        default=None,
        description="Optional Conan user segment in reference (name/version@user/channel).",
    )
    channel: Optional[str] = Field(
        default=None,
        description="Optional Conan channel segment in reference.",
    )
    profile: Optional[str] = Field(
        default=None,
        description="Optional Conan host profile name/path.",
    )
    build_profile: Optional[str] = Field(
        default=None,
        description="Optional Conan build profile name/path.",
    )
    remote: Optional[str] = Field(
        default=None,
        description="Optional Conan remote to use for resolution.",
    )
    settings: Dict[str, str] = Field(
        default_factory=dict,
        description="Additional Conan settings (key/value), e.g. compiler.cppstd=20.",
    )
    options: Dict[str, str] = Field(
        default_factory=dict,
        description="Conan options (key/value), e.g. shared=True.",
    )
    required: bool = Field(
        default=True,
        description="Whether this package is required for successful build/install.",
    )
    digest: Optional[str] = Field(
        default=None,
        description="Content digest for the installed Conan cache payload.",
    )

    def reference(self) -> str:
        """Return full Conan reference string."""
        base = f"{self.name}/{self.version}"
        if self.user and self.channel:
            return f"{base}@{self.user}/{self.channel}"
        return base


class GitPkg(BaseModel):
    """Git-based package dependency.

    Cloned into __exodus_cache/git/<name>/<digest>/, then optional
    setup_commands are run inside the clone. Resolved commit SHA is
    written back as `digest` (analog to AptPkg.digest).
    """

    name: str = Field(
        description="Logical package name, used as primary cache key.",
    )
    repo: str = Field(
        description="Git repository URL (https or ssh).",
    )
    ref: str = Field(
        default="HEAD",
        description=(
            "Tag, branch, or commit to check out. Resolved to a commit "
            "SHA during install and written into `digest`."
        ),
    )
    setup_commands: List[List[str]] = Field(
        default_factory=list,
        description=(
            "Commands to run inside the cloned directory after checkout. "
            "Each entry is an argv list (e.g. [\"./emsdk\", \"install\", "
            "\"latest\"]). Subprocess invocations are NOT shell-evaluated."
        ),
    )
    required: bool = Field(
        default=True,
        description="Whether this package is required for successful build/install.",
    )
    digest: Optional[str] = Field(
        default=None,
        description=(
            "Resolved commit SHA. Filled by `exodus pkg install`. Used as "
            "the cache-version segment."
        ),
    )
