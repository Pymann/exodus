"""
MISRA profile registry used by the analyze command.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class MisraProfile:
    key: str
    label: str
    standard: str
    status: str


MISRA_PROFILES: Dict[str, MisraProfile] = {
    "c2012": MisraProfile(
        key="c2012",
        label="MISRA C:2012",
        standard="MISRA C:2012",
        status="stable",
    ),
    "c2023": MisraProfile(
        key="c2023",
        label="MISRA C:2023",
        standard="MISRA C:2023",
        status="experimental",
    ),
    "cpp2008": MisraProfile(
        key="cpp2008",
        label="MISRA C++:2008",
        standard="MISRA C++:2008",
        status="stable",
    ),
    "cpp2023": MisraProfile(
        key="cpp2023",
        label="MISRA C++:2023",
        standard="MISRA C++:2023",
        status="experimental",
    ),
}


def profile_choices() -> List[str]:
    return sorted(MISRA_PROFILES.keys())


def resolve_profile(profile_key: str) -> MisraProfile:
    if profile_key not in MISRA_PROFILES:
        valid = ", ".join(profile_choices())
        raise ValueError(
            f"Unknown MISRA profile '{profile_key}'. Valid: {valid}"
        )
    return MISRA_PROFILES[profile_key]
