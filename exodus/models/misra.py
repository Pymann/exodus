"""MISRA-related configuration models."""

from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field


class MisraRuleSuppression(BaseModel):
    """Suppress a rule hit at a specific file and/or line."""

    file: Optional[Path] = Field(
        default=None,
        description="Optional file path filter for the suppression.",
    )
    line: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional 1-based line filter for the suppression.",
    )


class MisraHeuristicRuleConfig(BaseModel):
    """Base configuration inherited by all MISRA heuristic rule configs."""

    enabled: bool = True
    suppressions: List[MisraRuleSuppression] = Field(
        default_factory=list,
        description=(
            "Optional suppressions for this rule. If file and line match a violation, "
            "the rule will not trigger for that location."
        ),
    )


class MisraCppRule2101Config(MisraHeuristicRuleConfig):
    """Heuristic configuration for MISRA C++:2008 Rule 2-10-1."""

    min_identifier_length: int = Field(
        default=3,
        ge=1,
        description=(
            "Minimum identifier length to be considered for typographic-ambiguity checks."
        ),
    )
    case_insensitive: bool = Field(
        default=True,
        description="Normalize identifiers case-insensitively before ambiguity comparison.",
    )
    confusable_groups: List[str] = Field(
        default_factory=lambda: ["o0", "il1", "s5", "z2", "b8", "g6", "q9"],
        description=(
            "Each string defines a group of characters considered typographically confusable "
            "(e.g., 'o0' means 'o' and '0' are treated as equivalent)."
        ),
    )


class MisraRule2009Config(MisraHeuristicRuleConfig):
    """Heuristic configuration for MISRA C:2012 Rule 20.9 / C++:2008 Rule 16-0-7."""

    allowed_undefined_macros: List[str] = Field(
        default_factory=lambda: [
            "_MSC_VER",
            "_CRT_SECURE_NO_DEPRECATE",
            "__GNUC__",
            "__GNUC_MINOR__",
            "__GNUC_PATCHLEVEL__",
            "__clang__",
            "__clang_major__",
            "__clang_minor__",
            "__clang_patchlevel__",
            "__STDC__",
            "__STDC_VERSION__",
            "__STDC_HOSTED__",
            "__cplusplus",
            "__has_include",
            "__has_feature",
            "__has_extension",
            "__has_builtin",
        ],
        description=(
            "Identifiers that may legitimately appear in #if/#elif expressions "
            "without being locally #define'd."
        ),
    )


class MisraHeuristicsConfig(BaseModel):
    """Configurable MISRA heuristic rules."""

    rule_2_10_1: MisraCppRule2101Config = Field(
        default_factory=MisraCppRule2101Config
    )
    rule_20_9: MisraRule2009Config = Field(default_factory=MisraRule2009Config)
