"""
Analyze tool implementation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import traceback
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict, cast

from exodus.core.logger import get_logger
from exodus.models.project import Project, ProjectConfig
from exodus.tools.analyze.libclang_config import resolve_libclang_path
from exodus.tools.analyze.misra_profiles import MisraProfile, resolve_profile
from exodus.tools.analyze.misra_rules import (
    C_TO_CPP_MAP,
    Violation,
    analyze_tree,
)

try:
    import tree_sitter
    import tree_sitter_c
    import tree_sitter_cpp

    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

try:
    import clang.cindex

    HAS_CLANG = True
except ImportError:
    HAS_CLANG = False

if HAS_CLANG:
    try:
        resolved_libclang = resolve_libclang_path()
        if resolved_libclang is not None:
            clang.cindex.Config.set_library_file(str(resolved_libclang))
    except Exception:
        pass
    from exodus.tools.analyze.misra_clang_rules import analyze_clang_ast


DEFAULT_CLANG_WARNINGS = [
    "-Wall",
    "-Wextra",
    "-pedantic",
    "-Wshadow",
    "-Wshadow-all",
    "-Wunreachable-code",
    "-Wunused",
    "-Wunused-parameter",
    "-Wwrite-strings",
    "-Wimplicit-int",
    "-Wimplicit-function-declaration",
    "-Wstrict-prototypes",
    "-Wuninitialized",
    "-Wmissing-braces",
    "-Wpointer-to-int-cast",
    "-Wint-to-pointer-cast",
    "-Wcast-qual",
    "-Wunused-macros",
    "-Wunused-label",
    "-Wunused-local-typedefs",
]

C_EXTENSIONS = {".c"}
CPP_EXTENSIONS = {".cpp", ".cc", ".cxx"}
DEFAULT_SOURCE_GLOBS = ["**/*.c", "**/*.cpp", "**/*.cc"]

CPP2008_TO_CPP2023_RULE_MAP = {
    "0-1-1": "0.0.1",
    "14.3": "0.0.2",
    "17.7": "0.1.2",
    "0-1-11": "0.2.2",
    "2-7-1": "5.7.1",
    "2-3-1": "5.7.3",
    "2-13-2": "5.13.3",
    "2-13-3": "5.13.5",
    "2-10-2": "6.4.1",
    "5-2-4": "8.2.2",
    "5-2-6": "8.2.4",
    "7-5-4": "8.2.10",
    "5-14-1": "8.14.1",
    "6-2-1": "8.18.2",
    "5-18-1": "8.19.1",
    "6-3-1": "9.3.1",
    "6-4-1": "9.4.1",
    "15.1": "9.6.1",
    "8-4-3": "9.6.5",
    "7-4-2": "10.4.1",
    "8-5-1": "11.6.2",
    "8-5-3": "11.6.3",
    "9-5-1": "12.3.1",
    "16-0-8": "19.0.1",
    "16-0-1": "19.0.3",
    "16-1-2": "19.1.2",
    "16-0-7": "19.1.3",
    "16-2-4": "19.2.3",
    "16-3-2": "19.3.1",
    "16-3-1": "19.3.2",
    "16-0-5": "19.3.5",
    "18-0-2": "21.2.1",
    "18-0-3": "21.2.3",
    "8-4-1": "21.10.1",
    "17-0-5": "21.10.2",
    "18-7-1": "21.10.3",
    "27-0-1": "30.0.1",
    "7-3-3": "10.3.1",
    "3-1-1": "6.2.4",
}


class CrossTUDatabase:
    class DeclSignature(TypedDict):
        file: str
        line: int
        ret: str
        params: List[Tuple[str, str]]

    class ExtRecord(TypedDict):
        decls: Set[str]
        defns: Set[str]
        tu_users: Set[str]
        signatures: List["CrossTUDatabase.DeclSignature"]

    def __init__(self) -> None:
        self.lock = threading.Lock()
        # name -> set of (file, line, linkage, category)
        self.identifiers: Dict[str, Set[Tuple[str, int, str, str]]] = {}
        # name -> {"decls": set(), "defns": set(), "tu_users": set(), "signatures": list()}
        self.ext_objects: Dict[str, CrossTUDatabase.ExtRecord] = {}

    def _ensure_ext_record(self, name: str) -> ExtRecord:
        if name not in self.ext_objects:
            self.ext_objects[name] = {
                "decls": set(),
                "defns": set(),
                "tu_users": set(),
                "signatures": [],
            }
        return self.ext_objects[name]

    def add(
        self, name: str, file_path: str, line: int, linkage: str, category: str
    ) -> None:
        with self.lock:
            if name not in self.identifiers:
                self.identifiers[name] = set()
            self.identifiers[name].add(
                (str(file_path), round(line), str(linkage), str(category))
            )

    def update_ext(
        self,
        name: str,
        decl_file: Optional[str],
        is_defn: bool,
        tu_path: Optional[str],
    ) -> None:
        with self.lock:
            record = self._ensure_ext_record(name)
            if decl_file:
                if is_defn:
                    record["defns"].add(decl_file)
                else:
                    record["decls"].add(decl_file)
            if tu_path:
                record["tu_users"].add(tu_path)

    def add_decl_signature(
        self,
        name: str,
        file_path: str,
        line: int,
        return_type: str,
        params: List[Tuple[str, str]],
    ) -> None:
        with self.lock:
            record = self._ensure_ext_record(name)
            record["signatures"].append(
                {
                    "file": str(file_path),
                    "line": int(line),
                    "ret": return_type,
                    "params": params,
                }
            )

    def analyze(self) -> List[Violation]:
        violations: List[Violation] = []
        file_text_cache: Dict[str, str] = {}

        def _is_function_like_usage(symbol: str, files: Set[str]) -> bool:
            pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(")
            for f in files:
                if not f:
                    continue
                text = file_text_cache.get(f)
                if text is None:
                    try:
                        text = Path(f).read_text(
                            encoding="utf-8", errors="ignore"
                        )
                    except Exception:
                        text = ""
                    file_text_cache[f] = text
                if pattern.search(text):
                    return True
            return False

        for name, decls in self.identifiers.items():
            if len(decls) <= 1:
                continue

            cats = set(d[3] for d in decls)
            linkages = [d[2] for d in decls]

            # 5.6: Typedef uniqueness
            if "typedef" in cats:
                typedef_decls = [d for d in decls if d[3] == "typedef"]
                typedef_sites = {(d[0], d[1]) for d in typedef_decls}
                if len(typedef_sites) > 1:
                    for d in typedef_decls:
                        violations.append(
                            Violation(
                                "Rule 5.6",
                                f"Typedef name '{name}' is not unique across the project.",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                # Also report typedef collisions with non-typedef identifiers
                # (object/function/tag with the same spelling).
                non_typedef_decls = [d for d in decls if d[3] != "typedef"]
                if non_typedef_decls:
                    for d in typedef_decls + non_typedef_decls:
                        violations.append(
                            Violation(
                                "Rule 5.6",
                                f"Typedef name '{name}' is not unique across the project.",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                continue

            # 5.7: Tag uniqueness
            if "tag" in cats:
                tag_decls = [d for d in decls if d[3] == "tag"]
                tag_sites = {(d[0], d[1]) for d in tag_decls}
                if len(tag_sites) > 1:
                    for d in tag_decls:
                        violations.append(
                            Violation(
                                "Rule 5.7",
                                f"Tag name '{name}' is reused for another entity.",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                continue

            # 5.4 & 5.5: Macros
            if "macro" in cats:
                if len(cats) > 1:
                    for d in decls:
                        violations.append(
                            Violation(
                                "Rule 5.5",
                                f"Identifier '{name}' is not distinct from a macro name.",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                else:
                    for d in decls:
                        violations.append(
                            Violation(
                                "Rule 5.4",
                                f"Macro identifier '{name}' is not distinct (multiple definitions).",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                continue

            # 5.8 & 5.9: Linkage
            has_external = "LinkageKind.EXTERNAL" in linkages
            has_internal = "LinkageKind.INTERNAL" in linkages

            if has_external:
                if any(l != "LinkageKind.EXTERNAL" for l in linkages):
                    for d in decls:
                        if d[2] != "LinkageKind.EXTERNAL":
                            violations.append(
                                Violation(
                                    "Rule 5.8",
                                    f"Identifier '{name}' with external linkage has a cross-namespace collision.",
                                    Path(d[0]) if d[0] else None,
                                    d[1],
                                    trigger=name,
                                )
                            )
            elif has_internal:
                internal_decls = [
                    d for d in decls if d[2] == "LinkageKind.INTERNAL"
                ]
                internal_files = {d[0] for d in internal_decls}
                # Same static identifier may appear multiple times in one TU as
                # declaration + definition of the same entity. Only report when
                # it collides across translation units.
                if len(internal_files) > 1:
                    for d in internal_decls:
                        violations.append(
                            Violation(
                                "Rule 5.9",
                                f"Identifier '{name}' with internal linkage is not unique.",
                                Path(d[0]) if d[0] else None,
                                d[1],
                                trigger=name,
                            )
                        )
                elif any(l == "LinkageKind.NO_LINKAGE" for l in linkages):
                    for d in decls:
                        if d[2] == "LinkageKind.NO_LINKAGE":
                            violations.append(
                                Violation(
                                    "Rule 5.9",
                                    f"Identifier '{name}' with internal linkage collides with local scope.",
                                    Path(d[0]) if d[0] else None,
                                    d[1],
                                    trigger=name,
                                )
                            )

        for name, data in self.ext_objects.items():
            if name == "main":
                continue

            # Rule 8.3
            sigs = data.get("signatures", [])
            if len(sigs) > 1:
                first_sig = sigs[0]
                is_cpp_symbol = False
                if first_sig.get("file"):
                    is_cpp_symbol = (
                        Path(first_sig["file"]).suffix in CPP_EXTENSIONS
                    )
                for other_sig in sigs[1:]:
                    if other_sig.get("file"):
                        is_cpp_symbol = is_cpp_symbol or (
                            Path(other_sig["file"]).suffix in CPP_EXTENSIONS
                        )
                    if first_sig["ret"] != other_sig["ret"]:
                        violations.append(
                            Violation(
                                "Rule 8.3",
                                (
                                    f"Declaration of '{name}' has mismatched return type or type qualifiers "
                                    f"across files ('{first_sig['ret']}' vs '{other_sig['ret']}')."
                                ),
                                Path(other_sig["file"]),
                                other_sig["line"],
                                trigger=name,
                            )
                        )
                        if is_cpp_symbol:
                            violations.append(
                                Violation(
                                    "Rule 3-2-1",
                                    (
                                        f"Declarations of '{name}' are not type-compatible "
                                        f"('{first_sig['ret']}' vs '{other_sig['ret']}')."
                                    ),
                                    Path(other_sig["file"]),
                                    other_sig["line"],
                                    trigger=name,
                                )
                            )
                            violations.append(
                                Violation(
                                    "Rule 3-9-1",
                                    (
                                        f"Type tokens for '{name}' are not identical "
                                        f"('{first_sig['ret']}' vs '{other_sig['ret']}')."
                                    ),
                                    Path(other_sig["file"]),
                                    other_sig["line"],
                                    trigger=name,
                                )
                            )

                    if len(first_sig["params"]) != len(other_sig["params"]):
                        violations.append(
                            Violation(
                                "Rule 8.3",
                                f"Declaration of '{name}' has mismatched parameter count.",
                                Path(other_sig["file"]),
                                other_sig["line"],
                                trigger=name,
                            )
                        )
                        if is_cpp_symbol:
                            violations.append(
                                Violation(
                                    "Rule 3-2-1",
                                    f"Declarations of '{name}' have incompatible parameter lists.",
                                    Path(other_sig["file"]),
                                    other_sig["line"],
                                    trigger=name,
                                )
                            )
                            violations.append(
                                Violation(
                                    "Rule 3-9-1",
                                    f"Type tokens for '{name}' parameter list are not identical.",
                                    Path(other_sig["file"]),
                                    other_sig["line"],
                                    trigger=name,
                                )
                            )
                    else:
                        for p1, p2 in zip(
                            first_sig["params"], other_sig["params"]
                        ):
                            if p1[0] != p2[0]:
                                violations.append(
                                    Violation(
                                        "Rule 8.3",
                                        (
                                            f"Declaration of '{name}' has mismatched parameter types "
                                            f"('{p1[0]}' vs '{p2[0]}')."
                                        ),
                                        Path(other_sig["file"]),
                                        other_sig["line"],
                                        trigger=name,
                                    )
                                )
                                if is_cpp_symbol:
                                    violations.append(
                                        Violation(
                                            "Rule 3-2-1",
                                            (
                                                f"Declarations of '{name}' are not type-compatible "
                                                f"('{p1[0]}' vs '{p2[0]}')."
                                            ),
                                            Path(other_sig["file"]),
                                            other_sig["line"],
                                            trigger=name,
                                        )
                                    )
                                    violations.append(
                                        Violation(
                                            "Rule 3-9-1",
                                            (
                                                f"Type tokens for '{name}' parameter are not identical "
                                                f"('{p1[0]}' vs '{p2[0]}')."
                                            ),
                                            Path(other_sig["file"]),
                                            other_sig["line"],
                                            trigger=name,
                                        )
                                    )
                            elif p1[1] and p2[1] and p1[1] != p2[1]:
                                violations.append(
                                    Violation(
                                        "Rule 8.3",
                                        (
                                            f"Declaration of '{name}' has mismatched parameter names "
                                            f"('{p1[1]}' vs '{p2[1]}')."
                                        ),
                                        Path(other_sig["file"]),
                                        other_sig["line"],
                                        trigger=name,
                                    )
                                )

            ext_decls = data["decls"]
            ext_defns = data["defns"]
            ext_users = data["tu_users"]
            signatures = data["signatures"]
            sample_tu = next(iter(ext_defns or ext_decls or ext_users), None)
            sample_file = Path(sample_tu) if sample_tu else None
            header_suffixes = {".h", ".hh", ".hpp", ".hxx"}
            has_header_decl = any(
                Path(entry).suffix.lower() in header_suffixes
                for entry in (ext_decls | ext_defns)
            )

            if len(ext_decls) > 1:
                violations.append(
                    Violation(
                        "Rule 8.5",
                        (
                            f"External object/function '{name}' is declared in multiple "
                            "distinct files."
                        ),
                        sample_file,
                        0,
                        trigger=name,
                    )
                )
                if sample_file and sample_file.suffix in CPP_EXTENSIONS:
                    violations.append(
                        Violation(
                            "Rule 3-2-3",
                            (
                                f"'{name}' is declared more than once within a translation unit "
                                "or project declaration set."
                            ),
                            sample_file,
                            0,
                            trigger=name,
                        )
                    )

            if len(ext_defns) > 1:
                violations.append(
                    Violation(
                        "Rule 8.6",
                        f"External identifier '{name}' has multiple definitions.",
                        sample_file,
                        0,
                        trigger=name,
                    )
                )
            elif len(ext_defns) == 0 and len(ext_users) > 0:
                violations.append(
                    Violation(
                        "Rule 8.6",
                        f"External identifier '{name}' is used but never defined.",
                        sample_file,
                        0,
                        trigger=name,
                    )
                )
                # Rule 17.3: no visible declaration for called function.
                # If we only see call-like usage and no collected function signature,
                # treat this as implicit declaration usage in C code.
                if not signatures and _is_function_like_usage(name, ext_users):
                    violations.append(
                        Violation(
                            "Rule 17.3",
                            f"A function shall not be declared implicitly: '{name}'",
                            sample_file,
                            0,
                            trigger=name,
                        )
                    )

            if len(ext_defns) == 1 and len(ext_users) <= 1:
                # Only single-TU external usage should prefer static when declaration exists.
                if (
                    len(ext_users) == 0
                    or list(ext_users)[0] == list(ext_defns)[0]
                ):
                    # Public API symbols declared in headers can be referenced
                    # from external translation units that are not part of this scan.
                    # Do not force Rule 8.7 in that case.
                    if len(ext_decls) > 0 and not has_header_decl:
                        violations.append(
                            Violation(
                                "Rule 8.7",
                                (
                                    f"External identifier '{name}' is referenced in only one "
                                    "translation unit and should be static."
                                ),
                                sample_file,
                                0,
                                trigger=name,
                            )
                        )

            if sample_file and sample_file.suffix in CPP_EXTENSIONS:
                # Rule 3-3-1: external-linkage objects/functions should be declared in a header.
                is_publicly_referenced = (
                    len(ext_users) > 1 or len(ext_decls) > 0
                )
                if is_publicly_referenced and not has_header_decl:
                    violations.append(
                        Violation(
                            "Rule 3-3-1",
                            (
                                f"External identifier '{name}' is not declared in a header file."
                            ),
                            sample_file,
                            0,
                            trigger=name,
                        )
                    )

        return violations


class AnalyzeTool:
    """Tool for analyzing the project."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)
        self.misra_profile: Optional[MisraProfile] = None
        self.project_config: Optional[ProjectConfig] = None
        self.single_rules: Optional[Set[str]] = self._parse_single_rules(
            getattr(args, "single_rules", None)
        )
        self.violations: List[Violation] = []
        self.violation_keys: Set[Tuple[str, str, int, str, str]] = set()
        self.violation_canonical_index: Dict[
            Tuple[str, str, int, str], int
        ] = {}
        self.lock = threading.Lock()
        # libclang can become unstable when used concurrently from multiple Python threads.
        # Keep clang analysis serialized to avoid random hangs/deadlocks on larger projects.
        self.clang_lock = threading.Lock()
        self.global_db = CrossTUDatabase()
        self.enable_clang = HAS_CLANG and not bool(
            getattr(args, "no_clang", False)
        )
        self.clang_compile_db_args: Dict[str, List[str]] = {}
        self.clang_compile_db_path: Optional[Path] = None
        self.debug_clang = bool(getattr(args, "debug_clang", False))
        self.clang_debug_file: Optional[Path] = None

    @staticmethod
    def _normalize_rule_for_filter(rule: str) -> str:
        normalized = (rule or "").strip()
        if normalized.lower().startswith("rule "):
            normalized = normalized[5:].strip()
        return normalized.lower()

    @classmethod
    def _parse_single_rules(
        cls, raw_rules: Optional[List[str]]
    ) -> Optional[Set[str]]:
        if not raw_rules:
            return None
        selected: Set[str] = set()
        for token in raw_rules:
            for piece in str(token).split(","):
                normalized = cls._normalize_rule_for_filter(piece)
                if normalized:
                    selected.add(normalized)
        return selected or None

    def _rule_is_selected(self, rule: str) -> bool:
        if not self.single_rules:
            return True
        return self._normalize_rule_for_filter(rule) in self.single_rules

    def _resolve_misra_profile(self, config: ProjectConfig) -> MisraProfile:
        cli_profile = getattr(self.args, "misra_profile", None)
        selected_profile = cli_profile or config.misra_profile
        return resolve_profile(selected_profile)

    def _resolved_project_libclang(
        self, config: ProjectConfig
    ) -> Optional[Path]:
        return resolve_libclang_path(preferred_path=config.clang_library_file)

    def _abort_for_missing_clang(self, config: ProjectConfig) -> int:
        configured = (
            str(config.clang_library_file)
            if config.clang_library_file is not None
            else "unset"
        )
        self.logger.info(
            "Configure libclang via project config "
            "'clang_library_file', the EXODUS_LIBCLANG environment "
            "variable, or by fetching the referenced artifact with "
            "'exodus pkg install'. Current clang_library_file=%s",
            configured,
        )
        self.logger.fatal(
            "MISRA analysis requires libclang, but the shared library "
            "could not be resolved."
        )
        return 2

    @staticmethod
    def _violation_key(violation: Violation) -> Tuple[str, str, int, str, str]:
        return (
            violation.rule,
            str(violation.file) if violation.file else "",
            int(violation.line),
            violation.message,
            violation.detector or "",
        )

    @staticmethod
    def _detector_priority(detector: str) -> int:
        priority = {
            "clang-diagnostic": 5,
            "cpp-ch0-diagnostic": 5,
            "project-config": 5,
            "cross-tu-heuristic": 4,
            "tree-sitter-query": 3,
            "clang-heuristic": 2,
            "cpp-ch0-heuristic": 2,
            "fallback": 1,
            "unknown-detector": 0,
        }
        return priority.get(detector or "", 0)

    @staticmethod
    def _extract_quoted_symbol(message: str) -> str:
        match = re.search(r"'([^']+)'", message)
        return match.group(1) if match else ""

    @staticmethod
    def _rule_to_heuristic_attr(rule: str) -> str:
        raw = rule
        if raw.startswith("Rule "):
            raw = raw[5:].strip()
        normalized = re.sub(r"[^0-9A-Za-z]+", "_", raw).strip("_")
        return f"rule_{normalized}" if normalized else ""

    @staticmethod
    def _file_matches_suppression(
        violation_file: Optional[Path], suppression_file: Path
    ) -> bool:
        if violation_file is None:
            return False
        v = str(violation_file)
        s = str(suppression_file)
        return v == s or v.endswith(s)

    def _is_suppressed(self, violation: Violation) -> bool:
        if not self.project_config:
            return False
        heuristics = getattr(self.project_config, "misra_heuristics", None)
        if heuristics is None:
            return False
        attr = self._rule_to_heuristic_attr(violation.rule or "")
        if not attr or not hasattr(heuristics, attr):
            return False
        cfg = getattr(heuristics, attr)
        suppressions = getattr(cfg, "suppressions", []) or []
        for suppression in suppressions:
            s_file = getattr(suppression, "file", None)
            s_line = getattr(suppression, "line", None)
            if s_file is not None and not self._file_matches_suppression(
                violation.file, s_file
            ):
                continue
            if s_line is not None and int(s_line) != int(violation.line):
                continue
            return True
        return False

    @classmethod
    def _canonical_violation_key(
        cls, violation: Violation
    ) -> Tuple[str, str, int, str]:
        rule = violation.rule
        file_str = str(violation.file) if violation.file else ""
        line = int(violation.line)
        msg = violation.message or ""

        # Normalize known duplicate phrasings emitted by different detectors.
        if rule in {
            "Rule 5.5",
            "Rule 5.6",
            "Rule 5.7",
            "Rule 2-10-3",
            "Rule 2-10-4",
            "Rule 2.7",
            "Rule 0-1-11",
        }:
            symbol = cls._extract_quoted_symbol(msg)
            if symbol:
                return (rule, file_str, line, symbol)
        if rule in {"Rule 4.2", "Rule 2-3-1"}:
            if "trigraph" in msg.lower():
                return (rule, file_str, line, "trigraph")
        if rule == "Rule 10.1":
            return (rule, file_str, line, "bitwise")

        # Default: keep message-specific identity.
        return (rule, file_str, line, msg)

    @staticmethod
    def _tag_violations(
        violations: List[Violation], default_detector: str
    ) -> List[Violation]:
        for violation in violations:
            if not getattr(violation, "detector", ""):
                violation.detector = default_detector
        return violations

    def _record_violations(self, violations: List[Violation]) -> None:
        if not violations:
            return
        with self.lock:
            for violation in violations:
                if not getattr(violation, "trigger", ""):
                    try:
                        derived_trigger = violation._derived_trigger()
                    except Exception:
                        derived_trigger = ""
                    if derived_trigger:
                        violation.trigger = derived_trigger
                raw_trigger = getattr(violation, "trigger", "")
                if isinstance(raw_trigger, (list, tuple, set)):
                    trigger_text = ", ".join(
                        str(x) for x in raw_trigger if x is not None
                    )
                elif raw_trigger is None:
                    trigger_text = ""
                else:
                    trigger_text = str(raw_trigger)
                trigger_text = trigger_text.strip()
                if trigger_text and trigger_text != raw_trigger:
                    violation.trigger = trigger_text
                # Replace low-information triggers (e.g. single short identifiers)
                # with a richer source-derived trigger when possible.
                if (
                    violation.file is not None
                    and violation.line
                    and re.fullmatch(r"[A-Za-z_]\w*", trigger_text)
                    and len(trigger_text) <= 4
                ):
                    try:
                        better_trigger = (
                            Violation._extract_trigger_from_source(
                                violation.file, int(violation.line)
                            )
                        )
                    except Exception:
                        better_trigger = ""
                    if (
                        better_trigger
                        and better_trigger != trigger_text
                        and len(better_trigger) > len(trigger_text) + 2
                    ):
                        violation.trigger = better_trigger
                if (
                    self.misra_profile
                    and self.misra_profile.key in {"cpp2008", "cpp2023"}
                    and isinstance(violation.rule, str)
                    and violation.rule.startswith("Rule ")
                ):
                    mapped_cpp2008 = C_TO_CPP_MAP.get(violation.rule)
                    if mapped_cpp2008:
                        violation.rule = mapped_cpp2008
                if (
                    self.misra_profile
                    and self.misra_profile.key == "cpp2023"
                    and isinstance(violation.rule, str)
                    and violation.rule.startswith("Rule ")
                ):
                    rule_id = violation.rule[5:].strip()
                    mapped = CPP2008_TO_CPP2023_RULE_MAP.get(rule_id)
                    if mapped:
                        violation.rule = f"Rule {mapped}"
                if (
                    self.misra_profile
                    and self.misra_profile.key == "cpp2023"
                    and isinstance(violation.rule, str)
                    and violation.rule.startswith("Rule ")
                ):
                    # MISRA C++:2023 coverage uses dotted triplet rule IDs (x.y.z).
                    # Keep output profile-pure and drop legacy/non-triplet IDs.
                    rule_id = violation.rule[5:].strip()
                    if rule_id.count(".") != 2:
                        continue
                if (
                    self.misra_profile
                    and self.misra_profile.key == "cpp2008"
                    and isinstance(violation.rule, str)
                    and violation.rule.startswith("Rule ")
                ):
                    # MISRA C++:2008 uses hyphenated identifiers (e.g. 5-0-17).
                    # Drop C/C2023-style dotted identifiers in this profile to avoid
                    # mixed-profile output noise (e.g. "Rule 10.3", "Rule 8.4").
                    rule_id = violation.rule[5:].strip()
                    if "." in rule_id:
                        continue
                if not self._rule_is_selected(violation.rule):
                    continue
                if self._is_suppressed(violation):
                    continue
                key = self._violation_key(violation)
                if key in self.violation_keys:
                    continue
                canonical_key = self._canonical_violation_key(violation)
                existing_index = self.violation_canonical_index.get(
                    canonical_key
                )
                if existing_index is not None:
                    existing = self.violations[existing_index]
                    old_priority = self._detector_priority(existing.detector)
                    new_priority = self._detector_priority(violation.detector)
                    if new_priority > old_priority:
                        old_key = self._violation_key(existing)
                        self.violation_keys.discard(old_key)
                        self.violations[existing_index] = violation
                        self.violation_keys.add(key)
                    continue

                self.violation_keys.add(key)
                self.violation_canonical_index[canonical_key] = len(
                    self.violations
                )
                self.violations.append(violation)

    def _collect_source_files(self, config: ProjectConfig) -> List[Path]:
        patterns = config.sources or DEFAULT_SOURCE_GLOBS
        source_files: Set[Path] = set()
        for pattern in patterns:
            source_files.update(config.source_root.glob(pattern))

        supported = {
            src
            for src in source_files
            if src.is_file() and src.suffix in (C_EXTENSIONS | CPP_EXTENSIONS)
        }
        return sorted(supported)

    def _profile_accepts_file(self, source_file: Path) -> bool:
        if not self.misra_profile:
            return True

        suffix = source_file.suffix
        is_c = suffix in C_EXTENSIONS
        is_cpp = suffix in CPP_EXTENSIONS
        key = self.misra_profile.key

        if key in {"c2012", "c2023"}:
            return is_c
        if key in {"cpp2008", "cpp2023"}:
            return is_cpp
        return is_c or is_cpp

    def _default_lang_standard(self, is_cpp: bool) -> str:
        profile_key = self.misra_profile.key if self.misra_profile else ""
        if is_cpp:
            if profile_key == "cpp2023":
                return "23"
            return "03"
        if profile_key == "c2023":
            return "23"
        return "11"

    def _build_clang_args(
        self,
        config: ProjectConfig,
        is_cpp: bool,
        standard_override: Optional[str] = None,
    ) -> List[str]:
        args = list(DEFAULT_CLANG_WARNINGS)
        configured_standard = config.compiler.lang_standard
        selected_standard = (
            standard_override
            or configured_standard
            or self._default_lang_standard(is_cpp=is_cpp)
        )

        if is_cpp:
            args.append("-xc++")
            args.append(f"-std=c++{selected_standard}")
        else:
            args.append("-xc")
            args.append(f"-std=c{selected_standard}")

        for inc in config.search_paths:
            args.append(f"-I{inc}")

        for name, value in config.defines.items():
            if value:
                args.append(f"-D{name}={value}")
            else:
                args.append(f"-D{name}")

        return args

    @staticmethod
    def _normalize_compile_db_file_key(file_path: Path) -> str:
        return str(file_path.resolve())

    def _discover_compile_commands_path(
        self, config: ProjectConfig
    ) -> Optional[Path]:
        candidates = [
            Path.cwd() / "compile_commands.json",
            config.build_root / "compile_commands.json",
            Path.cwd() / "out" / "compile_commands.json",
        ]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except Exception:
                resolved = candidate
            if resolved.exists() and resolved.is_file():
                return resolved
        return None

    @staticmethod
    def _sanitize_compile_command_args(
        args: List[str], source_file: Path, command_dir: Optional[Path] = None
    ) -> List[str]:
        if not args:
            return []
        # Drop compiler executable
        work = list(args[1:]) if len(args) > 1 else []
        source_name = source_file.name
        source_abs = str(source_file.resolve())
        source_rel = str(source_file)

        filtered: List[str] = []
        include_like_flags = {
            "-I",
            "-isystem",
            "-iquote",
            "-idirafter",
            "-include",
            "-imacros",
            "-isysroot",
            "--sysroot",
        }
        pass_through_prefixes = (
            "-I",
            "-D",
            "-U",
            "-std=",
            "-x",
            "-isystem",
            "-iquote",
            "-idirafter",
            "-include",
            "-imacros",
            "-isysroot",
            "--sysroot=",
            "-target",
            "--target=",
            "-nostdinc",
            "-nostdinc++",
            "-fms-extensions",
            "-fms-compatibility",
            "-fms-compatibility-version=",
            "-fdelayed-template-parsing",
            "-fchar8_t",
            "-fshort-wchar",
            "-funsigned-char",
            "-fsigned-char",
        )

        i = 0
        while i < len(work):
            token = work[i]
            # Drop compile-only and output-specifying flags.
            if token in {"-c"}:
                i += 1
                continue
            if token in {"-o", "-MF", "-MT", "-MQ"}:
                i += 2
                continue
            if token.startswith("-o") and len(token) > 2:
                i += 1
                continue
            if token in {"-MMD", "-MD", "-MP"}:
                i += 1
                continue

            # Drop source file operand itself.
            if token in {source_abs, source_rel, source_name}:
                i += 1
                continue
            # Drop any plain token that looks like a source path.
            lower = token.lower()
            if lower.endswith(
                (".c", ".cc", ".cpp", ".cxx")
            ) and not token.startswith("-"):
                i += 1
                continue

            # Keep only AST-relevant frontend options from compile database.
            if token in include_like_flags:
                if i + 1 < len(work):
                    value = work[i + 1]
                    if command_dir is not None:
                        value_path = Path(value)
                        if (
                            not value_path.is_absolute()
                            and not value.startswith("-")
                        ):
                            value = str((command_dir / value_path).resolve())
                    filtered.append(token)
                    filtered.append(value)
                    i += 2
                    continue
                i += 1
                continue

            if token in {"-x", "-target"}:
                if i + 1 < len(work):
                    filtered.append(token)
                    filtered.append(work[i + 1])
                    i += 2
                    continue
                i += 1
                continue

            if token.startswith(pass_through_prefixes):
                filtered.append(token)
                i += 1
                continue

            # Drop non-essential flags (warnings, optimization, debug, linker flags, etc.)
            i += 1

        return filtered

    def _load_compile_commands_for_sources(
        self, source_files: List[Path]
    ) -> None:
        self.clang_compile_db_args = {}
        self.clang_compile_db_path = None
        if not source_files:
            return
        project_config = self.project_config
        if project_config is None:
            return
        path = self._discover_compile_commands_path(project_config)
        if path is None:
            return
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8", errors="ignore")
            )
        except Exception as exc:
            self.logger.warning(
                "Failed to parse compile_commands.json at %s: %s", path, exc
            )
            return
        if not isinstance(payload, list):
            self.logger.warning(
                "compile_commands.json at %s is not a JSON array.", path
            )
            return

        source_keys = {
            self._normalize_compile_db_file_key(src): src
            for src in source_files
        }
        mapped = 0
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            raw_file = entry.get("file")
            if not raw_file:
                continue
            file_path = Path(raw_file)
            if not file_path.is_absolute():
                directory = Path(entry.get("directory", str(Path.cwd())))
                file_path = directory / file_path
            key = self._normalize_compile_db_file_key(file_path)
            src = source_keys.get(key)
            if src is None:
                continue

            raw_args = entry.get("arguments")
            if isinstance(raw_args, list):
                args = [str(a) for a in raw_args]
            else:
                cmd = entry.get("command")
                if not isinstance(cmd, str) or not cmd.strip():
                    continue
                try:
                    args = shlex.split(cmd)
                except Exception:
                    continue

            cmd_dir_raw = entry.get("directory")
            cmd_dir = (
                Path(cmd_dir_raw)
                if isinstance(cmd_dir_raw, str) and cmd_dir_raw
                else None
            )
            sanitized = self._sanitize_compile_command_args(
                args, src, command_dir=cmd_dir
            )
            if not sanitized:
                continue
            self.clang_compile_db_args[key] = sanitized
            mapped += 1

        if mapped > 0:
            self.clang_compile_db_path = path
            self.logger.info(
                "Using compile_commands.json from %s (matched %d/%d sources).",
                path,
                mapped,
                len(source_files),
            )

    def _clang_args_for_file(
        self,
        source_file: Path,
        config: ProjectConfig,
        is_cpp: bool,
        standard_override: Optional[str] = None,
    ) -> List[str]:
        key = self._normalize_compile_db_file_key(source_file)
        from_db = self.clang_compile_db_args.get(key)
        if from_db:
            return list(from_db)
        return self._build_clang_args(
            config, is_cpp=is_cpp, standard_override=standard_override
        )

    def _write_clang_debug(
        self,
        *,
        source_file: Path,
        args: List[str],
        status: str,
        exit_code: Optional[int] = None,
        stderr: str = "",
        note: str = "",
    ) -> None:
        if not self.debug_clang or self.clang_debug_file is None:
            return
        payload = {
            "file": str(source_file),
            "status": status,
            "exit_code": exit_code,
            "stderr": stderr,
            "note": note,
            "args": args,
            "compile_commands": (
                str(self.clang_compile_db_path)
                if self.clang_compile_db_path
                else ""
            ),
        }
        try:
            self.clang_debug_file.parent.mkdir(parents=True, exist_ok=True)
            with self.clang_debug_file.open("a", encoding="utf-8") as fobj:
                fobj.write(json.dumps(payload, ensure_ascii=True) + "\n")
        except Exception:
            return

    def _fallback_lang_standards(
        self, is_cpp: bool, primary_standard: str, has_user_override: bool
    ) -> List[str]:
        # If the user explicitly configured a language standard, do not guess alternatives.
        if has_user_override:
            return [primary_standard]

        if is_cpp:
            candidates = [primary_standard, "20", "17", "14", "11", "03"]
        else:
            candidates = [primary_standard, "2x", "17", "11", "99"]

        unique: List[str] = []
        seen = set()
        for std in candidates:
            if std not in seen:
                seen.add(std)
                unique.append(std)
        return unique

    def _analyze_with_tree_sitter(
        self,
        source_file: Path,
        language: tree_sitter.Language,
        config: ProjectConfig,
    ) -> None:
        parser = tree_sitter.Parser()
        if hasattr(parser, "set_language"):
            cast(Any, parser).set_language(language)
        else:
            parser.language = language

        source_code = source_file.read_bytes()
        tree = parser.parse(source_code)
        file_violations = analyze_tree(
            tree, source_file, language, source_code, project_config=config
        )
        self._record_violations(
            self._tag_violations(file_violations, "tree-sitter-query")
        )

    def _analyze_with_clang(
        self, source_file: Path, is_cpp: bool, config: ProjectConfig
    ) -> None:
        clang_index = clang.cindex.Index.create()
        options = clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        has_user_standard = bool(config.compiler.lang_standard)
        primary_standard = (
            config.compiler.lang_standard
            or self._default_lang_standard(is_cpp=is_cpp)
        )
        standards_to_try = self._fallback_lang_standards(
            is_cpp=is_cpp,
            primary_standard=primary_standard,
            has_user_override=has_user_standard,
        )

        last_exc: Optional[Exception] = None
        for idx, standard in enumerate(standards_to_try):
            args = self._clang_args_for_file(
                source_file,
                config=config,
                is_cpp=is_cpp,
                standard_override=standard,
            )
            try:
                tu = clang_index.parse(
                    str(source_file), args=args, options=options
                )
                clang_violations = analyze_clang_ast(
                    tu, source_file, self.global_db, config
                )
                self._record_violations(
                    self._tag_violations(clang_violations, "clang-heuristic")
                )
                if idx > 0:
                    language_name = "C++" if is_cpp else "C"
                    self.logger.warning(
                        "Fell back to %s%s for %s after analysis failure with a newer standard.",
                        language_name,
                        standard,
                        source_file,
                    )
                return
            except Exception as exc:
                last_exc = exc
                continue

        if last_exc is not None:
            raise last_exc

    def _analyze_with_clang_subprocess(
        self, source_file: Path, is_cpp: bool, config: ProjectConfig
    ) -> None:
        args = self._clang_args_for_file(
            source_file, config=config, is_cpp=is_cpp
        )
        self._write_clang_debug(
            source_file=source_file,
            args=args,
            status="start",
            note="clang worker invocation",
        )
        try:
            config_payload = config.model_dump()
        except AttributeError:
            config_payload = config.dict()

        payload = {
            "source_file": str(source_file),
            "clang_args": args,
            "project_config": config_payload,
        }
        trace_file: Optional[Path] = None
        if self.debug_clang and self.clang_debug_file is not None:
            trace_root = self.clang_debug_file.parent / "clang_traces"
            trace_file = trace_root / f"{source_file}.trace"
            try:
                trace_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                trace_file = None
        cmd = [
            sys.executable,
            "-m",
            "exodus.tools.analyze.clang_worker",
        ]

        def _run_worker(
            parse_only: bool = False,
        ) -> Optional[subprocess.CompletedProcess[str]]:
            env = os.environ.copy()
            if parse_only:
                env["EXODUS_CLANG_PARSE_ONLY"] = "1"
            else:
                env.pop("EXODUS_CLANG_PARSE_ONLY", None)
            if trace_file is not None:
                env["EXODUS_CLANG_TRACE_FILE"] = str(trace_file)
            try:
                return subprocess.run(
                    cmd,
                    input=json.dumps(payload, default=str),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                note = (
                    "worker timeout after 30s (parse-only retry)"
                    if parse_only
                    else "worker timeout after 30s"
                )
                self._write_clang_debug(
                    source_file=source_file,
                    args=args,
                    status="timeout",
                    note=note,
                )
                self.logger.error(
                    "Clang worker timed out for %s after 30s; skipping clang for this file.",
                    source_file,
                )
                return None

        proc = _run_worker(parse_only=False)
        if proc is None:
            return

        if proc.returncode < 0:
            self.logger.warning(
                "Clang worker crashed for %s (exit=%d). Retrying once in parse-only mode.",
                source_file,
                proc.returncode,
            )
            self._write_clang_debug(
                source_file=source_file,
                args=args,
                status="retry-parse-only",
                exit_code=proc.returncode,
                stderr=(proc.stderr or "").strip(),
                note="worker crashed; retry with EXODUS_CLANG_PARSE_ONLY=1",
            )
            retry_proc = _run_worker(parse_only=True)
            if retry_proc is None:
                return
            if retry_proc.returncode == 0:
                self._write_clang_debug(
                    source_file=source_file,
                    args=args,
                    status="ok-parse-only",
                    exit_code=retry_proc.returncode,
                    note="parse-only retry succeeded; AST heuristic violations skipped for this file",
                )
                self.logger.warning(
                    "Clang parse-only fallback succeeded for %s; AST heuristic checks skipped for this file.",
                    source_file,
                )
                return
            proc = retry_proc

        if proc.returncode != 0:
            self._write_clang_debug(
                source_file=source_file,
                args=args,
                status="failed",
                exit_code=proc.returncode,
                stderr=(proc.stderr or "").strip(),
            )
            self.logger.error(
                "Clang worker failed for %s (exit=%d). stderr: %s",
                source_file,
                proc.returncode,
                (proc.stderr or "").strip(),
            )
            return
        self._write_clang_debug(
            source_file=source_file,
            args=args,
            status="ok",
            exit_code=proc.returncode,
        )

        try:
            response = json.loads(proc.stdout or "{}")
        except Exception as exc:
            self.logger.error(
                "Failed to parse clang worker response for %s: %s",
                source_file,
                exc,
            )
            return

        raw_violations = response.get("violations", []) or []
        worker_violations: List[Violation] = []
        for raw in raw_violations:
            v_file = raw.get("file")
            worker_violations.append(
                Violation(
                    raw.get("rule", "Rule ?"),
                    raw.get("message", ""),
                    Path(v_file) if v_file else None,
                    int(raw.get("line", 0)),
                    detector=raw.get("detector", "clang-heuristic"),
                    trigger=raw.get("trigger", ""),
                )
            )
        self._record_violations(
            self._tag_violations(worker_violations, "clang-heuristic")
        )

        identifiers = response.get("identifiers", {}) or {}
        for name, entries in identifiers.items():
            for entry in entries:
                self.global_db.add(
                    name,
                    entry.get("file", ""),
                    int(entry.get("line", 0)),
                    entry.get("linkage", "None"),
                    entry.get("category", "ordinary"),
                )

        ext_objects = response.get("ext_objects", {}) or {}
        for name, rec in ext_objects.items():
            for decl in rec.get("decls", []) or []:
                self.global_db.update_ext(name, decl, False, None)
            for defn in rec.get("defns", []) or []:
                self.global_db.update_ext(name, defn, True, None)
            for user in rec.get("tu_users", []) or []:
                self.global_db.update_ext(name, None, False, user)
            for sig in rec.get("signatures", []) or []:
                self.global_db.add_decl_signature(
                    name,
                    sig.get("file", ""),
                    int(sig.get("line", 0)),
                    sig.get("ret", ""),
                    sig.get("params", []) or [],
                )

    def _analyze_file(
        self,
        source_file: Path,
        lang_c: tree_sitter.Language,
        lang_cpp: tree_sitter.Language,
        config: ProjectConfig,
    ) -> None:
        """Analyzes a single file using both Tree-Sitter and Clang."""
        is_c = source_file.suffix in C_EXTENSIONS
        is_cpp = source_file.suffix in CPP_EXTENSIONS
        if not is_c and not is_cpp:
            return

        language = lang_c if is_c else lang_cpp
        self.logger.info("Analyzing file: %s", source_file)

        if HAS_TREE_SITTER:
            try:
                self._analyze_with_tree_sitter(source_file, language, config)
            except Exception as exc:
                self.logger.error(
                    "Tree-sitter failed to analyze %s: %s", source_file, exc
                )
        self.logger.info("Finished file: %s", source_file)

    def _scan_header_rule_3_1_1_with_clang(
        self, header: Path, config: ProjectConfig
    ) -> List[Violation]:
        if not HAS_CLANG:
            return []
        violations: List[Violation] = []
        try:
            idx = clang.cindex.Index.create()
            args = self._build_clang_args(config, is_cpp=True) + [
                "-x",
                "c++-header",
            ]
            tu = idx.parse(
                str(header),
                args=args,
                options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
        except Exception:
            return []

        header_resolved = header.resolve()
        for cursor in tu.cursor.walk_preorder():
            try:
                loc = cursor.location
                if not loc.file:
                    continue
                if Path(loc.file.name).resolve() != header_resolved:
                    continue
                parent = cursor.semantic_parent
                if not parent or parent.kind not in (
                    clang.cindex.CursorKind.TRANSLATION_UNIT,
                    clang.cindex.CursorKind.NAMESPACE,
                ):
                    continue

                if (
                    cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL
                    and cursor.is_definition()
                ):
                    token_text = {t.spelling for t in cursor.get_tokens()}
                    if "inline" in token_text or "constexpr" in token_text:
                        continue
                    if cursor.storage_class in (
                        clang.cindex.StorageClass.STATIC,
                        clang.cindex.StorageClass.EXTERN,
                    ):
                        continue
                    violations.append(
                        Violation(
                            "Rule 3-1-1",
                            "Header contains a non-inline function definition that may violate ODR when included in multiple translation units.",
                            header,
                            int(loc.line),
                            detector="header-clang-heuristic",
                            trigger=cursor.spelling or "",
                        )
                    )
                elif (
                    cursor.kind == clang.cindex.CursorKind.VAR_DECL
                    and cursor.is_definition()
                ):
                    token_text = {t.spelling for t in cursor.get_tokens()}
                    if {"inline", "constexpr", "constinit"} & token_text:
                        continue
                    if cursor.storage_class in (
                        clang.cindex.StorageClass.STATIC,
                        clang.cindex.StorageClass.EXTERN,
                    ):
                        continue
                    violations.append(
                        Violation(
                            "Rule 3-1-1",
                            "Header contains a namespace-scope object definition that may violate ODR when included in multiple translation units.",
                            header,
                            int(loc.line),
                            detector="header-clang-heuristic",
                            trigger=cursor.spelling or "",
                        )
                    )
            except Exception:
                continue
        return violations

    def _record_cpp_general_rules(
        self, config: ProjectConfig, source_files: List[Path]
    ) -> None:
        if self.misra_profile and self.misra_profile.key not in {
            "cpp2008",
            "cpp2023",
        }:
            return

        has_cpp = any(src.suffix in CPP_EXTENSIONS for src in source_files)
        if not has_cpp:
            return

        # Rule 1-0-2: Multiple compilers shall only be used if they have a common, defined interface.
        if (
            config.compiler.additional_compilers
            and not config.compiler.common_interface_defined
        ):
            self._record_violations(
                [
                    Violation(
                        "Rule 1-0-2",
                        (
                            "Multiple compilers are configured without a defined common interface "
                            f"(primary='{config.compiler.name}', additional={config.compiler.additional_compilers})."
                        ),
                        None,
                        0,
                        detector="project-config",
                        trigger=config.compiler.name,
                    )
                ]
            )

        # Rule 1-0-3: Integer division behavior shall be documented and taken into account.
        if not config.compiler.integer_division_documented:
            self._record_violations(
                [
                    Violation(
                        "Rule 1-0-3",
                        (
                            "Integer division behavior for the selected compiler/toolchain is not documented "
                            "in project configuration (compiler.integer_division_documented=false)."
                        ),
                        None,
                        0,
                        detector="project-config",
                        trigger=config.compiler.name,
                    )
                ]
            )

        # Rule 3-1-1: headers should be safely includable in multiple TUs without ODR violations.
        # Restrict scan to practical project include roots instead of the whole tree,
        # otherwise vendored tests/third-party fixtures dominate results.
        header_suffixes = {".h", ".hh", ".hpp", ".hxx"}
        source_root = config.source_root.resolve()
        preferred_roots = [source_root / "include", source_root / "src"]
        scan_roots: List[Path] = []
        seen_roots: Set[Path] = set()

        def _add_scan_root(root: Path) -> None:
            try:
                resolved = root.resolve()
            except Exception:
                return
            if not resolved.exists() or not resolved.is_dir():
                return
            try:
                resolved.relative_to(source_root)
            except ValueError:
                return
            if resolved in seen_roots:
                return
            seen_roots.add(resolved)
            scan_roots.append(resolved)

        has_preferred = any(p.exists() and p.is_dir() for p in preferred_roots)
        for inc in config.search_paths:
            candidate = (config.source_root / inc).resolve()
            # If common include roots exist, avoid broad "." scan by default.
            if has_preferred and candidate == source_root:
                continue
            _add_scan_root(candidate)
        for root in preferred_roots:
            _add_scan_root(root)
        if not scan_roots:
            _add_scan_root(source_root)

        header_files: List[Path] = []
        seen_headers: Set[Path] = set()
        for root in scan_roots:
            for p in root.rglob("*"):
                if not p.is_file() or p.suffix.lower() not in header_suffixes:
                    continue
                if p in seen_headers:
                    continue
                seen_headers.add(p)
                header_files.append(p)
        header_violations: List[Violation] = []
        func_def_re = re.compile(
            r"^\s*(?!inline\b)(?!static\b)(?:[\w:<>]+\s+)+\w+\s*\([^;]*\)\s*\{"
        )
        global_def_re = re.compile(
            r"^\s*(?!extern\b)(?!static\b)(?!constexpr\b)(?:unsigned\s+|signed\s+)?(?:short|int|long|float|double|char|wchar_t|bool)\s+\w+\s*="
        )
        class_decl_start_re = re.compile(r"^\s*(class|struct)\b")
        class_decl_with_open_re = re.compile(r"^\s*(class|struct)\b[^;{]*\{")
        need_rule_3_1_1 = self._rule_is_selected("Rule 3-1-1")
        use_clang_for_3_1_1 = bool(
            self.enable_clang and HAS_CLANG and need_rule_3_1_1
        )
        for header in header_files:
            try:
                text = header.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if use_clang_for_3_1_1:
                header_violations.extend(
                    self._scan_header_rule_3_1_1_with_clang(header, config)
                )
            brace_depth = 0
            class_depth = 0
            function_depth = 0
            pending_class_decl = False
            for line_no, line in enumerate(text.splitlines(), start=1):
                line_no_comment = line.split("//", 1)[0]
                stripped = line_no_comment.strip()
                class_opens_here = bool(
                    class_decl_with_open_re.search(line_no_comment)
                )
                if not class_opens_here and class_decl_start_re.search(
                    line_no_comment
                ):
                    # Multi-line class/struct declaration where '{' appears later.
                    if (
                        "{" not in line_no_comment
                        and ";" not in line_no_comment
                    ):
                        pending_class_decl = True
                if pending_class_decl and "{" in line_no_comment:
                    class_opens_here = True
                    pending_class_decl = False

                function_opens_here = False
                if (
                    not use_clang_for_3_1_1
                    and class_depth == 0
                    and function_depth == 0
                    and func_def_re.search(line_no_comment)
                ):
                    function_opens_here = True
                    header_violations.append(
                        Violation(
                            "Rule 3-1-1",
                            "Header contains a non-inline function definition that may violate ODR when included in multiple translation units.",
                            header,
                            line_no,
                            detector="header-scan-heuristic",
                            trigger=stripped or line_no_comment.strip(),
                        )
                    )
                elif (
                    not use_clang_for_3_1_1
                    and class_depth == 0
                    and function_depth == 0
                    and global_def_re.search(line_no_comment)
                ):
                    header_violations.append(
                        Violation(
                            "Rule 3-1-1",
                            "Header contains a namespace-scope object definition that may violate ODR when included in multiple translation units.",
                            header,
                            line_no,
                            detector="header-scan-heuristic",
                            trigger=stripped or line_no_comment.strip(),
                        )
                    )
                if re.match(r"^\s*namespace\s*\{", line_no_comment):
                    header_violations.append(
                        Violation(
                            "Rule 7-3-3",
                            "There shall be no unnamed namespaces in header files.",
                            header,
                            line_no,
                            detector="header-scan-heuristic",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if brace_depth == 0 and (
                    re.match(r"^\s*using\s+namespace\b", line_no_comment)
                    or re.match(
                        r"^\s*using\s+[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+\s*;",
                        line_no_comment,
                    )
                ):
                    header_violations.append(
                        Violation(
                            "Rule 7-3-6",
                            "using-directives and using-declarations shall not be used in header files outside class/function scope.",
                            header,
                            line_no,
                            detector="header-scan-heuristic",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if stripped:
                    brace_delta = line_no_comment.count(
                        "{"
                    ) - line_no_comment.count("}")
                    brace_depth += brace_delta
                    if class_opens_here and brace_delta > 0:
                        class_depth += brace_delta
                    elif class_depth > 0 and brace_delta != 0:
                        class_depth = max(0, class_depth + brace_delta)
                    if function_opens_here and brace_delta > 0:
                        function_depth += brace_delta
                    elif function_depth > 0 and brace_delta != 0:
                        function_depth = max(0, function_depth + brace_delta)
        if header_violations:
            self._record_violations(header_violations)

    def _get_max_workers(self) -> Optional[int]:
        jobs = getattr(self.args, "jobs", None)
        if jobs and jobs > 0:
            return cast(int, jobs)
        return None

    def run(self) -> int:
        """Executes the analyze command."""
        self.logger.info("Starting analysis...")

        project = Project.load(Path.cwd())
        self.project_config = project.config
        if not HAS_CLANG:
            self.logger.info(
                "Configure libclang via project config "
                "'clang_library_file', the EXODUS_LIBCLANG environment "
                "variable, or by fetching the referenced artifact with "
                "'exodus pkg install'."
            )
            self.logger.fatal(
                "MISRA analysis requires the Python clang bindings, "
                "but 'clang.cindex' is not importable."
            )
            return 2
        resolved_libclang = self._resolved_project_libclang(project.config)
        if resolved_libclang is None:
            return self._abort_for_missing_clang(project.config)
        if HAS_CLANG:
            try:
                clang.cindex.Config.set_library_file(str(resolved_libclang))
            except Exception:
                return self._abort_for_missing_clang(project.config)
        self.misra_profile = self._resolve_misra_profile(project.config)
        if self.debug_clang:
            project_name = (
                project.config.name or project.root.name or "project"
            )
            self.clang_debug_file = (
                Path("out") / "analyze" / project_name / "clang_debug.jsonl"
            )
            try:
                self.clang_debug_file.parent.mkdir(parents=True, exist_ok=True)
                self.clang_debug_file.write_text("", encoding="utf-8")
            except Exception:
                self.clang_debug_file = None
        self.logger.info(
            "Using MISRA profile: %s (%s, %s)",
            self.misra_profile.key,
            self.misra_profile.standard,
            self.misra_profile.status,
        )
        if self.single_rules:
            selected = ", ".join(sorted(self.single_rules))
            self.logger.info(
                "Rule filter enabled (--single-rules): %s", selected
            )
        if self.debug_clang and self.clang_debug_file is not None:
            self.logger.info("Clang debug log: %s", self.clang_debug_file)

        if not HAS_TREE_SITTER:
            self.logger.error(
                "Tree-sitter is not installed. Analysis features are disabled."
            )
            self._record_violations(
                [
                    Violation(
                        "Global",
                        "Tree-sitter dependencies are missing.",
                        None,
                        trigger="tree-sitter",
                    )
                ]
            )
            self.print_violations()
            return 1

        lang_c = tree_sitter.Language(tree_sitter_c.language())
        lang_cpp = tree_sitter.Language(tree_sitter_cpp.language())
        source_files = self._collect_source_files(project.config)
        filtered_source_files = [
            src for src in source_files if self._profile_accepts_file(src)
        ]
        skipped_files = len(source_files) - len(filtered_source_files)
        if skipped_files:
            self.logger.info(
                "Skipping %d files due to MISRA profile language scope (%s).",
                skipped_files,
                self.misra_profile.key if self.misra_profile else "unknown",
            )
        source_files = filtered_source_files
        self._load_compile_commands_for_sources(source_files)

        if not source_files:
            self.logger.warning("No source files found for analysis.")
            return 0

        max_workers = self._get_max_workers()
        worker_count = max_workers if max_workers is not None else "auto"
        self.logger.info(
            "Found %d source files. Starting workers=%s",
            len(source_files),
            worker_count,
        )
        if not self.enable_clang:
            self.logger.warning(
                "Clang analysis disabled (--no-clang). Running tree-sitter-only."
            )
        interrupted = False
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        )
        futures = {}
        try:
            futures = {
                executor.submit(
                    self._analyze_file, src, lang_c, lang_cpp, project.config
                ): src
                for src in source_files
            }
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                src = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.logger.error(
                        "Analysis generated an exception for %s: %s", src, exc
                    )
                completed += 1
                self.logger.info(
                    "Progress: %d/%d files analyzed",
                    completed,
                    len(source_files),
                )
        except KeyboardInterrupt:
            interrupted = True
            self.logger.warning(
                "Analysis interrupted by user. Cancelling pending tasks..."
            )
            for future in futures:
                future.cancel()
            # Do not block on already running tasks when user interrupted.
            executor.shutdown(wait=False, cancel_futures=True)
            return 130
        finally:
            if not interrupted:
                executor.shutdown(wait=True)

        if self.enable_clang:
            self.logger.info(
                "Starting clang pass in main routine over %d files...",
                len(source_files),
            )
            clang_done = 0
            for src in source_files:
                is_cpp = src.suffix in CPP_EXTENSIONS
                try:
                    with self.clang_lock:
                        self._analyze_with_clang_subprocess(
                            src, is_cpp=is_cpp, config=project.config
                        )
                except Exception as exc:
                    self.logger.error(
                        "Clang failed to analyze %s: %s", src, exc
                    )
                    self.logger.error(traceback.format_exc())
                clang_done += 1
                self.logger.info(
                    "Clang progress: %d/%d files analyzed",
                    clang_done,
                    len(source_files),
                )

        self._record_cpp_general_rules(project.config, source_files)
        self._record_violations(
            self._tag_violations(
                self.global_db.analyze(), "cross-tu-heuristic"
            )
        )
        if self.misra_profile and self.misra_profile.key in {
            "cpp2008",
            "cpp2023",
        }:
            has_odr_signal = any(
                v.rule in {"Rule 3-2-1", "Rule 3-2-3", "Rule 3-2-4"}
                for v in self.violations
            )
            has_odr_violation = any(
                v.rule == "Rule 3-2-2" for v in self.violations
            )
            if has_odr_signal and not has_odr_violation:
                self._record_violations(
                    [
                        Violation(
                            "Rule 3-2-2",
                            "One Definition Rule (ODR) appears to be violated based on declaration/definition inconsistencies.",
                            None,
                            0,
                            detector="cross-tu-derived",
                            trigger="ODR",
                        )
                    ]
                )
        self._write_per_rule_output(project)
        self._write_per_file_output(project)
        self.print_violations()
        return 1 if self.violations else 0

    def print_violations(self) -> None:
        """Prints all collected violations."""
        if not self.violations:
            self.logger.info("No violations found.")
            return

        self.logger.warning("Found %d violations:", len(self.violations))
        for violation in sorted(
            self.violations,
            key=lambda item: (str(item.file) if item.file else "", item.line),
        ):
            try:
                print(str(violation))
            except BrokenPipeError:
                return

    @staticmethod
    def _rule_file_stem(rule: str) -> str:
        raw = rule.strip()
        if raw.lower().startswith("rule "):
            raw = raw[5:].strip()
        safe = re.sub(r"[^0-9A-Za-z._-]+", "_", raw).strip("._-")
        return safe or "unknown_rule"

    def _write_per_rule_output(self, project: Project) -> None:
        if not getattr(self.args, "per_rule_output", False):
            return
        if not self.violations:
            self.logger.info(
                "Per-rule output enabled, but there are no violations to write."
            )
            return

        project_name = project.config.name or project.root.name or "project"
        out_dir = Path("out") / "analyze" / project_name
        out_dir.mkdir(parents=True, exist_ok=True)
        for old_rule_file in out_dir.glob("*.txt"):
            try:
                old_rule_file.unlink(missing_ok=True)
            except PermissionError:
                self.logger.warning(
                    "Skipping cleanup of read-only per-rule file: %s",
                    old_rule_file,
                )

        grouped: Dict[str, List[Violation]] = defaultdict(list)
        for violation in self.violations:
            grouped[violation.rule].append(violation)

        for rule, items in grouped.items():
            stem = self._rule_file_stem(rule)
            target = out_dir / f"{stem}.txt"
            sorted_items = sorted(
                items,
                key=lambda item: (
                    str(item.file) if item.file else "",
                    int(item.line),
                    item.message or "",
                ),
            )
            try:
                target.write_text(
                    "\n".join(str(item) for item in sorted_items) + "\n",
                    encoding="utf-8",
                )
            except PermissionError:
                self.logger.warning(
                    "Skipping per-rule output write (permission denied): %s",
                    target,
                )

        self.logger.info(
            "Wrote per-rule output for %d rules to: %s",
            len(grouped),
            out_dir,
        )

    @staticmethod
    def _file_output_path(
        out_dir: Path, project_root: Path, violation_file: Optional[Path]
    ) -> Path:
        if violation_file is None:
            return out_dir / "Global.aal"
        try:
            vf = violation_file
            if not vf.is_absolute():
                rel = Path(str(vf))
                # Keep project-relative paths as-is to preserve folder structure.
                if rel.parts and rel.parts[0] != "..":
                    return out_dir / rel.parent / f"{rel.name}.aal"
            # Absolute or escaping path: normalize against project root.
            if not vf.is_absolute():
                vf = (project_root / vf).resolve()
            else:
                vf = vf.resolve()
            rel = vf.relative_to(project_root.resolve())
            parent = out_dir / rel.parent
            filename = f"{rel.name}.aal"
            return parent / filename
        except Exception:
            safe = re.sub(r"[^0-9A-Za-z._-]+", "_", str(violation_file)).strip(
                "._-"
            )
            safe = safe or "unknown_file"
            return out_dir / "external" / f"{safe}.aal"

    def _write_per_file_output(self, project: Project) -> None:
        if not getattr(self.args, "per_file_output", False):
            return
        if not self.violations:
            self.logger.info(
                "Per-file output enabled, but there are no violations to write."
            )
            return

        project_name = project.config.name or project.root.name or "project"
        out_dir = Path("out") / "analyze" / project_name
        out_dir.mkdir(parents=True, exist_ok=True)
        for old_file in out_dir.glob("*.aal"):
            old_file.unlink(missing_ok=True)

        grouped: Dict[Path, List[Violation]] = defaultdict(list)
        for violation in self.violations:
            target = self._file_output_path(
                out_dir, project.root, violation.file
            )
            grouped[target].append(violation)

        for target, items in grouped.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            sorted_items = sorted(
                items,
                key=lambda item: (
                    item.rule or "",
                    int(item.line),
                    item.message or "",
                ),
            )
            target.write_text(
                "\n".join(str(item) for item in sorted_items) + "\n",
                encoding="utf-8",
            )

        self.logger.info(
            "Wrote per-file output for %d files to: %s",
            len(grouped),
            out_dir,
        )
