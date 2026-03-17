"""Extract project configuration from external build systems."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from exodus.core.logger import get_logger
from exodus.models.project import Project

_CMAKE_CONTROL_WORDS = {"PUBLIC", "PRIVATE", "INTERFACE"}


def _extract_cmake_calls(text: str, fn_name: str) -> List[str]:
    calls: List[str] = []
    pattern = re.compile(rf"\b{re.escape(fn_name)}\s*\(", re.IGNORECASE)
    idx = 0
    while True:
        match = pattern.search(text, idx)
        if not match:
            break
        start = match.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth == 0:
            calls.append(text[start : i - 1])
            idx = i
        else:
            break
    return calls


def _detect_project_name(text: str, fallback: str) -> str:
    match = re.search(r"\bproject\s*\(\s*([A-Za-z_]\w*)", text, re.IGNORECASE)
    return match.group(1) if match else fallback


def _parse_options(text: str) -> Dict[str, bool]:
    options: Dict[str, bool] = {}
    for match in re.finditer(
        r"\boption\s*\(\s*([A-Za-z_]\w*)\s+\"[^\"]*\"\s+(ON|OFF)\s*\)",
        text,
        re.IGNORECASE,
    ):
        options[match.group(1)] = match.group(2).upper() == "ON"
    return options


def _parse_set_bool_vars(text: str) -> Dict[str, bool]:
    vars_map: Dict[str, bool] = {}
    for match in re.finditer(
        r"\bset\s*\(\s*([A-Za-z_]\w*)\s+(ON|OFF)\s*\)", text, re.IGNORECASE
    ):
        vars_map[match.group(1)] = match.group(2).upper() == "ON"
    return vars_map


def _parse_simple_set_alias(text: str, bool_map: Dict[str, bool]) -> None:
    for match in re.finditer(
        r"\bset\s*\(\s*([A-Za-z_]\w*)\s+\$<BOOL:\$\{([A-Za-z_]\w*)\}>\s*\)",
        text,
        re.IGNORECASE,
    ):
        dst = match.group(1)
        src = match.group(2)
        if src in bool_map:
            bool_map[dst] = bool_map[src]


def _tokenize_call_body(body: str) -> List[str]:
    body_no_comments = re.sub(r"#.*", "", body)
    return [
        tok.strip()
        for tok in re.split(r"\s+", body_no_comments)
        if tok.strip()
    ]


def _evaluate_expr_token(
    token: str, bool_vars: Dict[str, bool], project_name: str
) -> Optional[str]:
    # $<$<NOT:$<BOOL:${VAR}>>:MACRO>
    m_not_bool = re.match(
        r"^\$<\$<NOT:\$<BOOL:\$\{([A-Za-z_]\w*)\}>>:([^>]+)>$",
        token,
    )
    if m_not_bool:
        var = m_not_bool.group(1)
        macro = m_not_bool.group(2).strip()
        if not bool_vars.get(var, False):
            return macro
        return None

    # $<$<BOOL:${VAR}>:MACRO>
    m_bool = re.match(r"^\$<\$<BOOL:\$\{([A-Za-z_]\w*)\}>:([^>]+)>$", token)
    if m_bool:
        var = m_bool.group(1)
        macro = m_bool.group(2).strip()
        if bool_vars.get(var, False):
            return macro
        return None

    # $<${VAR}:MACRO>
    m_var = re.match(r"^\$<\$\{([A-Za-z_]\w*)\}:([^>]+)>$", token)
    if m_var:
        var = m_var.group(1)
        macro = m_var.group(2).strip()
        if bool_vars.get(var, False):
            return macro
        return None

    # Replace ${PROJECT_NAME}
    if "${PROJECT_NAME}" in token:
        return token.replace("${PROJECT_NAME}", project_name)
    return token


def _parse_macro_definition(
    raw_macro: str,
) -> Optional[Tuple[str, Optional[str]]]:
    macro = raw_macro.strip()
    if not macro or macro in _CMAKE_CONTROL_WORDS:
        return None
    if "${" in macro:
        return None
    if "=" in macro:
        key, value = macro.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            return None
        return key, value
    if re.match(r"^[A-Za-z_]\w*$", macro):
        return macro, None
    return None


def _extract_target_defines(
    text: str, bool_vars: Dict[str, bool], project_name: str
) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    for call_body in _extract_cmake_calls(text, "target_compile_definitions"):
        for token in _tokenize_call_body(call_body):
            if token in _CMAKE_CONTROL_WORDS:
                continue
            materialized = _evaluate_expr_token(token, bool_vars, project_name)
            if not materialized:
                continue
            parsed = _parse_macro_definition(materialized)
            if not parsed:
                continue
            key, value = parsed
            out[key] = value
    return out


def _extract_include_dirs(text: str) -> List[Path]:
    dirs: List[Path] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"\$<BUILD_INTERFACE:\$\{PROJECT_SOURCE_DIR\}/([^>]+)>", text
    ):
        rel = match.group(1).strip().strip("/")
        if rel and rel not in seen:
            dirs.append(Path(rel))
            seen.add(rel)
    return dirs


def _extract_cxx_standard(text: str) -> Optional[str]:
    match = re.search(r"\bCXX_STANDARD\s+(\d+)", text)
    if match:
        return match.group(1)
    return None


def _guess_source_patterns(root: Path) -> List[str]:
    if (root / "src").exists():
        cpp_files = list((root / "src").rglob("*.cpp"))
        c_files = list((root / "src").rglob("*.c"))
        patterns: List[str] = []
        if cpp_files:
            patterns.append("src/**/*.cpp")
        if c_files:
            patterns.append("src/**/*.c")
        if patterns:
            return patterns
    return ["**/*.c", "**/*.cpp", "**/*.cc"]


class ExtractTool:
    """Extract exodus.json data from CMake projects."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    def _resolve_extract_type(self) -> str:
        for part in getattr(self.args, "spec", []) or []:
            if part.lower().startswith("type="):
                return str(part.split("=", 1)[1]).strip().lower()
        explicit = getattr(self.args, "type", None)
        if explicit:
            return str(explicit).strip().lower()
        return "cmake"

    def _extract_from_cmake(self) -> int:
        root = Path.cwd()
        cmake_file = Path(getattr(self.args, "cmake_file", "CMakeLists.txt"))
        if not cmake_file.is_absolute():
            cmake_file = root / cmake_file
        if not cmake_file.exists():
            self.logger.error("CMake file not found: %s", cmake_file)
            return 1

        text = cmake_file.read_text(encoding="utf-8", errors="ignore")
        project = Project.load(root)
        project_name = _detect_project_name(
            text, project.config.name or root.name
        )

        bool_vars = _parse_options(text)
        bool_vars.update(_parse_set_bool_vars(text))
        _parse_simple_set_alias(text, bool_vars)

        defines = _extract_target_defines(text, bool_vars, project_name)
        include_dirs = _extract_include_dirs(text)
        cxx_standard = _extract_cxx_standard(text)
        source_patterns = _guess_source_patterns(root)

        project.config.name = project_name
        if cxx_standard and not project.config.compiler.lang_standard:
            project.config.compiler.lang_standard = cxx_standard

        for src_pattern in source_patterns:
            if src_pattern not in project.config.sources:
                project.config.sources.append(src_pattern)

        for inc in include_dirs:
            if inc not in project.config.search_paths:
                project.config.search_paths.append(inc)

        for key, value in defines.items():
            if key not in project.config.defines:
                project.config.defines[key] = value

        project.save(root)
        self.logger.info(
            "Extracted CMake config into exodus.json (defines +%d, include_paths +%d, source_patterns +%d).",
            len(defines),
            len(include_dirs),
            len(source_patterns),
        )
        return 0

    def run(self) -> int:
        extract_type = self._resolve_extract_type()
        if extract_type != "cmake":
            self.logger.error("Unsupported extract type: %s", extract_type)
            return 1
        return self._extract_from_cmake()
