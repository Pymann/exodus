import re
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, cast

from exodus.tools.analyze.misra_rules import Violation

CPP2023_ONLY_FALLBACK_RULES = {
    "Rule 13.1.1",
    "Rule 13.1.2",
    "Rule 13.3.1",
    "Rule 13.3.2",
    "Rule 14.1.1",
    "Rule 15.0.1",
    "Rule 15.0.2",
    "Rule 15.1.1",
    "Rule 15.1.2",
    "Rule 15.1.4",
    "Rule 15.1.5",
    "Rule 17.8.1",
    "Rule 18.3.3",
}


def _strip_line_comment(line: str) -> str:
    return line.split("//", 1)[0]


def _count_brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def _is_standalone_terminator_statement(line: str) -> bool:
    stripped = _strip_line_comment(line).strip()
    if not stripped:
        return False
    if not re.fullmatch(r"(return|throw|goto)\b[^;]*;\s*", stripped):
        return False
    # Avoid single-line guarded statements like `if (x) return;`.
    if re.search(r"\b(if|else|for|while|switch|case|default|catch)\b", stripped):
        return False
    return True


def _is_reachable_transition_line(line: str) -> bool:
    stripped = _strip_line_comment(line).strip()
    if not stripped:
        return True
    if stripped in {"{", "}", ";"}:
        return True
    if stripped.startswith(("else", "catch", "case ", "default", "#")):
        return True
    if stripped.endswith(":"):
        return True
    return False


def _find_unreachable_statement_lines(lines: List[str]) -> List[int]:
    unreachable: List[int] = []
    brace_depth = 0
    pending_terminator_depth: Optional[int] = None
    for idx, raw in enumerate(lines, start=1):
        code = _strip_line_comment(raw)
        stripped = code.strip()
        opens = code.count("{")
        closes = code.count("}")
        effective_depth = brace_depth - closes
        if effective_depth < 0:
            effective_depth = 0

        if pending_terminator_depth is not None:
            if (
                stripped
                and effective_depth == pending_terminator_depth
                and not _is_reachable_transition_line(raw)
            ):
                unreachable.append(idx)
            pending_terminator_depth = None

        if _is_standalone_terminator_statement(raw):
            pending_terminator_depth = effective_depth

        brace_depth += opens - closes
        if brace_depth < 0:
            brace_depth = 0
    return unreachable


def run_fallback_source_scans(
    file_path: Path, is_cpp_file: bool, profile_key: Optional[str] = None
) -> List[Violation]:
    violations: List[Violation] = []
    seen: Set[Tuple[str, str, int, str, str]] = set()
    cpp_stdlib_reserved_macro_or_name = {
        "NULL",
        "EOF",
        "errno",
        "va_start",
        "va_end",
        "va_arg",
        "va_copy",
        "abort",
        "exit",
        "getenv",
        "system",
        "atof",
        "atoi",
        "atol",
        "atoll",
        "malloc",
        "calloc",
        "realloc",
        "free",
        "bsearch",
        "qsort",
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "scanf",
        "fscanf",
        "sscanf",
        "fopen",
        "fclose",
        "fread",
        "fwrite",
        "time",
        "clock",
        "signal",
        "raise",
        "setjmp",
        "longjmp",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strlen",
        "strcmp",
    }
    try:
        source_text = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = source_text.splitlines()
        if not is_cpp_file:
            # Rule 9.1 (C heuristic): local object read in initializer before any assignment.
            # Keep this narrow to avoid noisy flow-sensitive guesses.
            decl_re = re.compile(
                r"^\s*(?:unsigned|signed|short|long|int|char|float|double|_Bool|size_t|int\d+_t|uint\d+_t)\s+([A-Za-z_]\w*)\s*;\s*(?://.*)?$"
            )
            for i, raw in enumerate(lines, start=1):
                m_decl = decl_re.match(raw)
                if not m_decl:
                    continue
                var_name = m_decl.group(1)
                assigned = False
                for j in range(i + 1, min(len(lines), i + 80) + 1):
                    stmt = lines[j - 1].split("//", 1)[0]
                    if re.search(rf"\b{re.escape(var_name)}\s*=", stmt):
                        assigned = True
                        break
                    if re.search(
                        rf"\b[A-Za-z_]\w*\s*=\s*[^;]*\b{re.escape(var_name)}\b",
                        stmt,
                    ):
                        violations.append(
                            Violation(
                                "Rule 9.1",
                                f"variable '{var_name}' is uninitialized when used here",
                                file_path,
                                j,
                                trigger=var_name,
                            )
                        )
                        break
                    if "}" in stmt and assigned:
                        break

            # Rule 17.4 (C heuristic): non-void function appears to miss final return path.
            func_head_re = re.compile(
                r"^\s*(?!static_assert)([A-Za-z_]\w*(?:\s+[*\sA-Za-z_]\w*)*)\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"
            )
            for i, raw in enumerate(lines, start=1):
                m_fn = func_head_re.match(raw)
                if not m_fn:
                    continue
                ret_spec = m_fn.group(1).strip()
                if re.search(r"\bvoid\b", ret_spec):
                    continue
                depth = raw.count("{") - raw.count("}")
                j = i
                body_lines = [raw]
                while depth > 0 and j < len(lines):
                    j += 1
                    ln = lines[j - 1]
                    body_lines.append(ln)
                    depth += ln.count("{") - ln.count("}")
                body_no_comments = [
                    ln.split("//", 1)[0].strip() for ln in body_lines
                ]
                return_lines = [
                    idx
                    for idx, ln in enumerate(body_no_comments, start=i)
                    if re.search(r"\breturn\b", ln)
                ]
                if not return_lines:
                    continue
                last_stmt = ""
                for ln in reversed(body_no_comments):
                    s = ln.strip()
                    if not s or s == "}" or s == "{":
                        continue
                    last_stmt = s
                    break
                if not last_stmt.startswith("return"):
                    violations.append(
                        Violation(
                            "Rule 17.4",
                            "All exit paths from a function with non-void return type shall have an explicit return statement with an expression",
                            file_path,
                            i,
                            trigger=m_fn.group(2),
                        )
                    )

            # Rule 8.13 (C heuristic): non-const pointer parameters that are read
            # but never written should be const-qualified.
            for i, raw in enumerate(lines, start=1):
                m_fn = func_head_re.match(raw)
                if not m_fn:
                    continue
                depth = raw.count("{") - raw.count("}")
                j = i
                body_lines = [raw]
                while depth > 0 and j < len(lines):
                    j += 1
                    ln = lines[j - 1]
                    body_lines.append(ln)
                    depth += ln.count("{") - ln.count("}")
                signature = raw
                for k in range(i + 1, min(j, len(lines)) + 1):
                    if "(" in signature and ")" in signature:
                        break
                    signature += " " + lines[k - 1].strip()
                param_hits = list(
                    re.finditer(
                        r"([^,()]*\*+\s*([A-Za-z_]\w+))",
                        signature,
                    )
                )
                if not param_hits:
                    continue
                body_text = "\n".join(body_lines)
                for ph in param_hits:
                    decl_txt = ph.group(1)
                    p_name = ph.group(2)
                    if re.search(r"\bconst\b", decl_txt):
                        continue
                    has_write = bool(
                        re.search(rf"\*\s*{re.escape(p_name)}\s*=", body_text)
                        or re.search(
                            rf"{re.escape(p_name)}\s*\[[^\]]*\]\s*=", body_text
                        )
                        or re.search(
                            rf"{re.escape(p_name)}\s*->[^;]*=", body_text
                        )
                    )
                    if has_write:
                        continue
                    if re.search(rf"\b{re.escape(p_name)}\b", body_text):
                        violations.append(
                            Violation(
                                "Rule 8.13",
                                f"A pointer should point to a const-qualified type whenever possible: '{p_name}'",
                                file_path,
                                i,
                                trigger=p_name,
                            )
                        )
        cpp2023_virtual_base_types: Set[str] = set()
        cpp2023_ptr_decl_types: Dict[str, str] = {}
        cpp_template_overload_counts: Dict[str, int] = {}
        cpp_explicit_specializations: List[Tuple[int, str]] = []
        cpp_function_templates: Dict[str, int] = {}
        cpp_class_templates: Dict[str, int] = {}
        cpp_template_uses: Set[str] = set()
        cpp_function_specializations: Set[str] = set()
        cpp_primary_templates: Set[str] = set()
        cpp_specializations: List[Tuple[int, str]] = []
        if is_cpp_file:
            pending_explicit_specialization = False
            pending_template_decl = False
            brace_depth_scan = 0
            for lno, raw in enumerate(lines, start=1):
                line = raw.split("//", 1)[0].strip()
                if re.match(r"^\s*namespace\b", line):
                    brace_depth_scan += line.count("{") - line.count("}")
                    continue
                m_tpl_class = re.match(
                    r"^\s*template\s*<[^>]+>\s*(?:class|struct)\s+([A-Za-z_]\w*)\b",
                    line,
                )
                if m_tpl_class:
                    name = m_tpl_class.group(1)
                    cpp_class_templates.setdefault(name, lno)
                    cpp_primary_templates.add(name)
                m_explicit_class_inst = re.match(
                    r"^\s*template\s+(?:class|struct)\s+([A-Za-z_]\w*)\s*<[^>]+>\s*;",
                    line,
                )
                if m_explicit_class_inst:
                    cpp_template_uses.add(m_explicit_class_inst.group(1))
                m_explicit_class_spec = re.match(
                    r"^\s*template\s*<\s*>\s*(?:class|struct)\s+([A-Za-z_]\w*)\s*<[^>]+>\b",
                    line,
                )
                if m_explicit_class_spec:
                    cpp_template_uses.add(m_explicit_class_spec.group(1))
                if re.match(r"^\s*template\s*<[^>]+>\s*$", line):
                    pending_template_decl = True
                    continue
                m_tpl_fn = re.match(
                    r"^\s*template\s*<[^>]+>\s+.*?\b([A-Za-z_]\w*)\s*\(",
                    line,
                )
                if m_tpl_fn:
                    nm = m_tpl_fn.group(1)
                    cpp_template_overload_counts[nm] = (
                        cpp_template_overload_counts.get(nm, 0) + 1
                    )
                    cpp_function_templates.setdefault(nm, lno)
                    cpp_primary_templates.add(nm)
                    # Rule 14-5-1: non-member generic function should be in a namespace (heuristic).
                    if brace_depth_scan == 0:
                        violations.append(
                            Violation(
                                "Rule 14-5-1",
                                "A non-member generic function should be declared in a non-associated namespace.",
                                file_path,
                                lno,
                                trigger=nm,
                            )
                        )
                    pending_template_decl = False
                elif pending_template_decl:
                    m_next_class = re.match(
                        r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)\b", line
                    )
                    if m_next_class:
                        name = m_next_class.group(1)
                        cpp_class_templates.setdefault(name, lno)
                        cpp_primary_templates.add(name)
                    m_next_fn = re.match(r"^\s*.*?\b([A-Za-z_]\w*)\s*\(", line)
                    if m_next_fn:
                        nm = m_next_fn.group(1)
                        cpp_template_overload_counts[nm] = (
                            cpp_template_overload_counts.get(nm, 0) + 1
                        )
                        cpp_function_templates.setdefault(nm, lno)
                        cpp_primary_templates.add(nm)
                        if brace_depth_scan == 0:
                            violations.append(
                                Violation(
                                    "Rule 14-5-1",
                                    "A non-member generic function should be declared in a non-associated namespace.",
                                    file_path,
                                    lno,
                                    trigger=nm,
                                )
                            )
                    pending_template_decl = False
                if re.match(r"^\s*template\s*<\s*>\s*$", line):
                    pending_explicit_specialization = True
                    continue
                m_exp_spec_inline = re.match(
                    r"^\s*template\s*<\s*>\s+.*?\b([A-Za-z_]\w*)\s*<[^>]*>\s*\(",
                    line,
                )
                if m_exp_spec_inline:
                    spec_name = m_exp_spec_inline.group(1)
                    cpp_explicit_specializations.append((lno, spec_name))
                    cpp_function_specializations.add(spec_name)
                    cpp_specializations.append((lno, spec_name))
                    pending_explicit_specialization = False
                    continue
                if pending_explicit_specialization:
                    m_after = re.match(
                        r"^\s*.*?\b([A-Za-z_]\w*)\s*<[^>]*>\s*\(", line
                    )
                    if m_after:
                        spec_name = m_after.group(1)
                        cpp_explicit_specializations.append((lno, spec_name))
                        cpp_function_specializations.add(spec_name)
                        cpp_specializations.append((lno, spec_name))
                    pending_explicit_specialization = False
                m_partial_or_exp_class_spec = re.match(
                    r"^\s*template\s*<[^>]*>\s*(?:class|struct)\s+([A-Za-z_]\w*)\s*<[^>]+>",
                    line,
                )
                if m_partial_or_exp_class_spec and not re.match(
                    r"^\s*template\s*<[^>]+>\s*(?:class|struct)\s+([A-Za-z_]\w*)\s*$",
                    line,
                ):
                    cpp_specializations.append(
                        (lno, m_partial_or_exp_class_spec.group(1))
                    )
                if not line.startswith("template"):
                    for m_use in re.finditer(
                        r"\b([A-Za-z_]\w*)\s*<[^>]+>\s*(?:\(|\w|::)", line
                    ):
                        cpp_template_uses.add(m_use.group(1))
                brace_depth_scan += line.count("{") - line.count("}")
            # Rule 14-5-2 / 14-5-3: class template special member declaration checks (source-scan heuristic).
            class_tpl_re = re.compile(
                r"template\s*<[^>]+>\s*(?:class|struct)\s+([A-Za-z_]\w*)[^;{]*\{([\s\S]*?)\};",
                re.MULTILINE,
            )
            for m_cls in class_tpl_re.finditer(source_text):
                cls_name = m_cls.group(1)
                body = m_cls.group(2)
                class_start_line = source_text[: m_cls.start()].count("\n") + 1

                has_template_ctor = bool(
                    re.search(
                        rf"template\s*<[^>]+>[\s\S]*?\b{re.escape(cls_name)}\s*\(",
                        body,
                    )
                )
                has_copy_ctor_decl = bool(
                    re.search(
                        rf"\b{re.escape(cls_name)}\s*\(\s*const\s+{re.escape(cls_name)}\s*&",
                        body,
                    )
                )
                if has_template_ctor and not has_copy_ctor_decl:
                    violations.append(
                        Violation(
                            "Rule 14-5-2",
                            "A copy constructor shall be declared when there is a template constructor with a single generic parameter.",
                            file_path,
                            class_start_line,
                            trigger=cls_name,
                        )
                    )

                has_template_assign = bool(
                    re.search(
                        r"template\s*<[^>]+>[\s\S]*?\boperator=\s*\(",
                        body,
                    )
                )
                has_copy_assign_decl = bool(
                    re.search(
                        rf"\boperator=\s*\(\s*const\s+{re.escape(cls_name)}\s*&",
                        body,
                    )
                )
                if has_template_assign and not has_copy_assign_decl:
                    violations.append(
                        Violation(
                            "Rule 14-5-3",
                            "A copy assignment operator shall be declared when there is a template assignment operator with a generic parameter.",
                            file_path,
                            class_start_line,
                            trigger=cls_name,
                        )
                    )
            # Rule 14-6-1: dependent-base names should use qualification or this->.
            dep_base_re = re.compile(
                r"template\s*<([^>]+)>\s*(?:class|struct)\s+([A-Za-z_]\w*)\s*:\s*[^{};]*<[^>]+>[^{};]*\{([\s\S]*?)\};",
                re.MULTILINE,
            )
            keywords = {
                "if",
                "for",
                "while",
                "switch",
                "return",
                "sizeof",
                "static_cast",
                "dynamic_cast",
                "reinterpret_cast",
                "const_cast",
                "throw",
            }
            for m_dep in dep_base_re.finditer(source_text):
                body = m_dep.group(3)
                cls_line = source_text[: m_dep.start()].count("\n") + 1
                for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
                    name = cm.group(1)
                    if name in keywords:
                        continue
                    prefix = body[max(0, cm.start() - 8) : cm.start()]
                    if "this->" in prefix or "::" in prefix:
                        continue
                    # Likely unqualified call in dependent-base context.
                    call_line = cls_line + body[: cm.start()].count("\n")
                    violations.append(
                        Violation(
                            "Rule 14-6-1",
                            "In a class template with a dependent base, names from that base should be referenced using qualification or this->.",
                            file_path,
                            call_line,
                            trigger=name,
                        )
                    )
                    break

            # Rule 14.1.1: non-static data members should be either all private or all public.
            class_re = re.compile(
                r"\b(class|struct)\s+([A-Za-z_]\w*)[^;{]*\{([\s\S]*?)\};",
                re.MULTILINE,
            )
            class_bases: Dict[str, List[Tuple[str, bool]]] = {}
            class_lines: Dict[str, int] = {}
            for m_cls in class_re.finditer(source_text):
                kind = m_cls.group(1)
                cls_name = m_cls.group(2)
                body = m_cls.group(3)
                class_line = source_text[: m_cls.start()].count("\n") + 1
                class_lines[cls_name] = class_line
                current_access = "private" if kind == "class" else "public"
                public_data = 0
                private_data = 0
                protected_data = 0
                for raw_member in body.splitlines():
                    member = raw_member.split("//", 1)[0].strip()
                    if not member:
                        continue
                    if member in {"public:", "private:", "protected:"}:
                        current_access = member[:-1]
                        continue
                    if (
                        "static" in member
                        or "(" in member
                        or ")" in member
                        or not member.endswith(";")
                    ):
                        continue
                    if current_access == "public":
                        public_data += 1
                    elif current_access == "private":
                        private_data += 1
                    elif current_access == "protected":
                        protected_data += 1
                if public_data > 0 and (
                    private_data > 0 or protected_data > 0
                ):
                    violations.append(
                        Violation(
                            "Rule 14.1.1",
                            "Non-static data members should be either all private or all public.",
                            file_path,
                            class_line,
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )
                # Rule 15.0.1: special member functions shall be provided appropriately (rule-of-five heuristic).
                has_copy_ctor = bool(
                    re.search(
                        rf"\b{re.escape(cls_name)}\s*\(\s*const\s+{re.escape(cls_name)}\s*&",
                        body,
                    )
                )
                has_move_ctor = bool(
                    re.search(
                        rf"\b{re.escape(cls_name)}\s*\(\s*{re.escape(cls_name)}\s*&&",
                        body,
                    )
                )
                has_copy_assign = bool(
                    re.search(
                        rf"\boperator=\s*\(\s*const\s+{re.escape(cls_name)}\s*&",
                        body,
                    )
                )
                has_move_assign = bool(
                    re.search(
                        rf"\boperator=\s*\(\s*{re.escape(cls_name)}\s*&&",
                        body,
                    )
                )
                has_dtor = bool(
                    re.search(rf"\~\s*{re.escape(cls_name)}\s*\(", body)
                )
                special_count = sum(
                    1
                    for v in [
                        has_copy_ctor,
                        has_move_ctor,
                        has_copy_assign,
                        has_move_assign,
                        has_dtor,
                    ]
                    if v
                )
                if 0 < special_count < 5:
                    violations.append(
                        Violation(
                            "Rule 15.0.1",
                            "Special member functions shall be provided appropriately.",
                            file_path,
                            class_line,
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )
                # Rule 15.0.2: user-provided copy/move member functions should have appropriate signatures.
                bad_copy_ctor = bool(
                    re.search(
                        rf"\b{re.escape(cls_name)}\s*\(\s*{re.escape(cls_name)}\s*&\s*[A-Za-z_]\w*\s*\)",
                        body,
                    )
                )
                bad_move_ctor = bool(
                    re.search(
                        rf"\b{re.escape(cls_name)}\s*\(\s*const\s+{re.escape(cls_name)}\s*&&",
                        body,
                    )
                )
                bad_copy_assign = bool(
                    re.search(
                        rf"\b(?:void|bool|int)\s+operator=\s*\(\s*const\s+{re.escape(cls_name)}\s*&",
                        body,
                    )
                )
                bad_move_assign = bool(
                    re.search(
                        rf"\b(?:void|bool|int)\s+operator=\s*\(\s*{re.escape(cls_name)}\s*&&",
                        body,
                    )
                )
                if (
                    bad_copy_ctor
                    or bad_move_ctor
                    or bad_copy_assign
                    or bad_move_assign
                ):
                    violations.append(
                        Violation(
                            "Rule 15.0.2",
                            "User-provided copy and move member functions of a class should have appropriate signatures.",
                            file_path,
                            class_line,
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )

                # Rule 15.1.1 / 15.1.2 / 15.1.4 (constructor/destructor/member-initialization heuristics).
                ctor_def_re = re.compile(
                    rf"\b{re.escape(cls_name)}\s*\(([^)]*)\)\s*(?::\s*([^\{{;]*))?\s*\{{([\s\S]*?)\}}",
                    re.MULTILINE,
                )
                dtor_def_re = re.compile(
                    rf"\~\s*{re.escape(cls_name)}\s*\(([^)]*)\)\s*\{{([\s\S]*?)\}}",
                    re.MULTILINE,
                )
                data_member_names = []
                for raw_member in body.splitlines():
                    member = raw_member.split("//", 1)[0].strip()
                    if not member or "(" in member or ")" in member:
                        continue
                    if "static" in member or not member.endswith(";"):
                        continue
                    mm_name = re.search(
                        r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;", member
                    )
                    if mm_name:
                        data_member_names.append(mm_name.group(1))
                # Rule 18.3.3: handlers of ctor/dtor function-try-block shall not use non-static members.
                ftry_re = re.compile(
                    rf"(?:{re.escape(cls_name)}\s*\([^)]*\)|~\s*{re.escape(cls_name)}\s*\([^)]*\))\s*try\s*(?::[^\{{}}]*)?\{{[\s\S]*?\}}\s*catch\s*\([^)]*\)\s*\{{([\s\S]*?)\}}",
                    re.MULTILINE,
                )
                for ftry in ftry_re.finditer(body):
                    catch_body = ftry.group(1) or ""
                    if any(
                        re.search(rf"\b{re.escape(m)}\b", catch_body)
                        for m in data_member_names
                    ):
                        violations.append(
                            Violation(
                                "Rule 18.3.3",
                                "Handlers for a function-try-block of a constructor or destructor shall not use non-static members from their class or its bases.",
                                file_path,
                                class_line,
                                detector="clang-fallback-scan",
                                trigger=cls_name,
                            )
                        )
                        break
                class_head = m_cls.group(0).split("{", 1)[0]
                base_names = []
                m_inherit = re.search(r":\s*(.+)$", class_head)
                if m_inherit:
                    for raw_base in m_inherit.group(1).split(","):
                        b = raw_base.strip()
                        if not b:
                            continue
                        b = re.sub(
                            r"\b(public|private|protected|virtual)\b", " ", b
                        )
                        b = re.sub(r"\s+", " ", b).strip()
                        b = re.sub(r"<[^>]*>", "", b).strip()
                        b_name = b.split("::")[-1].strip()
                        if re.match(r"^[A-Za-z_]\w*$", b_name):
                            base_names.append(b_name)
                for ctor_m in ctor_def_re.finditer(body):
                    init_list = (ctor_m.group(2) or "").strip()
                    ctor_body = ctor_m.group(3) or ""
                    # 15.1.1: dynamic type use from ctor/dtor (heuristic: virtual call, typeid(*this), dynamic_cast<...>(this))
                    if (
                        re.search(r"\btypeid\s*\(\s*\*\s*this\s*\)", ctor_body)
                        or re.search(
                            r"\bdynamic_cast\s*<[^>]+>\s*\(\s*this\s*\)",
                            ctor_body,
                        )
                        or re.search(r"\bvirtual_", ctor_body)
                    ):
                        violations.append(
                            Violation(
                                "Rule 15.1.1",
                                "An object's dynamic type shall not be used from within its constructor or destructor.",
                                file_path,
                                class_line,
                                detector="clang-fallback-scan",
                                trigger=cls_name,
                            )
                        )
                    # 15.1.2: all immediate/virtual bases should be explicitly initialized by constructors.
                    if base_names:
                        inits = [
                            x.strip().split("(", 1)[0].strip()
                            for x in init_list.split(",")
                            if x.strip()
                        ]
                        missing_base = [
                            b for b in base_names if b not in inits
                        ]
                        if missing_base:
                            violations.append(
                                Violation(
                                    "Rule 15.1.2",
                                    "All constructors of a class should explicitly initialize all of its virtual base classes and immediate base classes.",
                                    file_path,
                                    class_line,
                                    detector="clang-fallback-scan",
                                    trigger=cls_name,
                                )
                            )
                    # 15.1.4: all direct non-static data members should be initialized before object is accessible.
                    if data_member_names:
                        inits = [
                            x.strip().split("(", 1)[0].strip()
                            for x in init_list.split(",")
                            if x.strip()
                        ]
                        missing_members = [
                            m for m in data_member_names if m not in inits
                        ]
                        if missing_members:
                            violations.append(
                                Violation(
                                    "Rule 15.1.4",
                                    "All direct, non-static data members of a class should be initialized before the class object is accessible.",
                                    file_path,
                                    class_line,
                                    detector="clang-fallback-scan",
                                    trigger=cls_name,
                                )
                            )
                # Rule 15.1.5: initializer-list constructor should be the only constructor.
                ctor_decl_re = re.compile(
                    rf"\b{re.escape(cls_name)}\s*\(([^)]*)\)\s*(?:[:;{{])",
                    re.MULTILINE,
                )
                ctor_params = [
                    m.group(1) or "" for m in ctor_decl_re.finditer(body)
                ]
                il_ctor_count = sum(
                    1 for ptxt in ctor_params if "initializer_list" in ptxt
                )
                if il_ctor_count > 0 and len(ctor_params) > il_ctor_count:
                    violations.append(
                        Violation(
                            "Rule 15.1.5",
                            "A class shall only define an initializer-list constructor when it is the only constructor.",
                            file_path,
                            class_line,
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )

                for dtor_m in dtor_def_re.finditer(body):
                    dtor_body = dtor_m.group(2) or ""
                    if (
                        re.search(r"\btypeid\s*\(\s*\*\s*this\s*\)", dtor_body)
                        or re.search(
                            r"\bdynamic_cast\s*<[^>]+>\s*\(\s*this\s*\)",
                            dtor_body,
                        )
                        or re.search(r"\bvirtual_", dtor_body)
                    ):
                        violations.append(
                            Violation(
                                "Rule 15.1.1",
                                "An object's dynamic type shall not be used from within its constructor or destructor.",
                                file_path,
                                class_line,
                                detector="clang-fallback-scan",
                                trigger=cls_name,
                            )
                        )

            # Collect class inheritance edges for chapter-13 hierarchy checks.
            class_decl_re = re.compile(
                r"\b(?:class|struct)\s+([A-Za-z_]\w*)\s*(?:\:\s*([^{;]+))?\s*\{",
                re.MULTILINE,
            )
            for m_decl in class_decl_re.finditer(source_text):
                cls_name = m_decl.group(1)
                bases_txt = m_decl.group(2) or ""
                bases = []
                if bases_txt.strip():
                    for raw_base in bases_txt.split(","):
                        b = raw_base.strip()
                        if not b:
                            continue
                        is_virtual = "virtual" in b
                        b = re.sub(
                            r"\b(public|private|protected|virtual)\b", " ", b
                        )
                        b = re.sub(r"\s+", " ", b).strip()
                        b = re.sub(r"<[^>]*>", "", b).strip()
                        b_name = b.split("::")[-1].strip()
                        if re.match(r"^[A-Za-z_]\w*$", b_name):
                            bases.append((b_name, is_virtual))
                            if is_virtual:
                                cpp2023_virtual_base_types.add(b_name)
                class_bases[cls_name] = bases

            # Rule 13.1.1: classes should not be inherited virtually.
            for cls_name, edges in class_bases.items():
                if any(is_virtual for _, is_virtual in edges):
                    violations.append(
                        Violation(
                            "Rule 13.1.1",
                            "Classes should not be inherited virtually.",
                            file_path,
                            class_lines.get(cls_name, 1),
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )

            # Rule 13.1.2: a base class shall not be both virtual and non-virtual in the same hierarchy.
            for root in class_bases.keys():
                seen_by_base: Dict[str, Set[bool]] = {}
                stack: List[Tuple[str, bool]] = [(root, False)]
                visited: Set[Tuple[str, bool]] = set()
                while stack:
                    node, path_has_virtual = stack.pop()
                    visit_key = (node, path_has_virtual)
                    if visit_key in visited:
                        continue
                    visited.add(visit_key)
                    for base_name, edge_virtual in class_bases.get(node, []):
                        base_kind = path_has_virtual or edge_virtual
                        seen_by_base.setdefault(base_name, set()).add(
                            base_kind
                        )
                        stack.append((base_name, base_kind))
                if any(
                    kinds == {True, False} for kinds in seen_by_base.values()
                ):
                    violations.append(
                        Violation(
                            "Rule 13.1.2",
                            "An accessible base class shall not be both virtual and non-virtual in the same hierarchy.",
                            file_path,
                            class_lines.get(root, 1),
                            detector="clang-fallback-scan",
                            trigger=root,
                        )
                    )

            # Rule 13.3.1: virtual/override/final should be used appropriately (derived-class heuristic).
            class_methods: Dict[str, Dict[Tuple[str, int], Dict[str, Any]]] = (
                {}
            )
            for m_cls in class_re.finditer(source_text):
                cls_name = m_cls.group(2)
                body = m_cls.group(3)
                class_methods.setdefault(cls_name, {})
                for raw_member in body.splitlines():
                    member = raw_member.split("//", 1)[0].strip()
                    if not member:
                        continue
                    mm = re.search(
                        r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:const\b[^;{]*)?\s*(?:override\b\s*)?(?:final\b\s*)?(?:;|\{)",
                        member,
                    )
                    if mm and "~" not in member:
                        fn_name = mm.group(1)
                        params_txt = mm.group(2).strip()
                        if params_txt and params_txt != "void":
                            raw_params = [
                                p.strip()
                                for p in params_txt.split(",")
                                if p.strip()
                            ]
                        else:
                            raw_params = []
                        defaults = []
                        for rp in raw_params:
                            if "=" in rp:
                                defaults.append(rp.split("=", 1)[1].strip())
                            else:
                                defaults.append(None)
                        class_methods[cls_name][(fn_name, len(raw_params))] = {
                            "is_virtual": ("virtual" in member)
                            or ("override" in member)
                            or ("final" in member),
                            "defaults": tuple(defaults),
                        }
                    if not class_bases.get(cls_name):
                        continue
                    class_line = class_lines.get(cls_name, 1)
                    if "virtual" not in member:
                        continue
                    if "~" in member:
                        continue
                    if "(" not in member or ")" not in member:
                        continue
                    if (
                        "override" in member
                        or "final" in member
                        or "= 0" in member
                    ):
                        continue
                    violations.append(
                        Violation(
                            "Rule 13.3.1",
                            "User-declared member functions shall use the virtual, override and final specifiers appropriately.",
                            file_path,
                            class_line,
                            detector="clang-fallback-scan",
                            trigger=cls_name,
                        )
                    )
                    break

            # Rule 13.3.2: overriding virtual function parameters shall not specify different default arguments.
            for cls_name, methods in class_methods.items():
                if not class_bases.get(cls_name):
                    continue
                class_line = class_lines.get(cls_name, 1)
                # gather virtual methods from all bases in hierarchy
                inherited_virtuals: Dict[Tuple[str, int], Tuple[Any, ...]] = {}
                base_stack: List[str] = [
                    b for b, _ in class_bases.get(cls_name, [])
                ]
                seen_bases: Set[str] = set()
                while base_stack:
                    b = base_stack.pop()
                    if b in seen_bases:
                        continue
                    seen_bases.add(b)
                    for key, meta in class_methods.get(b, {}).items():
                        if meta.get("is_virtual"):
                            inherited_virtuals[key] = meta.get("defaults", ())
                    for bb, _ in class_bases.get(b, []):
                        base_stack.append(bb)
                for key, meta in methods.items():
                    if key not in inherited_virtuals:
                        continue
                    own_defaults = meta.get("defaults", ())
                    base_defaults = inherited_virtuals.get(key, ())
                    if (
                        any(d is not None for d in own_defaults)
                        and own_defaults != base_defaults
                    ):
                        violations.append(
                            Violation(
                                "Rule 13.3.2",
                                "Parameters in an overriding virtual function shall not specify different default arguments.",
                                file_path,
                                class_line,
                                detector="clang-fallback-scan",
                                trigger=str(key),
                            )
                        )
                        break

            # Rule 14-6-2: called function in generic function should depend on generic parameter type.
            fn_tpl_re = re.compile(
                r"template\s*<([^>]+)>\s*([^{;]+?)\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{([\s\S]*?)\}",
                re.MULTILINE,
            )
            for m_fn in fn_tpl_re.finditer(source_text):
                tparams = m_fn.group(1)
                fn_name = m_fn.group(3)
                fn_params = m_fn.group(4)
                body = m_fn.group(5)
                fn_line = source_text[: m_fn.start()].count("\n") + 1
                tnames = set(re.findall(r"\b([A-Za-z_]\w*)\b", tparams))
                if not tnames:
                    continue
                if not any(
                    re.search(rf"\b{re.escape(tn)}\b", fn_params)
                    for tn in tnames
                ):
                    continue
                for call_m in re.finditer(
                    r"\b([A-Za-z_]\w*)\s*\(([^)]*)\)", body
                ):
                    callee = call_m.group(1)
                    args = call_m.group(2)
                    if callee == fn_name:
                        continue
                    if callee in keywords:
                        continue
                    prefix = body[max(0, call_m.start() - 8) : call_m.start()]
                    if "::" in prefix:
                        continue
                    if any(
                        re.search(rf"\b{re.escape(tn)}\b", args)
                        for tn in tnames
                    ):
                        continue
                    call_line = fn_line + body[: call_m.start()].count("\n")
                    violations.append(
                        Violation(
                            "Rule 14-6-2",
                            "The function called by a generic function should depend on the type of a generic parameter.",
                            file_path,
                            call_line,
                            trigger=callee,
                        )
                    )
                    break
        brace_depth = 0
        checked_local_headers: Set[str] = set()
        c_union_depth_stack: List[int] = []
        c_current_fn: Dict[str, Any] | None = None
        c_file_scope_objects: List[Tuple[str, int]] = []
        c_align_specs: Dict[str, List[Tuple[str, int]]] = {}
        c_atomic_aggregate_objects: List[Tuple[str, int]] = []
        c_declared_functions: Set[str] = set()
        c_pointer_variables: Set[str] = set()
        c_defined_macros: Set[str] = set()
        cpp_declared_functions: Set[str] = set()
        c_known_non_calls = {
            "if",
            "for",
            "while",
            "switch",
            "return",
            "sizeof",
            "_Alignof",
            "void",
        }
        c_known_std_calls = {
            "printf",
            "fprintf",
            "sprintf",
            "snprintf",
            "fopen",
            "fclose",
            "fread",
            "fwrite",
            "malloc",
            "free",
            "realloc",
            "calloc",
            "exit",
            "abort",
            "atoi",
            "atol",
            "atoll",
            "bsearch",
            "qsort",
            "strcpy",
            "strcat",
            "strncpy",
            "strncat",
            "strlen",
            "memset",
            "memcmp",
            "memcpy",
            "memmove",
            "strerror",
            "localtime",
            "thrd_join",
            "thrd_detach",
            "thrd_create",
            "mtx_init",
            "mtx_lock",
            "mtx_unlock",
            "mtx_timedlock",
            "mtx_destroy",
            "cnd_init",
            "cnd_wait",
            "cnd_timedwait",
            "cnd_destroy",
            "tss_create",
            "tss_get",
            "tss_set",
            "tss_delete",
        }
        c_errno_setting_functions = {
            "strtol",
            "strtoll",
            "strtoul",
            "strtoull",
            "strtof",
            "strtod",
            "strtold",
        }
        c_errno_used_in_file = bool(re.search(r"\berrno\b", source_text))
        c_errno_reset_since_last_call = False
        c_pending_errno_call: Tuple[str, int] | None = None
        c_const_pointer_functions = {
            "localeconv",
            "getenv",
            "setlocale",
            "strerror",
        }
        c_volatile_pointer_functions = {
            "asctime",
            "ctime",
            "gmtime",
            "localtime",
            "localeconv",
            "getenv",
            "setlocale",
            "strerror",
        }
        c_last_return_ptr_var: Dict[str, Tuple[str, int]] = {}
        c_stale_return_ptr_var: Dict[str, Tuple[str, int]] = {}
        cpp_defined_macros_in_file: Set[str] = set()
        cpp_const_pointer_functions = {
            "localeconv",
            "getenv",
            "setlocale",
            "strerror",
        }
        cpp_volatile_pointer_functions = {
            "asctime",
            "ctime",
            "gmtime",
            "localtime",
            "localeconv",
            "getenv",
            "setlocale",
            "strerror",
        }
        cpp_last_return_ptr_var: Dict[str, Tuple[str, int]] = {}
        cpp_stale_return_ptr_var: Dict[str, Tuple[str, int]] = {}
        cpp2023_incomplete_class_candidates: Set[str] = set()
        cpp2023_ptr_to_incomplete_class: Dict[str, str] = {}
        cpp2023_const_vars: Set[str] = set()
        cpp2023_stream_last_io: Dict[str, str] = {}
        cpp2023_unsized_delete_line = None
        cpp2023_sized_delete_line = None
        cpp2023_pending_template_params: Set[str] | None = None
        cpp2023_forward_ctx: Dict[str, Any] | None = None
        cpp2023_fn_end_depth: int | None = None
        cpp2023_moved_vars: Dict[str, int] = {}
        cpp2023_unscoped_enum_constants: Set[str] = set()
        cpp2023_bool_vars: Set[str] = set()
        cpp2023_float_vars: Set[str] = set()
        cpp2023_void_ptr_vars: Set[str] = set()
        cpp2023_integral_vars: Set[str] = set()
        cpp2023_pointer_vars: Set[str] = set()
        cpp2023_current_fn: Dict[str, Any] | None = None
        cpp2023_switch_ctx: Dict[str, Any] | None = None
        cpp2023_file_scope_static_vars: List[Tuple[str, int]] = []
        cpp2023_file_scope_static_fns: Dict[str, int] = {}
        cpp2023_file_scope_types: Dict[str, int] = {}
        cpp2023_file_scope_external_fns: Dict[str, int] = {}
        cpp2023_file_scope_external_objs: Dict[str, int] = {}
        cpp2023_fn_decl_sigs: Dict[Any, List[Tuple[str, int]]] = {}
        cpp2023_fn_def_sigs: Dict[Any, List[Tuple[str, int]]] = {}
        cpp2023_deleted_ptrs: Dict[str, int] = {}
        cpp2023_labels_in_fn: Dict[str, Tuple[int, int]] = {}
        c_in_block_comment = False
        cpp2023_catch_depth_stack: List[int] = []
        cpp2023_unsigned_vars: Set[str] = set()
        cpp2023_char_vars: Set[str] = set()
        cpp2023_polymorphic_types: Set[str] = set()
        cpp2023_polymorphic_vars: Set[str] = set()
        cpp2023_variadic_functions: Set[str] = set()
        cpp2023_pmf_vars: Set[str] = set()
        cpp2023_param_name_signatures: Dict[
            Tuple[str, int], Tuple[Tuple[str, ...], int]
        ] = {}
        cpp2023_mixed_use_macro_params: Dict[str, Set[int]] = {}
        cpp2023_array_vars: Set[str] = set()
        cpp2023_array_sizes: Dict[str, int] = {}
        cpp2023_ptr_base: Dict[str, str] = {}
        if is_cpp_file and profile_key == "cpp2023":
            forward_declared = set(
                re.findall(
                    r"^\s*class\s+([A-Za-z_]\w*)\s*;\s*$",
                    source_text,
                    flags=re.MULTILINE,
                )
            )
            defined_classes = set(
                re.findall(
                    r"^\s*class\s+([A-Za-z_]\w*)\b[^;]*\{",
                    source_text,
                    flags=re.MULTILINE,
                )
            )
            cpp2023_incomplete_class_candidates = (
                forward_declared - defined_classes
            )
        if not is_cpp_file:
            for raw in lines:
                m_macro = re.match(
                    r"^\s*#\s*define\s+([A-Za-z_]\w*)\b",
                    raw,
                )
                if m_macro:
                    c_defined_macros.add(m_macro.group(1))
                    continue
                line_nc = raw.split("//", 1)[0].strip()
                if not line_nc or line_nc.startswith("#"):
                    continue
                m_decl = re.match(
                    r"^\s*(?:extern\s+)?(?:_Noreturn\s+)?(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*[;{]",
                    line_nc,
                )
                if not m_decl:
                    # Accept declaration wrappers like CJSON_PUBLIC(type) foo(...);
                    m_decl = re.match(
                        r"^\s*(?:(?:[A-Za-z_]\w*)\s*\([^;{}()]*\)\s*)*(?:extern\s+)?(?:_Noreturn\s+)?(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*[;{]",
                        line_nc,
                    )
                if m_decl:
                    c_declared_functions.add(m_decl.group(1))
                # Collect pointer variable names to improve pointer-cast heuristics.
                # Example matches: "int *p;", "char *a, *b;", "const void *ptr = ..."
                if "(" not in line_nc and ")" not in line_nc:
                    for m_ptr in re.finditer(r"\*\s*([A-Za-z_]\w*)", line_nc):
                        c_pointer_variables.add(m_ptr.group(1))
        else:
            for raw in lines:
                line_nc = raw.split("//", 1)[0].strip()
                if not line_nc or line_nc.startswith("#"):
                    continue
                m_cpp_decl = re.match(
                    r"^\s*(?:template\s*<[^>]+>\s*)?(?:inline\s+|static\s+|constexpr\s+|virtual\s+|explicit\s+|friend\s+|extern\s+)?(?:[\w:<>]+\s+)+([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*(?:const\b[^{};]*)?(?:noexcept(?:\s*\([^)]*\))?)?\s*[;{]",
                    line_nc,
                )
                if m_cpp_decl and m_cpp_decl.group(1) not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                    "return",
                }:
                    cpp_declared_functions.add(m_cpp_decl.group(1))

        def _has_include_guard(header_path: Path) -> bool:
            try:
                txt = header_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return True
            if re.search(r"^\s*#\s*pragma\s+once\b", txt, re.MULTILINE):
                return True
            # Basic include-guard shape: #ifndef X / #define X near top + #endif somewhere later.
            ifndef_match = re.search(
                r"^\s*#\s*ifndef\s+([A-Za-z_]\w*)\s*$", txt, re.MULTILINE
            )
            if not ifndef_match:
                return False
            macro = ifndef_match.group(1)
            define_re = re.compile(
                rf"^\s*#\s*define\s+{re.escape(macro)}\b", re.MULTILINE
            )
            endif_re = re.compile(r"^\s*#\s*endif\b", re.MULTILINE)
            return bool(define_re.search(txt) and endif_re.search(txt))

        def _unnamed_namespace_line(header_path: Path) -> Optional[int]:
            try:
                txt = header_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return None
            for lno, raw in enumerate(txt.splitlines(), start=1):
                if re.search(r"\bnamespace\s*\{\s*$", raw.split("//", 1)[0]):
                    return lno
            return None

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                brace_depth += line.count("{") - line.count("}")
                continue
            line_no_comment = line.split("//", 1)[0]
            if is_cpp_file and profile_key == "cpp2023" and brace_depth == 0:
                static_var_decl = re.match(
                    r"^\s*static\b(?![^;{}()]*\()\s+[^;{}()]*\b([A-Za-z_]\w*)\s*(?:=\s*[^;]*)?;",
                    line_no_comment,
                )
                if static_var_decl:
                    cpp2023_file_scope_static_vars.append(
                        (static_var_decl.group(1), idx)
                    )
                static_fn_decl = re.match(
                    r"^\s*static\b[^;{}()]*\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:\{|;)",
                    line_no_comment,
                )
                if static_fn_decl:
                    fn_name = static_fn_decl.group(1)
                    if fn_name not in {"if", "for", "while", "switch"}:
                        cpp2023_file_scope_static_fns.setdefault(fn_name, idx)
                typedef_decl = re.match(
                    r"^\s*typedef\b[^;{}]*\b([A-Za-z_]\w*)\s*;",
                    line_no_comment,
                )
                if typedef_decl:
                    cpp2023_file_scope_types.setdefault(
                        typedef_decl.group(1), idx
                    )
                using_decl = re.match(
                    r"^\s*using\s+([A-Za-z_]\w*)\s*=",
                    line_no_comment,
                )
                if using_decl:
                    cpp2023_file_scope_types.setdefault(
                        using_decl.group(1), idx
                    )
                type_decl = re.match(
                    r"^\s*(?:class|struct|enum(?:\s+class)?)\s+([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if type_decl:
                    cpp2023_file_scope_types.setdefault(
                        type_decl.group(1), idx
                    )
                ext_fn_def = re.match(
                    r"^\s*(?!static\b)(?!inline\b)(?!constexpr\b)(?:[\w:<>~]+\s+)+([A-Za-z_]\w*)\s*\(([^;{}()]*)\)\s*\{",
                    line_no_comment,
                )
                if ext_fn_def:
                    fname = ext_fn_def.group(1)
                    if fname not in {"if", "for", "while", "switch"}:
                        cpp2023_file_scope_external_fns.setdefault(fname, idx)
                        arity = 0
                        params = (ext_fn_def.group(2) or "").strip()
                        if params and params != "void":
                            arity = len(
                                [p for p in params.split(",") if p.strip()]
                            )
                        key = (fname, arity)
                        cpp2023_fn_def_sigs.setdefault(key, []).append(
                            (line_no_comment.strip(), idx)
                        )
                ext_obj_def = re.match(
                    r"^\s*(?!static\b)(?!extern\b)(?!constexpr\b)(?:[\w:<>]+\s+)+([A-Za-z_]\w*)\s*=\s*[^;]+;",
                    line_no_comment,
                )
                if ext_obj_def:
                    cpp2023_file_scope_external_objs.setdefault(
                        ext_obj_def.group(1), idx
                    )
                fn_decl = re.match(
                    r"^\s*(?:[\w:<>~]+\s+)+([A-Za-z_]\w*)\s*\(([^;{}()]*)\)\s*;",
                    line_no_comment,
                )
                if fn_decl:
                    fname = fn_decl.group(1)
                    if fname not in {"if", "for", "while", "switch"}:
                        arity = 0
                        params = (fn_decl.group(2) or "").strip()
                        if params and params != "void":
                            arity = len(
                                [p for p in params.split(",") if p.strip()]
                            )
                        key = (fname, arity)
                        cpp2023_fn_decl_sigs.setdefault(key, []).append(
                            (line_no_comment.strip(), idx)
                        )
            if not is_cpp_file:
                # Rule 17.10 / 17.9: _Noreturn function type and behavior checks (heuristic).
                c_fn_def = re.match(
                    r"^\s*(?P<prefix>[^;{}()]*)\b(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}()]*)\)\s*\{",
                    line_no_comment,
                )
                if c_fn_def:
                    fn_name = c_fn_def.group("name")
                    if fn_name in {"if", "for", "while", "switch"}:
                        c_fn_def = None
                if c_fn_def:
                    prefix = c_fn_def.group("prefix") or ""
                    params = c_fn_def.group("params") or ""
                    param_array_names = set(
                        m.group(1)
                        for m in re.finditer(
                            r"\b([A-Za-z_]\w*)\s*\[\s*\]", params
                        )
                    )
                    c_current_fn = {
                        "end_depth": brace_depth + line_no_comment.count("{"),
                        "param_array_names": param_array_names,
                        "is_noreturn": "_Noreturn" in prefix,
                        "name": fn_name,
                        "array_sizes": {},
                        "atomic_declared": set(),
                        "atomic_initialized": set(),
                        "looks_noreturn": False,
                        "mtx_initialized": set(),
                        "mtx_non_recursive": set(),
                        "mtx_locked": {},
                        "mtx_mode": {},
                        "cnd_initialized": set(),
                        "cnd_assoc": {},
                        "thrd_terminated": set(),
                        "thrd_created": set(),
                        "tss_created": set(),
                    }
                    if "_Noreturn" in prefix and "void" not in prefix:
                        violations.append(
                            Violation(
                                "Rule 17.10",
                                "A function declared with a _Noreturn function specifier shall have void return type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=fn_name,
                            )
                        )
                if c_current_fn:
                    # Track simple local fixed-size arrays for Rule 21.17 bounds checks.
                    arr_decl = re.search(
                        r"\b(?:char|signed\s+char|unsigned\s+char|int8_t|uint8_t)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]",
                        line_no_comment,
                    )
                    if arr_decl:
                        c_current_fn["array_sizes"][arr_decl.group(1)] = int(
                            arr_decl.group(2)
                        )
                    atomic_decl = re.search(
                        r"\b_Atomic\s*(?:\(\s*[A-Za-z_]\w*\s*\)|\s+[A-Za-z_]\w*)\s+([A-Za-z_]\w+)\s*(?:[;=])",
                        line_no_comment,
                    )
                    if atomic_decl:
                        aname = atomic_decl.group(1)
                        c_current_fn["atomic_declared"].add(aname)
                        if "=" in line_no_comment:
                            c_current_fn["atomic_initialized"].add(aname)
                    for aname in list(
                        c_current_fn.get("atomic_declared", set())
                    ):
                        if re.search(
                            rf"\b{re.escape(aname)}\s*=", line_no_comment
                        ):
                            c_current_fn["atomic_initialized"].add(aname)
                    if (
                        re.search(r"\bwhile\s*\(\s*1\s*\)", line_no_comment)
                        or re.search(
                            r"\bfor\s*\(\s*;\s*;\s*\)", line_no_comment
                        )
                        or re.search(r"\b(?:abort|exit)\s*\(", line_no_comment)
                    ):
                        c_current_fn["looks_noreturn"] = True

                    if c_current_fn.get("is_noreturn") and re.search(
                        r"\breturn\b", line_no_comment
                    ):
                        violations.append(
                            Violation(
                                "Rule 17.9",
                                "A function declared with a _Noreturn function specifier shall not return to its caller.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=c_current_fn.get("name", ""),
                            )
                        )
                    for name in c_current_fn.get("param_array_names", set()):
                        if re.search(
                            rf"\bsizeof\s*\(\s*{re.escape(name)}\s*\)",
                            line_no_comment,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 12.5",
                                    "The sizeof operator shall not have an operand which is a function parameter declared as 'array of type'.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=name,
                                )
                            )
                            break
                    # Rule 9.7: atomic objects should be initialized before access (heuristic).
                    m_atomic_load = re.search(
                        r"\batomic_(?:load|fetch_add|fetch_sub|exchange)\s*\(\s*&\s*([A-Za-z_]\w+)",
                        line_no_comment,
                    )
                    if m_atomic_load:
                        aname = m_atomic_load.group(1)
                        if aname in c_current_fn.get(
                            "atomic_declared", set()
                        ) and aname not in c_current_fn.get(
                            "atomic_initialized", set()
                        ):
                            violations.append(
                                Violation(
                                    "Rule 9.7",
                                    "Atomic objects shall be appropriately initialized before being accessed.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=aname,
                                )
                            )
                    # Rule 21.17: string handling shall not access beyond object bounds (heuristic).
                    arr_sizes = c_current_fn.get("array_sizes", {})
                    m_strcpy = re.search(
                        r'\bstrcpy\s*\(\s*([A-Za-z_]\w*)\s*,\s*"([^"]*)"\s*\)',
                        line_no_comment,
                    )
                    if m_strcpy:
                        dst = m_strcpy.group(1)
                        lit = m_strcpy.group(2)
                        if (
                            dst in arr_sizes
                            and (len(lit) + 1) > arr_sizes[dst]
                        ):
                            violations.append(
                                Violation(
                                    "Rule 21.17",
                                    "Use of the string handling functions from <string.h> shall not result in accesses beyond the bounds of the objects referenced by their pointer parameters.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=dst,
                                )
                            )
                    m_memn = re.search(
                        r"\b(?:memcpy|memmove|strncpy|strncat)\s*\(\s*([A-Za-z_]\w*)\s*,\s*[^,]+,\s*(\d+)\s*\)",
                        line_no_comment,
                    )
                    if m_memn:
                        dst = m_memn.group(1)
                        n = int(m_memn.group(2))
                        if dst in arr_sizes and n > arr_sizes[dst]:
                            violations.append(
                                Violation(
                                    "Rule 21.17",
                                    "Use of the string handling functions from <string.h> shall not result in accesses beyond the bounds of the objects referenced by their pointer parameters.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=dst,
                                )
                            )

                    # Rules 22.11/22.14/22.16/22.17/22.18/22.19/22.20 (thread/sync heuristics).
                    mtx_init = re.search(
                        r"\bmtx_init\s*\(\s*&\s*([A-Za-z_]\w*)\s*,\s*([^)]+)\)",
                        line_no_comment,
                    )
                    if mtx_init:
                        m = mtx_init.group(1)
                        mode = mtx_init.group(2)
                        c_current_fn["mtx_initialized"].add(m)
                        c_current_fn["mtx_mode"][m] = mode
                        if "mtx_recursive" not in mode:
                            c_current_fn["mtx_non_recursive"].add(m)
                    cnd_init = re.search(
                        r"\bcnd_init\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)",
                        line_no_comment,
                    )
                    if cnd_init:
                        c_current_fn["cnd_initialized"].add(cnd_init.group(1))
                    tss_create = re.search(
                        r"\btss_create\s*\(\s*&\s*([A-Za-z_]\w*)\s*,",
                        line_no_comment,
                    )
                    if tss_create:
                        c_current_fn["tss_created"].add(tss_create.group(1))
                    thrd_create = re.search(
                        r"\bthrd_create\s*\(\s*&\s*([A-Za-z_]\w*)\s*,",
                        line_no_comment,
                    )
                    if thrd_create:
                        c_current_fn["thrd_created"].add(thrd_create.group(1))

                    mtx_lock = re.search(
                        r"\bmtx_lock\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)",
                        line_no_comment,
                    )
                    if mtx_lock:
                        m = mtx_lock.group(1)
                        if m not in c_current_fn["mtx_initialized"]:
                            violations.append(
                                Violation(
                                    "Rule 22.14",
                                    "Thread synchronization objects shall be initialized before being accessed.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )
                        if (
                            m in c_current_fn["mtx_locked"]
                            and m in c_current_fn["mtx_non_recursive"]
                        ):
                            violations.append(
                                Violation(
                                    "Rule 22.18",
                                    "Non-recursive mutexes shall not be recursively locked.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )
                        c_current_fn["mtx_locked"].setdefault(m, idx)

                    mtx_unlock = re.search(
                        r"\bmtx_unlock\s*\(\s*&\s*([A-Za-z_]\w*)\s*\)",
                        line_no_comment,
                    )
                    if mtx_unlock:
                        m = mtx_unlock.group(1)
                        if m not in c_current_fn["mtx_initialized"]:
                            violations.append(
                                Violation(
                                    "Rule 22.14",
                                    "Thread synchronization objects shall be initialized before being accessed.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )
                        if m not in c_current_fn["mtx_locked"]:
                            violations.append(
                                Violation(
                                    "Rule 22.17",
                                    "No thread shall unlock a mutex or call cnd_wait() or cnd_timedwait() for a mutex it has not locked before.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )
                        else:
                            del c_current_fn["mtx_locked"][m]
                    mtx_timedlock = re.search(
                        r"\bmtx_timedlock\s*\(\s*&\s*([A-Za-z_]\w*)\s*,",
                        line_no_comment,
                    )
                    if mtx_timedlock:
                        m = mtx_timedlock.group(1)
                        mode = c_current_fn["mtx_mode"].get(m, "")
                        if "mtx_timed" not in mode:
                            violations.append(
                                Violation(
                                    "Rule 21.26",
                                    "The Standard Library function mtx_timedlock() shall only be invoked on mutex objects of appropriate mutex type.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )

                    cnd_wait = re.search(
                        r"\bcnd_(?:wait|timedwait)\s*\(\s*&\s*([A-Za-z_]\w*)\s*,\s*&\s*([A-Za-z_]\w*)",
                        line_no_comment,
                    )
                    if cnd_wait:
                        cnd = cnd_wait.group(1)
                        m = cnd_wait.group(2)
                        if (
                            cnd not in c_current_fn["cnd_initialized"]
                            or m not in c_current_fn["mtx_initialized"]
                        ):
                            violations.append(
                                Violation(
                                    "Rule 22.14",
                                    "Thread synchronization objects shall be initialized before being accessed.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=cnd,
                                )
                            )
                        if m not in c_current_fn["mtx_locked"]:
                            violations.append(
                                Violation(
                                    "Rule 22.17",
                                    "No thread shall unlock a mutex or call cnd_wait() or cnd_timedwait() for a mutex it has not locked before.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=m,
                                )
                            )
                        prev_m = c_current_fn["cnd_assoc"].get(cnd)
                        if prev_m is None:
                            c_current_fn["cnd_assoc"][cnd] = m
                        elif prev_m != m:
                            violations.append(
                                Violation(
                                    "Rule 22.19",
                                    "A condition variable shall be associated with at most one mutex object.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=cnd,
                                )
                            )

                    thrd_term = re.search(
                        r"\bthrd_(join|detach)\s*\(\s*([A-Za-z_]\w*)\b",
                        line_no_comment,
                    )
                    if thrd_term:
                        th = thrd_term.group(2)
                        if th not in c_current_fn["thrd_created"]:
                            violations.append(
                                Violation(
                                    "Rule 22.12",
                                    "Thread objects, thread synchronization objects, and thread-specific storage pointers shall only be accessed by the appropriate Standard Library functions.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=th,
                                )
                            )
                        if th in c_current_fn["thrd_terminated"]:
                            violations.append(
                                Violation(
                                    "Rule 22.11",
                                    "A thread that was previously either joined or detached shall not be subsequently joined nor detached.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=th,
                                )
                            )
                        else:
                            c_current_fn["thrd_terminated"].add(th)

                    tss_use = re.search(
                        r"\btss_(?:get|set)\s*\(\s*([A-Za-z_]\w*)\b",
                        line_no_comment,
                    )
                    if (
                        tss_use
                        and tss_use.group(1) not in c_current_fn["tss_created"]
                    ):
                        violations.append(
                            Violation(
                                "Rule 22.20",
                                "Thread-specific storage pointers shall be created before being accessed.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=tss_use.group(1),
                            )
                        )
                    mtx_addr_use = re.search(
                        r"\(\s*void\s*\*\s*\)\s*&\s*(m|c|key)\b",
                        line_no_comment,
                    )
                    if mtx_addr_use:
                        violations.append(
                            Violation(
                                "Rule 22.12",
                                "Thread objects, thread synchronization objects, and thread-specific storage pointers shall only be accessed by the appropriate Standard Library functions.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=mtx_addr_use.group(1),
                            )
                        )
                    if re.search(
                        r"\b(static|extern)\s+(thrd_t|mtx_t|cnd_t|tss_t)\b",
                        line_no_comment,
                    ):
                        violations.append(
                            Violation(
                                "Rule 22.13",
                                "Thread objects, thread synchronization objects and thread-specific storage pointers shall have appropriate storage duration.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                    if re.search(
                        r"\b(mtx_destroy|cnd_destroy|tss_delete)\s*\(",
                        line_no_comment,
                    ):
                        active = c_current_fn.get(
                            "thrd_created", set()
                        ) - c_current_fn.get("thrd_terminated", set())
                        if active:
                            violations.append(
                                Violation(
                                    "Rule 22.15",
                                    "Thread synchronization objects and thread-specific storage pointers shall not be destroyed until after all threads accessing them have terminated.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=",".join(sorted(active)),
                                )
                            )
                # Rule 11.10: _Atomic qualifier shall not be applied to incomplete type void.
                if re.search(
                    r"\b_Atomic\s*\(\s*void\s*\)", line_no_comment
                ) or re.search(r"\b_Atomic\s+void\b", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 11.10",
                            "The _Atomic qualifier shall not be applied to the incomplete type void.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 21.25: memory synchronization operations should be sequentially consistent.
                if (
                    "atomic_" in line_no_comment
                    and "memory_order_" in line_no_comment
                ):
                    if "memory_order_seq_cst" not in line_no_comment:
                        violations.append(
                            Violation(
                                "Rule 21.25",
                                "All memory synchronization operations shall be executed in sequentially consistent order.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                # Rule 23.1 / 23.2: generic selection usage checks (heuristic).
                if "_Generic" in line_no_comment and not re.match(
                    r"^\s*#\s*define\b", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 23.1",
                            "A generic selection should only be expanded from a macro.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                    m_generic = re.search(
                        r"\b_Generic\s*\(\s*([^,]+)\s*,", line_no_comment
                    )
                    if m_generic:
                        ctrl = m_generic.group(1)
                        if re.search(
                            r"(\+\+|--|[^=!<>]=[^=])", ctrl
                        ) or re.search(r"\b[A-Za-z_]\w*\s*\(", ctrl):
                            violations.append(
                                Violation(
                                    "Rule 23.2",
                                    "A generic selection that is not expanded from a macro shall not contain potential side effects in the controlling expression.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=ctrl,
                                )
                            )
                    m_assoc = re.search(
                        r"\b_Generic\s*\(\s*[^,]+,\s*(.+)\)\s*;?\s*$",
                        line_no_comment,
                    )
                    if m_assoc:
                        assoc_text = m_assoc.group(1)
                        assoc_parts = [
                            p.strip()
                            for p in assoc_text.split(",")
                            if ":" in p
                        ]
                        default_pos = [
                            i
                            for i, p in enumerate(assoc_parts)
                            if re.match(r"^\s*default\s*:", p)
                        ]
                        non_default_count = sum(
                            1
                            for p in assoc_parts
                            if not re.match(r"^\s*default\s*:", p)
                        )
                        if non_default_count == 0:
                            violations.append(
                                Violation(
                                    "Rule 23.3",
                                    "A generic selection should contain at least one non-default association.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=assoc_text,
                                )
                            )
                        if default_pos:
                            d = default_pos[0]
                            if d not in {0, len(assoc_parts) - 1}:
                                violations.append(
                                    Violation(
                                        "Rule 23.8",
                                        "A default association shall appear as either the first or the last association of a generic selection.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=assoc_text,
                                    )
                                )
                        # Rule 23.4: generic associations shall list appropriate type.
                        for part in assoc_parts:
                            tname = part.split(":", 1)[0].strip()
                            if tname == "default":
                                continue
                            if "*" in tname and not re.search(
                                r"\b(?:void|char|short|int|long|float|double|_Bool)\s*\*$",
                                tname,
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 23.4",
                                        "A generic association shall list an appropriate type.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=tname,
                                    )
                                )
                                break
                        # Rule 23.5: should not depend on implicit pointer type conversion.
                        if re.search(
                            r"\(\s*(?:char|void)\s*\*\s*\)\s*&?\s*[A-Za-z_]\w*",
                            ctrl,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 23.5",
                                    "A generic selection should not depend on implicit pointer type conversion.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=ctrl,
                                )
                            )
                        # Rule 23.6: controlling expression essential type shall match standard type.
                        if re.search(
                            r"\b(?:int|long|double|float)\s*:", assoc_text
                        ):
                            ctrl_id_match = re.match(
                                r"^\s*([A-Za-z_]\w*)\s*$", ctrl
                            )
                            if ctrl_id_match:
                                ctrl_id = ctrl_id_match.group(1)
                                enum_decl_same_var = re.search(
                                    rf"\benum\s+[A-Za-z_]\w*\s*(?:\{{[^}}]*\}}\s*{re.escape(ctrl_id)}\b|\b{re.escape(ctrl_id)}\b)",
                                    source_text,
                                    re.DOTALL,
                                )
                                if enum_decl_same_var:
                                    violations.append(
                                        Violation(
                                            "Rule 23.6",
                                            "The controlling expression of a generic selection shall have an essential type that matches its standard type.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=ctrl_id,
                                        )
                                    )
                # Rule 18.10 (C:2023): pointers to variably-modified array types shall not be used.
                # Keep this constrained to C:2023 and declaration-like forms to avoid
                # matching normal pointer-index expressions.
                if profile_key == "c2023":
                    vla_ptr_match = re.search(
                        r"^\s*(?:const\s+|volatile\s+|static\s+)*[A-Za-z_]\w*(?:\s+[*A-Za-z_]\w*)*\s+\(\s*\*\s*[A-Za-z_]\w*\s*\)\s*\[\s*([A-Za-z_]\w*)\s*\]",
                        line_no_comment,
                    )
                    if vla_ptr_match:
                        bound = vla_ptr_match.group(1)
                        if not bound.isupper():
                            violations.append(
                                Violation(
                                    "Rule 18.10",
                                    "Pointers to variably-modified array types shall not be used.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=vla_ptr_match.group(0).strip(),
                                )
                            )
                # Rule 6.3: bit-field member shall not be declared in a union.
                if re.search(r"^\s*union\b.*\{", line_no_comment):
                    c_union_depth_stack.append(
                        brace_depth + line_no_comment.count("{")
                    )
                if c_union_depth_stack and re.search(
                    r":\s*\d+\s*[;,]", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 6.3",
                            "A bit field shall not be declared as a member of a union.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 8.16: zero alignment shall not appear.
                if re.search(r"\b_Alignas\s*\(\s*0\s*\)", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 8.16",
                            "The alignment specification of zero should not appear in an object declaration.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 8.17: at most one explicit alignment specifier.
                if len(re.findall(r"\b_Alignas\s*\(", line_no_comment)) > 1:
                    violations.append(
                        Violation(
                            "Rule 8.17",
                            "At most one explicit alignment specifier should appear in an object declaration.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Collect Rule 8.15 alignment declarations.
                align_decl = re.search(
                    r"\b_Alignas\s*\(\s*([^)]+?)\s*\)\s*(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*(?:=|;|\[)",
                    line_no_comment,
                )
                if align_decl:
                    align_val = align_decl.group(1).strip()
                    align_name = align_decl.group(2)
                    c_align_specs.setdefault(align_name, []).append(
                        (align_val, idx)
                    )
                # Collect atomic aggregate objects for Rule 12.6.
                atomic_obj = re.search(
                    r"\b_Atomic\s*\(\s*(?:struct|union)\s+[A-Za-z_]\w*\s*\)\s*([A-Za-z_]\w+)\b",
                    line_no_comment,
                )
                if atomic_obj:
                    c_atomic_aggregate_objects.append(
                        (atomic_obj.group(1), idx)
                    )
                # Collect file-scope object definitions for Rule 2.8 (heuristic).
                if (
                    brace_depth == 0
                    and not line_no_comment.lstrip().startswith("#")
                ):
                    fs_decl = re.match(
                        r"^\s*(?!extern\b)(?!typedef\b)(?!struct\b)(?!union\b)(?!enum\b)(?:_Alignas\s*\([^)]*\)\s*)?(?:const\s+|volatile\s+|static\s+|register\s+|signed\s+|unsigned\s+|short\s+|long\s+)*(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*(?:=\s*[^;]*)?;\s*$",
                        line_no_comment,
                    )
                    if fs_decl:
                        c_file_scope_objects.append((fs_decl.group(1), idx))
                # Rule 8.1: implicit int declaration/definition forms.
                if re.match(
                    r"^\s*extern\s+[A-Za-z_]\w+\s*;\s*$", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 8.1",
                            "Types shall be explicitly specified.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 22.13: thread/sync objects with non-local storage duration (heuristic).
                if re.search(
                    r"^\s*(?:static|extern)\s+(?:thrd_t|mtx_t|cnd_t|tss_t)\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 22.13",
                            "Thread objects, thread synchronization objects and thread-specific storage pointers shall have appropriate storage duration.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.match(
                    r"^\s*extern\s+[A-Za-z_]\w+\s*\([^)]*\)\s*;\s*$",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 8.1",
                            "Types shall be explicitly specified.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 8.12: duplicated value for implicitly-specified enumerator.
                enum_match = re.search(
                    r"\benum\b[^{]*\{([^}]*)\}", line_no_comment
                )
                if enum_match:
                    enum_items = [
                        it.strip()
                        for it in enum_match.group(1).split(",")
                        if it.strip()
                    ]
                    curr_val = -1
                    resolved_vals: List[int | None] = []
                    implicit_flags = []
                    for item in enum_items:
                        name_val = item.split("=", 1)
                        if len(name_val) == 2:
                            rhs = name_val[1].strip()
                            try:
                                curr_val = int(rhs, 0)
                            except Exception:
                                resolved_vals.append(None)
                                implicit_flags.append(False)
                                continue
                            resolved_vals.append(curr_val)
                            implicit_flags.append(False)
                        else:
                            curr_val += 1
                            resolved_vals.append(curr_val)
                            implicit_flags.append(True)
                    for i, val in enumerate(resolved_vals):
                        if not implicit_flags[i] or val is None:
                            continue
                        dup_count = sum(1 for x in resolved_vals if x == val)
                        if dup_count > 1:
                            violations.append(
                                Violation(
                                    "Rule 8.12",
                                    "Within an enumerator list, the value of an implicitly-specified enumeration constant shall be unique.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=str(val),
                                )
                            )
                            break
                # Rule 11.7: cast pointer expression to non-integer arithmetic type.
                cast_to_float = re.search(
                    r"\(\s*(?:float|double|long\s+double|float32_t|float64_t)\s*\)\s*([A-Za-z_]\w*|&\s*[A-Za-z_]\w*)",
                    line_no_comment,
                )
                if cast_to_float:
                    operand = cast_to_float.group(1).replace(" ", "")
                    suffix = line_no_comment[cast_to_float.end(1) :].lstrip()
                    is_pointer_like_operand = False
                    if operand.startswith("&"):
                        is_pointer_like_operand = True
                    elif operand in c_pointer_variables:
                        is_pointer_like_operand = True
                    # Do not treat casts of pointee/member expressions as pointer casts,
                    # e.g. (double)item->valueint or (double)numbers[i].
                    if (
                        suffix.startswith("->")
                        or suffix.startswith(".")
                        or suffix.startswith("[")
                    ):
                        is_pointer_like_operand = False
                    if is_pointer_like_operand:
                        violations.append(
                            Violation(
                                "Rule 11.7",
                                "A cast shall not be performed between pointer to object and a non-integer arithmetic type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=operand,
                            )
                        )
                # Rule 17.3 is intentionally not emitted from fallback source scans.
                # We rely on clang diagnostics for this rule to avoid high false-positive
                # rates in macro-heavy and function-pointer-heavy C code.
                # Rule 21.14: memcmp should not compare null-terminated strings (heuristic).
                memcmp_match = re.search(
                    r"\bmemcmp\s*\((.+)\)\s*;?", line_no_comment
                )
                if memcmp_match:
                    args = [
                        a.strip() for a in memcmp_match.group(1).split(",")
                    ]
                    if len(args) >= 2 and ('"' in args[0] or '"' in args[1]):
                        violations.append(
                            Violation(
                                "Rule 21.14",
                                "The Standard Library function memcmp shall not be used to compare null terminated strings.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=args[0] if '"' in args[0] else args[1],
                            )
                        )
                # Rule 21.21: system() shall not be used.
                if re.search(r"\bsystem\s*\(", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 21.21",
                            "The Standard Library system of <stdlib.h> shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 21.24: random number generator functions shall not be used.
                if re.search(
                    r"\b(rand|srand|random|srandom)\s*\(", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 21.24",
                            "The random number generator functions of <stdlib.h> shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 21.13: ctype arguments shall be unsigned-char representable or EOF (heuristic).
                ctype_match = re.search(
                    r"\b(isalnum|isalpha|isblank|iscntrl|isdigit|isgraph|islower|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper)\s*\((.+)\)",
                    line_no_comment,
                )
                if ctype_match:
                    arg = ctype_match.group(2).strip()
                    neg_lit = re.match(r"^-\s*(\d+)\s*$", arg)
                    if neg_lit and neg_lit.group(1) != "1":
                        violations.append(
                            Violation(
                                "Rule 21.13",
                                "Any value passed to a function in <ctype.h> shall be representable as an unsigned char or be the value EOF.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=arg,
                            )
                        )
                # Rule 7.5: integer-constant macro argument form (heuristic).
                int_const_macro = re.search(
                    r"\b(?:INT|UINT|INT_LEAST|UINT_LEAST|INT_FAST|UINT_FAST)(?:8|16|32|64|MAX)_C\s*\(([^)]+)\)",
                    line_no_comment,
                )
                if int_const_macro:
                    arg = int_const_macro.group(1).strip()
                    if re.search(r"[.eE]", arg) or re.search(r"[fFdD]", arg):
                        violations.append(
                            Violation(
                                "Rule 7.5",
                                "The argument of an integer-constant macro shall have an appropriate form.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=arg,
                            )
                        )
                # Rule 1.1: translation-limits envelope (heuristic: very long identifiers).
                if re.search(r"\b[A-Za-z_]\w{63,}\b", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 1.1",
                            "The program shall contain no violations of standard C syntax/constraints and shall not exceed implementation translation limits.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 1.3: undefined/critical unspecified behavior patterns (heuristic).
                line_ops = re.sub(r'"(?:\\.|[^"\\])*"', '""', line_no_comment)
                if re.search(
                    r"/\s*\(?\s*0(?:[uUlL]+)?\s*\)?(?!\s*\.)|(?<![\"'])%\s*\(?\s*0(?:[uUlL]+)?\s*\)?(?!\s*\.)",
                    line_ops,
                ) or re.search(r"<<\s*32\b|>>\s*32\b", line_ops):
                    violations.append(
                        Violation(
                            "Rule 1.3",
                            "There shall be no occurrence of undefined or critical unspecified behaviour.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 1.4: emergent language features (heuristic).
                if re.search(
                    r"\b_BitInt\s*\(|\btypeof_unqual\b|\bconstexpr\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 1.4",
                            "Emergent language features shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 1.5: obsolescent language features (heuristic).
                if re.search(r"\bregister\b", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 1.5",
                            "Obsolescent language features shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 7.6: small integer minimum-width macros shall not be used.
                if re.search(
                    r"\b(?:INT8_C|UINT8_C|INT16_C|UINT16_C|INT_LEAST8_C|UINT_LEAST8_C|INT_LEAST16_C|UINT_LEAST16_C)\s*\(",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 7.6",
                            "The small integer variants of the minimum-width integer constant macros shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 18.9: temporary-lifetime array object decaying to pointer (heuristic).
                if re.search(
                    r"\b[A-Za-z_]\w*\s*\*\s*[A-Za-z_]\w*\s*=\s*\(\s*[A-Za-z_]\w*\s*\[\s*\]\s*\)\s*\{",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 18.9",
                            "An object with temporary lifetime shall not undergo array-to-pointer conversion.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 9.6: chained designators with non-designated initializer (heuristic).
                if re.search(
                    r"=\s*\{[^}]*\.[A-Za-z_]\w*\s*=[^,]*,\s*[^.\[\]}][^,}]*",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 9.6",
                            "An initializer using chained designators shall not contain initializers without designators.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 17.13: function type shall not be type qualified (heuristic).
                if re.search(
                    r"\btypedef\b[^;]*\([^)]*\)\s*const\s*;", line_no_comment
                ) or re.search(
                    r"\b[A-Za-z_]\w*\s*\([^)]*\)\s*const\s*;",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 17.13",
                            "A function type shall not be type qualified.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 21.22 / 21.23: tgmath operand checks (heuristic).
                tgmath_call = re.search(
                    r"\b(fmax|fmin|fma|pow|hypot|atan2|copysign)\s*\((.+)\)",
                    line_no_comment,
                )
                if tgmath_call:
                    fn = tgmath_call.group(1)
                    args = [a.strip() for a in tgmath_call.group(2).split(",")]
                    if len(args) >= 1:
                        if any(
                            '"' in a or "'" in a or re.search(r"\bNULL\b", a)
                            for a in args
                        ):
                            violations.append(
                                Violation(
                                    "Rule 21.22",
                                    "All operand arguments to any type-generic macros declared in <tgmath.h> shall have an appropriate essential type.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=fn,
                                )
                            )
                    if (
                        fn
                        in {
                            "fmax",
                            "fmin",
                            "fma",
                            "pow",
                            "hypot",
                            "atan2",
                            "copysign",
                        }
                        and len(args) >= 2
                    ):

                        def _cat(a: str) -> str:
                            if re.search(r"\b\d+\.\d+[fF]\b", a):
                                return "float"
                            if re.search(r"\b\d+\.\d+\b", a):
                                return "double"
                            if re.search(r"\b\d+[uUlL]*\b", a):
                                return "int"
                            return "other"

                        c1 = _cat(args[0])
                        c2 = _cat(args[1])
                        if c1 != "other" and c2 != "other" and c1 != c2:
                            violations.append(
                                Violation(
                                    "Rule 21.23",
                                    "All operand arguments to any multi-argument type-generic macros declared in <tgmath.h> shall have the same standard type.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=f"{args[0]}, {args[1]}",
                                )
                            )
                # Rule 21.15 / 21.16 / 21.18: memory and string function argument checks (heuristic).
                mem_like = re.search(
                    r"\b(memcpy|memmove|memcmp|strncpy|strncmp)\s*\((.+)\)",
                    line_no_comment,
                )
                if mem_like:
                    fn = mem_like.group(1)
                    args = [a.strip() for a in mem_like.group(2).split(",")]
                    if len(args) >= 3:
                        cast1 = re.search(
                            r"\(\s*([A-Za-z_]\w*)\s*\*\s*\)", args[0]
                        )
                        cast2 = re.search(
                            r"\(\s*([A-Za-z_]\w*)\s*\*\s*\)", args[1]
                        )
                        if (
                            cast1
                            and cast2
                            and cast1.group(1) != cast2.group(1)
                        ):
                            violations.append(
                                Violation(
                                    "Rule 21.15",
                                    "The pointer arguments to the Standard Library functions memcpy, memmove and memcmp shall be pointers to qualified or unqualified versions of compatible types.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=fn,
                                )
                            )
                        if fn == "memcmp":
                            disallowed = {"float", "double", "long double"}
                            if (cast1 and cast1.group(1) in disallowed) or (
                                cast2 and cast2.group(1) in disallowed
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 21.16",
                                        "The pointer arguments to the Standard Library function memcmp shall point to either a pointer type, an essentially signed type, an essentially unsigned type, an essentially Boolean type or an essentially enum type.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=fn,
                                    )
                                )
                        size_arg = args[2]
                        if re.search(
                            r"\(\s*size_t\s*\)\s*-\s*\d+\b", size_arg
                        ):
                            violations.append(
                                Violation(
                                    "Rule 21.18",
                                    "The size_t argument passed to any function in <string.h> shall have an appropriate value.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=size_arg,
                                )
                            )
                # Rule 21.19 / 21.20: pointer return usage constraints (heuristic).
                ptr_decl = re.search(
                    r"\b(?:(const)\s+)?(?:char|struct\s+lconv|struct\s+tm)\s*\*\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\(",
                    line_no_comment,
                )
                ptr_assign = re.search(
                    r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\(",
                    line_no_comment,
                )
                if ptr_decl:
                    is_const = bool(ptr_decl.group(1))
                    var_name = ptr_decl.group(2)
                    fn_name = ptr_decl.group(3)
                    if fn_name in c_const_pointer_functions and not is_const:
                        violations.append(
                            Violation(
                                "Rule 21.19",
                                "The pointers returned by the Standard Library functions localeconv, getenv, setlocale or strerror shall only be used as if they have pointer to const-qualified type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=var_name,
                            )
                        )
                    if fn_name in c_volatile_pointer_functions:
                        if fn_name in c_last_return_ptr_var:
                            prev_var, prev_line = c_last_return_ptr_var[
                                fn_name
                            ]
                            c_stale_return_ptr_var[prev_var] = (
                                fn_name,
                                prev_line,
                            )
                        c_last_return_ptr_var[fn_name] = (var_name, idx)
                elif ptr_assign:
                    var_name = ptr_assign.group(1)
                    fn_name = ptr_assign.group(2)
                    if fn_name in c_volatile_pointer_functions:
                        if fn_name in c_last_return_ptr_var:
                            prev_var, prev_line = c_last_return_ptr_var[
                                fn_name
                            ]
                            c_stale_return_ptr_var[prev_var] = (
                                fn_name,
                                prev_line,
                            )
                        c_last_return_ptr_var[fn_name] = (var_name, idx)
                for stale_var in list(c_stale_return_ptr_var.keys()):
                    if stale_var in line_no_comment and not re.search(
                        rf"=\s*{re.escape(stale_var)}\s*;", line_no_comment
                    ):
                        fn_name, _ = c_stale_return_ptr_var[stale_var]
                        violations.append(
                            Violation(
                                "Rule 21.20",
                                f"The pointer returned by '{fn_name}' shall not be used following a subsequent call to the same function.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=stale_var,
                            )
                        )
                        del c_stale_return_ptr_var[stale_var]
                # Rule 22.7: EOF compare must use unmodified return value (heuristic).
                eof_cmp = re.search(
                    r"(.*?)\s*(==|!=|<=|>=|<|>)\s*EOF\b|\bEOF\s*(==|!=|<=|>=|<|>)\s*(.*)",
                    line_no_comment,
                )
                if eof_cmp:
                    lhs = (eof_cmp.group(1) or eof_cmp.group(4) or "").strip()
                    if lhs and not re.search(
                        r"\b[A-Za-z_]\w*\s*\([^)]*\)\s*$", lhs
                    ):
                        violations.append(
                            Violation(
                                "Rule 22.7",
                                "The macro EOF shall only be compared with the unmodified return value from any Standard Library function capable of returning EOF.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=lhs,
                            )
                        )
                # Rule 22.8 / 22.9 / 22.10: errno usage sequencing (heuristic).
                if c_errno_used_in_file:
                    if re.search(r"\berrno\s*=\s*0\s*;", line_no_comment):
                        c_errno_reset_since_last_call = True
                    if re.search(r"\berrno\b", line_no_comment) and re.search(
                        r"(==|!=|<=|>=|<|>)", line_no_comment
                    ):
                        if c_pending_errno_call is None:
                            violations.append(
                                Violation(
                                    "Rule 22.10",
                                    "The value of errno shall only be tested when the last function to be called was an errno-setting-function.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=line_no_comment.strip(),
                                )
                            )
                        else:
                            c_pending_errno_call = None
                    errno_call = re.search(
                        r"\b([A-Za-z_]\w*)\s*\(", line_no_comment
                    )
                    if (
                        errno_call
                        and errno_call.group(1) in c_errno_setting_functions
                    ):
                        if c_pending_errno_call is not None:
                            prev_name, prev_line = c_pending_errno_call
                            violations.append(
                                Violation(
                                    "Rule 22.9",
                                    f"The value of errno shall be tested against zero after calling an errno-setting-function ('{prev_name}').",
                                    file_path,
                                    prev_line,
                                    detector="clang-fallback-scan",
                                    trigger=prev_name,
                                )
                            )
                        if not c_errno_reset_since_last_call:
                            violations.append(
                                Violation(
                                    "Rule 22.8",
                                    "The value of errno shall be set to zero prior to a call to an errno-setting-function.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=errno_call.group(1),
                                )
                            )
                        c_pending_errno_call = (errno_call.group(1), idx)
                        c_errno_reset_since_last_call = False
                # Rule 21.2: reserved identifiers shall not be declared.
                if re.search(
                    r"^\s*(?:extern\s+)?(?:int|char|short|long|float|double|void|struct\s+\w+|enum\s+\w+|typedef\s+.*)\s+(__[A-Za-z_]\w*)\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 21.2",
                            "A reserved identifier or macro name shall not be declared.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
            if is_cpp_file and re.match(
                r"^\s*template\s+(class|struct|union)\s+[A-Za-z_]\w*\s*<[^>]*>\s*;?\s*$",
                line_no_comment,
            ):
                violations.append(
                    Violation(
                        "Rule 14-7-2",
                        "For any given template specialization, an explicit instantiation of the template shall not appear.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
            if is_cpp_file and re.match(
                r"^\s*template\s+.*\b[A-Za-z_]\w*\s*<[^>]*>\s*\(.*\)\s*;?\s*$",
                line_no_comment,
            ):
                violations.append(
                    Violation(
                        "Rule 14-7-2",
                        "For any given template specialization, an explicit instantiation of the template shall not appear.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
            if is_cpp_file:
                for spec_line, spec_name in cpp_explicit_specializations:
                    if (
                        spec_line == idx
                        and cpp_template_overload_counts.get(spec_name, 0) > 1
                    ):
                        violations.append(
                            Violation(
                                "Rule 14-8-1",
                                "Overloaded function templates shall not be explicitly specialized.",
                                file_path,
                                idx,
                                trigger=spec_name,
                            )
                        )
            if is_cpp_file and re.match(
                r"^\s*#\s*define\s+[A-Za-z_]\w*\s*\(", line
            ):
                violations.append(
                    Violation(
                        "Rule 16-0-4",
                        "Function-like macros shall not be defined.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
                if profile_key == "cpp2023":
                    violations.append(
                        Violation(
                            "Rule 19.0.2",
                            "Function-like macros shall not be defined.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
            if is_cpp_file and re.match(r"^\s*#\s*include\b", line):
                m_local_inc = re.match(
                    r'^\s*#\s*include\s*"([^"]+)"\s*$', line_no_comment
                )
                if m_local_inc:
                    rel = m_local_inc.group(1).strip()
                    header_candidate = (file_path.parent / rel).resolve()
                    if header_candidate.suffix.lower() in {
                        ".h",
                        ".hh",
                        ".hpp",
                        ".hxx",
                    }:
                        header_key = str(header_candidate)
                        if (
                            header_key not in checked_local_headers
                            and header_candidate.exists()
                        ):
                            checked_local_headers.add(header_key)
                            if not _has_include_guard(header_candidate):
                                violations.append(
                                    Violation(
                                        "Rule 16-2-3",
                                        f"Include guard missing for header '{rel}'.",
                                        file_path,
                                        idx,
                                        trigger=rel,
                                    )
                                )
                                if profile_key == "cpp2023":
                                    violations.append(
                                        Violation(
                                            "Rule 19.2.1",
                                            "Precautions shall be taken in order to prevent the contents of a header file being included more than once.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=rel,
                                        )
                                    )
                                    unnamed_ns_line = _unnamed_namespace_line(
                                        header_candidate
                                    )
                                    if unnamed_ns_line is not None:
                                        violations.append(
                                            Violation(
                                                "Rule 10.3.1",
                                                "There should be no unnamed namespaces in header files.",
                                                header_candidate,
                                                unnamed_ns_line,
                                                detector="clang-fallback-scan",
                                                trigger=rel,
                                            )
                                        )
                if not re.match(
                    r'^\s*#\s*include\s*(<[^>]+>|"[^"]+")\s*$', line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 16-2-6",
                            'The #include directive shall be followed by either a <filename> or "filename" sequence.',
                            file_path,
                            idx,
                            trigger=line_no_comment.strip(),
                        )
                    )
                    if profile_key == "cpp2023":
                        violations.append(
                            Violation(
                                "Rule 19.2.2",
                                'The #include directive shall be followed by either a <filename> or "filename" sequence.',
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                if re.match(
                    r'^\s*#\s*include\s*"[^"]*\\[^"]*"\s*$', line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 16-2-5",
                            "The \\ character should not be used in a #include directive string.",
                            file_path,
                            idx,
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.match(
                    r"^\s*#\s*include\s*<(stdio\.h|stdlib\.h|string\.h|time\.h|signal\.h|setjmp\.h|cstdio|cstdlib|cstring|ctime|csignal|csetjmp)>",
                    line_no_comment,
                ):
                    include_trigger = line_no_comment.strip()
                    violations.append(
                        Violation(
                            "Rule 18-0-1",
                            "The C library shall not be used.",
                            file_path,
                            idx,
                            trigger=include_trigger,
                        )
                    )
            if is_cpp_file and profile_key == "cpp2023":
                if brace_depth == 0 and re.match(
                    r"^\s*extern\b[^;]*\b[A-Za-z_]\w*\s*\[\s*\]\s*;",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 6.0.2",
                            "When an array with external linkage is declared, its size should be explicitly specified.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if brace_depth == 0 and not re.match(
                    r"^\s*(#|//|/\*|\*/)\b", line_no_comment
                ):
                    if re.match(
                        r"^\s*namespace\b", line_no_comment
                    ) or re.match(r'^\s*extern\s+"C"\b', line_no_comment):
                        pass
                    else:
                        top_decl = re.match(
                            r"^\s*(?:static\s+|const\s+|constexpr\s+|extern\s+)?(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;>]+>)?[\s\*&]+([A-Za-z_]\w*)\s*(\(|\[|=|;)",
                            line_no_comment,
                        )
                        if top_decl and top_decl.group(1) != "main":
                            violations.append(
                                Violation(
                                    "Rule 6.0.3",
                                    'The only declarations in the global namespace should be main, namespace declarations and extern "C" declarations.',
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=top_decl.group(1),
                                )
                            )
                            if top_decl.group(2) != "(":
                                violations.append(
                                    Violation(
                                        "Rule 6.7.2",
                                        "Global variables shall not be used.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=top_decl.group(1),
                                    )
                                )
                poly_decl = re.match(
                    r"^\s*(?:class|struct)\s+([A-Za-z_]\w*)\b.*\bvirtual\b",
                    line_no_comment,
                )
                if poly_decl:
                    cpp2023_polymorphic_types.add(poly_decl.group(1))
                poly_var = re.match(
                    r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:[=;,\[])",
                    line_no_comment,
                )
                if poly_var and poly_var.group(1) in cpp2023_polymorphic_types:
                    cpp2023_polymorphic_vars.add(poly_var.group(2))
                typeid_expr = re.search(
                    r"\btypeid\s*\(\s*([A-Za-z_]\w*)\s*\)", line_no_comment
                )
                if (
                    typeid_expr
                    and typeid_expr.group(1) in cpp2023_polymorphic_vars
                ):
                    violations.append(
                        Violation(
                            "Rule 8.2.9",
                            "The operand to typeid shall not be an expression of polymorphic class type.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                variadic_decl = re.match(
                    r"^\s*[\w:\<\>\~\s\*&]+\b([A-Za-z_]\w*)\s*\([^)]*\.\.\.\s*\)\s*[;{]",
                    line_no_comment,
                )
                if variadic_decl:
                    cpp2023_variadic_functions.add(variadic_decl.group(1))
                variadic_call = re.search(
                    r"\b([A-Za-z_]\w*)\s*\((.*)\)\s*;", line_no_comment
                )
                if (
                    variadic_call
                    and variadic_call.group(1) in cpp2023_variadic_functions
                ):
                    args_text = variadic_call.group(2)
                    if re.search(
                        r"\btrue\b|\bfalse\b|\d+\.\d*(?:[eE][+-]?\d+)?[fFlL]?\b",
                        args_text,
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.2.11",
                                "An argument passed via ellipsis shall have an appropriate type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=args_text,
                            )
                        )
                unsigned_decl = re.match(
                    r"^\s*(?:const\s+)?(?:unsigned(?:\s+int|\s+long|\s+short|\s+char)?|std::u?int\d+_t|u?int\d+_t)\b[^;=]*\b([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if unsigned_decl:
                    cpp2023_unsigned_vars.add(unsigned_decl.group(1))
                char_decl = re.match(
                    r"^\s*(?:const\s+)?(?:char|signed\s+char|unsigned\s+char|wchar_t|char16_t|char32_t)\b[^;=]*\b([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if char_decl:
                    cpp2023_char_vars.add(char_decl.group(1))
                if re.search(
                    r"^\s*(?!explicit\b)(?:inline\s+)?(?:[A-Za-z_]\w*::)?[A-Za-z_]\w*\s*\(\s*(?:const\s+)?[A-Za-z_:\<\>\s\*&]+\s+[A-Za-z_]\w*\s*(?:=\s*[^)]*)?\)\s*(?:;|\{)",
                    line_no_comment,
                ):
                    # Heuristic for single-argument constructor declarations without 'explicit'
                    if not re.search(r"\boperator\b", line_no_comment):
                        violations.append(
                            Violation(
                                "Rule 15.1.3",
                                "Conversion operators and constructors that are callable with a single argument shall be explicit.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                if re.search(
                    r"\boperator\s*&&\s*\(", line_no_comment
                ) or re.search(r"\boperator\s*\|\|\s*\(", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 16.5.1",
                            "The logical AND and logical OR operators shall not be overloaded.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(r"\boperator\s*&\s*\(", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 16.5.2",
                            "The address-of operator shall not be overloaded.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(
                    r"\boperator\s*(?:\+|-|\*|/|==|!=|<=|>=|<|>)\s*\(",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 16.6.1",
                            "Symmetrical operators should only be implemented as non-member functions.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                unary_minus = re.search(
                    r"(?:=\s*|return\s+|\(\s*)-\s*([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if (
                    unary_minus
                    and unary_minus.group(1) in cpp2023_unsigned_vars
                ):
                    violations.append(
                        Violation(
                            "Rule 8.3.1",
                            "The built-in unary - operator should not be applied to an expression of unsigned type.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=unary_minus.group(1),
                        )
                    )
                for cvar in list(cpp2023_char_vars):
                    if re.search(
                        rf"\b{re.escape(cvar)}\b\s*[\+\-\*/%]|[\+\-\*/%]\s*\b{re.escape(cvar)}\b|[<>&|]\s*\b{re.escape(cvar)}\b|\b{re.escape(cvar)}\b\s*[<>&|]",
                        line_no_comment,
                    ):
                        violations.append(
                            Violation(
                                "Rule 7.0.3",
                                "The numerical value of a character shall not be used.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=cvar,
                            )
                        )
                        break
                bitwise_m = re.search(
                    r"\b([A-Za-z_]\w*)\b\s*(?:<<|>>|&|\||\^)\s*\b([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if bitwise_m:
                    lhs, rhs = bitwise_m.group(1), bitwise_m.group(2)
                    if (
                        lhs in cpp2023_bool_vars
                        or rhs in cpp2023_bool_vars
                        or lhs in cpp2023_float_vars
                        or rhs in cpp2023_float_vars
                    ):
                        violations.append(
                            Violation(
                                "Rule 7.0.4",
                                "The operands of bitwise operators and shift operators shall be appropriate.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=f"{lhs} {rhs}",
                            )
                        )
                mixed_arith = re.search(
                    r"\b([A-Za-z_]\w*)\b\s*[\+\-\*/%]\s*\b([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if mixed_arith:
                    lhs, rhs = mixed_arith.group(1), mixed_arith.group(2)
                    lhs_unsigned = lhs in cpp2023_unsigned_vars
                    rhs_unsigned = rhs in cpp2023_unsigned_vars
                    lhs_signed = (
                        lhs in cpp2023_integral_vars and not lhs_unsigned
                    )
                    rhs_signed = (
                        rhs in cpp2023_integral_vars and not rhs_unsigned
                    )
                    if (lhs_unsigned and rhs_signed) or (
                        rhs_unsigned and lhs_signed
                    ):
                        violations.append(
                            Violation(
                                "Rule 7.0.5",
                                "Integral promotion and the usual arithmetic conversions shall not change the signedness or the type category of an operand.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=f"{lhs} {rhs}",
                            )
                        )
                # Rule 8.0.1: mixed operators without explicit parentheses can be ambiguous.
                if "(" not in line_no_comment and ")" not in line_no_comment:
                    has_shift = bool(re.search(r"<<|>>", line_no_comment))
                    has_add = bool(re.search(r"[+\-]", line_no_comment))
                    has_logic_mix = bool(
                        re.search(r"&&.*\|\||\|\|.*&&", line_no_comment)
                    )
                    if (has_shift and has_add) or has_logic_mix:
                        violations.append(
                            Violation(
                                "Rule 8.0.1",
                                "Parentheses should be used to make the meaning of an expression appropriately explicit.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                if re.search(
                    r"\b0x[0-9A-Fa-f]+U?\s*[\+\-\*]\s*0x[0-9A-Fa-f]+U?\b|\b0xFFFFFFFFU\s*\+\s*1U\b|\b4294967295U\s*\+\s*1U\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 8.20.1",
                            "An unsigned arithmetic operation with constant operands should not wrap.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                catch_open = re.search(
                    r"\bcatch\s*\([^)]*\)\s*\{", line_no_comment
                )
                if catch_open:
                    cpp2023_catch_depth_stack.append(
                        brace_depth + line_no_comment.count("{")
                    )
                in_catch = bool(cpp2023_catch_depth_stack)
                if (
                    re.search(r"\bthrow\s*;\s*$", line_no_comment)
                    and not in_catch
                ):
                    violations.append(
                        Violation(
                            "Rule 18.1.2",
                            "An empty throw shall only occur within the compound-statement of a catch handler.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                throw_var = re.search(
                    r"\bthrow\s+([A-Za-z_]\w*)\s*;", line_no_comment
                )
                if re.search(
                    r"\bthrow\s+[A-Za-z_]\w*\s*\*\s*[A-Za-z_]\w*\s*;",
                    line_no_comment,
                ) or (
                    throw_var and throw_var.group(1) in cpp2023_pointer_vars
                ):
                    violations.append(
                        Violation(
                            "Rule 18.1.1",
                            "An exception object shall not have pointer type.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                catch_decl = re.search(
                    r"\bcatch\s*\(([^)]*)\)", line_no_comment
                )
                if catch_decl:
                    cparam = catch_decl.group(1).strip()
                    if cpp2023_current_fn and cparam == "...":
                        cpp2023_current_fn["has_catch_all"] = True
                    if cparam and cparam != "...":
                        is_ref = "&" in cparam
                        is_const = "const" in cparam
                        is_pointer = "*" in cparam
                        if (not is_ref or not is_const) and not is_pointer:
                            violations.append(
                                Violation(
                                    "Rule 18.3.2",
                                    "An exception of class type shall be caught by const reference or reference.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=cparam,
                                )
                            )
                bitfield_decl = re.search(
                    r"\b([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)\s+[A-Za-z_]\w*\s*:\s*(\d+)\s*[;,]",
                    line_no_comment,
                )
                if bitfield_decl:
                    btype = bitfield_decl.group(1).strip()
                    bwidth = int(bitfield_decl.group(2))
                    violations.append(
                        Violation(
                            "Rule 12.2.1",
                            "Bit-fields should not be declared.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                    allowed_type = btype in {
                        "unsigned int",
                        "signed int",
                        "bool",
                        "std::uint8_t",
                        "std::uint16_t",
                        "std::uint32_t",
                        "std::uint64_t",
                    }
                    if not allowed_type:
                        violations.append(
                            Violation(
                                "Rule 12.2.2",
                                "Bit-fields shall have an appropriate type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=btype,
                            )
                        )
                    if bwidth == 1 and btype in {
                        "signed int",
                        "int",
                        "signed",
                    }:
                        violations.append(
                            Violation(
                                "Rule 12.2.3",
                                "A named bit-field with signed integer type shall not have a length of one bit.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=btype,
                            )
                        )
                fn_start = re.match(
                    r"^\s*(?:\[\[\s*noreturn\s*\]\]\s*)?[\w:\<\>\~\s\*&]+\b([A-Za-z_]\w*|operator=)\s*\([^;{}]*\)\s*(?:const\b[^{};]*)?(?:\s*noexcept(?:\s*\([^)]*\))?)?\s*\{",
                    line_no_comment,
                )
                if fn_start and fn_start.group(1) not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                }:
                    is_move_ctor = bool(
                        re.search(
                            r"\b([A-Za-z_]\w*)\s*\(\s*\1\s*&&", line_no_comment
                        )
                    )
                    is_move_assign = bool(
                        re.search(
                            r"\boperator=\s*\(\s*([A-Za-z_]\w*)\s*&&",
                            line_no_comment,
                        )
                    )
                    is_swap = bool(re.search(r"\bswap\s*\(", line_no_comment))
                    if (
                        is_move_ctor or is_move_assign or is_swap
                    ) and "noexcept" not in line_no_comment:
                        violations.append(
                            Violation(
                                "Rule 18.4.1",
                                "Exception-unfriendly functions shall be noexcept.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=fn_start.group(1),
                            )
                        )
                    cpp2023_current_fn = {
                        "start_line": idx,
                        "end_depth": brace_depth + line_no_comment.count("{"),
                        "is_noreturn": bool(
                            re.search(
                                r"\[\[\s*noreturn\s*\]\]", line_no_comment
                            )
                        ),
                        "is_noexcept": "noexcept" in line_no_comment,
                        "is_assignment_operator": "operator="
                        in line_no_comment,
                        "local_vars": set(),
                        "local_last_write": {},
                        "local_read_since_write": {},
                        "pending_gotos": [],
                        "has_try": False,
                        "has_catch_all": False,
                    }
                    cpp2023_labels_in_fn = {}
                if cpp2023_current_fn and re.search(
                    r"\btry\s*\{", line_no_comment
                ):
                    cpp2023_current_fn["has_try"] = True
                param_sig = re.match(
                    r"^\s*(?:\[\[\s*noreturn\s*\]\]\s*)?[\w:\<\>\~\s\*&]+\b(?:[A-Za-z_]\w*|operator=)\s*\(([^;{}()]*)\)\s*(?:const\b[^{};]*)?(?:\s*noexcept(?:\s*\([^)]*\))?)?\s*[;{]",
                    line_no_comment,
                )
                named_param_sig = re.match(
                    r"^\s*(?:virtual\s+)?(?:[\w:\<\>\~]+\s+)+([A-Za-z_]\w*)\s*\(([^;{}()]*)\)\s*(?:const\b[^{};]*)?(?:\s*noexcept(?:\s*\([^)]*\))?)?\s*[;{]",
                    line_no_comment,
                )
                if named_param_sig:
                    fn_name = named_param_sig.group(1)
                    params_text_all = (named_param_sig.group(2) or "").strip()
                    if params_text_all and params_text_all != "void":
                        param_names = []
                        valid = True
                        for raw_param in params_text_all.split(","):
                            p = raw_param.strip()
                            if not p or p == "...":
                                valid = False
                                break
                            p = p.split("=", 1)[0].strip()
                            p = re.sub(r"\[[^\]]*\]", " ", p)
                            m_name = re.search(r"([A-Za-z_]\w*)\s*$", p)
                            if not m_name:
                                valid = False
                                break
                            param_names.append(m_name.group(1))
                        if valid and param_names:
                            key = (fn_name, len(param_names))
                            prev = cpp2023_param_name_signatures.get(key)
                            if prev is None:
                                cpp2023_param_name_signatures[key] = (
                                    tuple(param_names),
                                    idx,
                                )
                            else:
                                prev_names, _ = prev
                                if prev_names != tuple(param_names):
                                    violations.append(
                                        Violation(
                                            "Rule 13.3.3",
                                            "The parameters in all declarations or overrides of a function shall either be unnamed or have identical names.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=fn_name,
                                        )
                                    )
                if param_sig:
                    params_text = (param_sig.group(1) or "").strip()
                    if params_text and params_text != "void":
                        for raw_param in params_text.split(","):
                            p = raw_param.strip()
                            if not p or p == "...":
                                continue
                            p_clean = p.split("=", 1)[0].strip()
                            p_ptr_typed = re.match(
                                r"^(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)$",
                                p_clean,
                            )
                            if p_ptr_typed:
                                cpp2023_ptr_decl_types[
                                    p_ptr_typed.group(2)
                                ] = p_ptr_typed.group(1)
                            if "*" in p:
                                before_ptr = p.split("*", 1)[0]
                                if "const" not in before_ptr:
                                    violations.append(
                                        Violation(
                                            "Rule 10.1.1",
                                            "The target type of a pointer or lvalue reference parameter should be const-qualified appropriately.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=p_clean,
                                        )
                                    )
                                    break
                            if "&" in p and "&&" not in p:
                                before_ref = p.split("&", 1)[0]
                                if "const" not in before_ref:
                                    violations.append(
                                        Violation(
                                            "Rule 10.1.1",
                                            "The target type of a pointer or lvalue reference parameter should be const-qualified appropriately.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=p_clean,
                                        )
                                    )
                                    break
                volatile_decl = re.match(
                    r"^\s*(?:static\s+)?volatile\s+(?!std::atomic\b)[A-Za-z_:\<\>\s]+(?:\*+)?\s*([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if (
                    re.search(r"\(\{", line_no_comment)
                    or re.search(r"\basm\s*\(", line_no_comment)
                    or re.search(
                        r"\b(?:unsigned\s+|signed\s+)?(?:char|short|int|long|float|double|bool)\s+[A-Za-z_]\w*\s*\[\s*[A-Za-z_]\w+\s*\]\s*;",
                        line_no_comment,
                    )
                ):
                    violations.append(
                        Violation(
                            "Rule 4.1.1",
                            "A program shall conform to ISO/IEC 14882:2017 (C++17).",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(
                    r"\b([A-Za-z_]\w*)\s*=\s*\1\s*(?:\+\+|--)", line_no_comment
                ) or re.search(
                    r"\b([A-Za-z_]\w*)\s*=\s*(?:\+\+|--)\s*\1\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 4.6.1",
                            "Operations on a memory location shall be sequenced appropriately.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if (
                    re.search(r"/\s*0\b", line_no_comment)
                    or re.search(
                        r"%\s*0\b",
                        line_no_comment,
                    )
                    or re.search(r"\*\s*nullptr\b", line_no_comment)
                ):
                    violations.append(
                        Violation(
                            "Rule 4.1.3",
                            "There shall be no occurrence of undefined or critical unspecified behaviour.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if brace_depth > 0 and re.search(
                    r"\b(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long|float|double|bool)\b[^;]*\b[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*[^;]*;",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 6.0.1",
                            "Block scope declarations shall not be visually ambiguous.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if volatile_decl and "*" not in line_no_comment:
                    violations.append(
                        Violation(
                            "Rule 10.1.2",
                            "The volatile qualifier shall be used appropriately.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                pmf_decl = re.match(
                    r"^\s*[\w:\<\>\~\s\*&]+\(\s*[^)]*::\s*\*\s*([A-Za-z_]\w+)\s*\)\s*\([^;]*\)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if pmf_decl:
                    cpp2023_pmf_vars.add(pmf_decl.group(1))
                pmf_cmp = re.search(
                    r"\b([A-Za-z_]\w*)\b\s*(==|!=)\s*\b([A-Za-z_]\w*|nullptr|NULL|0)\b",
                    line_no_comment,
                )
                if pmf_cmp:
                    lhs, _, rhs = pmf_cmp.groups()
                    if lhs in cpp2023_pmf_vars or rhs in cpp2023_pmf_vars:
                        other = rhs if lhs in cpp2023_pmf_vars else lhs
                        if other not in {"nullptr"}:
                            violations.append(
                                Violation(
                                    "Rule 13.3.4",
                                    "A comparison of a potentially virtual pointer to member function shall only be with nullptr.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=f"{lhs} {rhs}",
                                )
                            )
                label_match = re.match(
                    r"^\s*([A-Za-z_]\w*)\s*:\s*(?!:)", line_no_comment
                )
                if label_match and cpp2023_current_fn:
                    lname = label_match.group(1)
                    if lname not in {
                        "case",
                        "default",
                        "public",
                        "private",
                        "protected",
                    }:
                        cpp2023_labels_in_fn[lname] = (idx, brace_depth)
                        pending_gotos = cast(
                            List[Tuple[int, str, int]],
                            cpp2023_current_fn.get("pending_gotos", []),
                        )
                        for g_line, g_target, g_depth in pending_gotos:
                            if g_target == lname and brace_depth > g_depth:
                                violations.append(
                                    Violation(
                                        "Rule 9.6.2",
                                        "A goto statement shall reference a label in a surrounding block.",
                                        file_path,
                                        g_line,
                                        detector="clang-fallback-scan",
                                        trigger=g_target,
                                    )
                                )
                if cpp2023_current_fn:
                    local_decl = re.match(
                        r"^\s*(?:const\s+)?(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;>]+>)?[\s\*&]+([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                        line_no_comment,
                    )
                    if local_decl:
                        lname = local_decl.group(1)
                        cpp2023_current_fn["local_vars"].add(lname)
                        if "=" in line_no_comment:
                            cpp2023_current_fn["local_last_write"][lname] = idx
                            cpp2023_current_fn["local_read_since_write"][
                                lname
                            ] = False
                    for lvar in list(
                        cpp2023_current_fn.get("local_vars", set())
                    ):
                        if not re.search(
                            rf"\b{re.escape(lvar)}\b", line_no_comment
                        ):
                            continue
                        simple_write = re.match(
                            rf"^\s*{re.escape(lvar)}\s*=\s*[^;]*;\s*$",
                            line_no_comment,
                        )
                        if simple_write:
                            prev_write = cpp2023_current_fn[
                                "local_last_write"
                            ].get(lvar)
                            had_read = cpp2023_current_fn[
                                "local_read_since_write"
                            ].get(lvar, False)
                            if prev_write is not None and not had_read:
                                violations.append(
                                    Violation(
                                        "Rule 0.1.1",
                                        "A value should not be unnecessarily written to a local object.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=lvar,
                                    )
                                )
                            cpp2023_current_fn["local_last_write"][lvar] = idx
                            cpp2023_current_fn["local_read_since_write"][
                                lvar
                            ] = False
                            continue
                        if lvar not in cpp2023_current_fn["local_last_write"]:
                            violations.append(
                                Violation(
                                    "Rule 11.6.2",
                                    "The value of an object must not be read before it has been set.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=lvar,
                                )
                            )
                            continue
                        if lvar in cpp2023_current_fn["local_last_write"]:
                            cpp2023_current_fn["local_read_since_write"][
                                lvar
                            ] = True
                goto_match = re.search(
                    r"\bgoto\s+([A-Za-z_]\w*)\s*;", line_no_comment
                )
                if goto_match and cpp2023_current_fn:
                    target = goto_match.group(1)
                    cpp2023_current_fn.setdefault("pending_gotos", []).append(
                        (idx, target, brace_depth)
                    )
                    target_info = cpp2023_labels_in_fn.get(target)
                    if target_info is not None and target_info[0] < idx:
                        violations.append(
                            Violation(
                                "Rule 9.6.3",
                                "The goto statement shall jump to a label declared later in the function body.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=target,
                            )
                        )
                    if (
                        target_info is not None
                        and target_info[1] > brace_depth
                    ):
                        violations.append(
                            Violation(
                                "Rule 9.6.2",
                                "A goto statement shall reference a label in a surrounding block.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=target,
                            )
                        )
                if (
                    cpp2023_current_fn
                    and cpp2023_current_fn.get("is_noreturn")
                    and re.search(r"\breturn\b", line_no_comment)
                ):
                    violations.append(
                        Violation(
                            "Rule 9.6.4",
                            "A function declared with the [[noreturn]] attribute shall not return.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if (
                    cpp2023_current_fn
                    and cpp2023_current_fn.get("is_noexcept")
                    and re.search(r"\bthrow\b", line_no_comment)
                ):
                    violations.append(
                        Violation(
                            "Rule 18.5.1",
                            "A noexcept function should not attempt to propagate an exception to the calling function.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if cpp2023_current_fn:
                    ret_local_addr = re.search(
                        r"\breturn\s+&\s*([A-Za-z_]\w*)\s*;", line_no_comment
                    )
                    if (
                        ret_local_addr
                        and ret_local_addr.group(1)
                        in cpp2023_current_fn["local_vars"]
                    ):
                        violations.append(
                            Violation(
                                "Rule 6.8.2",
                                "A function must not return a reference or a pointer to a local variable with automatic storage duration.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=ret_local_addr.group(1),
                            )
                        )
                    if cpp2023_current_fn.get("is_assignment_operator"):
                        assign_local_addr = re.search(
                            r"\bthis->\s*[A-Za-z_]\w*\s*=\s*&\s*([A-Za-z_]\w*)\s*;",
                            line_no_comment,
                        )
                        if (
                            assign_local_addr
                            and assign_local_addr.group(1)
                            in cpp2023_current_fn["local_vars"]
                        ):
                            violations.append(
                                Violation(
                                    "Rule 6.8.3",
                                    "An assignment operator shall not assign the address of an object with automatic storage duration to an object with a greater lifetime.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=assign_local_addr.group(1),
                                )
                            )
                if brace_depth > 0 and re.match(
                    r"^\s*(?!for\s*\()(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long|float|double|bool)\s*[*&]?\s*[A-Za-z_]\w*\s*;\s*$",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 11.6.1",
                            "All variables should be initialized.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(
                    r"\b(?:unsigned(?:\s+int|\s+long|\s+short|\s+char)?|std::u?int\d+_t|u?int\d+_t)\b[^;=]*=\s*(0x[0-9A-Fa-f]+|\d+)\b(?![uU])",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 5.13.4",
                            "Unsigned integer literals shall be appropriately suffixed.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                lit_concat = re.search(
                    r'(?:(u8|u|U|L)?R?)"[^"]*"\s+(?:(u8|u|U|L)?R?)"[^"]*"',
                    line_no_comment,
                )
                if lit_concat:
                    p1 = lit_concat.group(1) or ""
                    p2 = lit_concat.group(2) or ""
                    if p1 != p2:
                        violations.append(
                            Violation(
                                "Rule 5.13.7",
                                "String literals with different encoding prefixes shall not be concatenated.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=lit_concat.group(0),
                            )
                        )
                for lit_m in re.finditer(
                    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])+\'', line_no_comment
                ):
                    lit = lit_m.group(0)
                    prefix = line_no_comment[
                        max(0, lit_m.start() - 3) : lit_m.start()
                    ]
                    if re.search(r"(?:u8|u|U|L)?R$", prefix):
                        continue
                    i = 1
                    is_char_lit = lit.startswith("'")
                    while i < len(lit) - 1:
                        if lit[i] != "\\":
                            i += 1
                            continue
                        if i + 1 >= len(lit) - 1:
                            break
                        esc = lit[i + 1]
                        if esc in {
                            "'",
                            '"',
                            "\\",
                            "?",
                            "a",
                            "b",
                            "f",
                            "n",
                            "r",
                            "t",
                            "v",
                        }:
                            i += 2
                            continue
                        if esc == "x":
                            j = i + 2
                            while j < len(lit) - 1 and re.match(
                                r"[0-9A-Fa-f]", lit[j]
                            ):
                                j += 1
                            if j == i + 2:
                                violations.append(
                                    Violation(
                                        "Rule 5.13.1",
                                        "Within character literals and non raw-string literals, \\ shall only be used to form a defined escape sequence or universal character name.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=lit,
                                    )
                                )
                            elif is_char_lit and (j - (i + 2)) > 2:
                                violations.append(
                                    Violation(
                                        "Rule 5.13.2",
                                        "Octal escape sequences, hexadecimal escape sequences and universal character names shall be terminated.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=lit,
                                    )
                                )
                            i = j
                            continue
                        if esc in {"u", "U"}:
                            need = 4 if esc == "u" else 8
                            j = i + 2
                            while j < len(lit) - 1 and re.match(
                                r"[0-9A-Fa-f]", lit[j]
                            ):
                                j += 1
                            have = j - (i + 2)
                            if have != need:
                                violations.append(
                                    Violation(
                                        "Rule 5.13.2",
                                        "Octal escape sequences, hexadecimal escape sequences and universal character names shall be terminated.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=lit,
                                    )
                                )
                            i = j
                            continue
                        if re.match(r"[0-7]", esc):
                            j = i + 1
                            cnt = 0
                            while (
                                j < len(lit) - 1
                                and cnt < 3
                                and re.match(r"[0-7]", lit[j])
                            ):
                                j += 1
                                cnt += 1
                            if j < len(lit) - 1 and re.match(r"[0-7]", lit[j]):
                                violations.append(
                                    Violation(
                                        "Rule 5.13.2",
                                        "Octal escape sequences, hexadecimal escape sequences and universal character names shall be terminated.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=lit,
                                    )
                                )
                            i = j
                            continue
                        violations.append(
                            Violation(
                                "Rule 5.13.1",
                                "Within character literals and non raw-string literals, \\ shall only be used to form a defined escape sequence or universal character name.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=lit,
                            )
                        )
                        i += 2
                if (
                    re.search(r"\bmain\s*\(", line_no_comment)
                    and brace_depth > 0
                ):
                    violations.append(
                        Violation(
                            "Rule 6.0.4",
                            "The identifier main shall not be used for a function other than the global function main.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                member_ret_ref = re.match(
                    r"^\s*([A-Za-z_]\w*)\s*&\s*([A-Za-z_]\w*)::([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\b)?\s*(?:noexcept(?:\s*\([^)]*\))?)?\s*(?:\{|;)",
                    line_no_comment,
                )
                if member_ret_ref and not re.search(
                    r"\)\s*(?:const\s*)?(?:&|&&)\s*(?:noexcept(?:\s*\([^)]*\))?)?\s*(?:\{|;)",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 6.8.4",
                            "Member functions returning references to their object should be ref-qualified appropriately.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(
                    r"^\s*(?:static\s+|const\s+|constexpr\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long|float|double|auto)\b[^;]*\bmain\b(?!\s*\()",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 6.0.4",
                            "The identifier main shall not be used for a function other than the global function main.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                bad_identifier_decl = re.match(
                    r"^\s*(?:class|struct|enum|typedef|using|(?:static|const|constexpr|extern|inline|volatile|unsigned|signed|long|short|int|char|float|double|bool|auto)\s+|(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:\s*<[^>]+>)?)\s+)+([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if bad_identifier_decl:
                    ident = bad_identifier_decl.group(1)
                    if re.search(r"__|^_[A-Z]|_$", ident):
                        violations.append(
                            Violation(
                                "Rule 5.10.1",
                                "User-defined identifiers shall have an appropriate form.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=ident,
                            )
                        )
                ptr_decl_generic = re.match(
                    r"^\s*(?:const\s+)?[A-Za-z_:\<\>\s]+\*\s*([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if ptr_decl_generic:
                    cpp2023_pointer_vars.add(ptr_decl_generic.group(1))
                del_match = re.search(
                    r"\bdelete\s+([A-Za-z_]\w*)\s*;", line_no_comment
                )
                if del_match:
                    cpp2023_deleted_ptrs[del_match.group(1)] = idx
                for pname, del_line in list(cpp2023_deleted_ptrs.items()):
                    if idx == del_line:
                        continue
                    if re.search(
                        rf"\*\s*{re.escape(pname)}\b|{re.escape(pname)}\s*->",
                        line_no_comment,
                    ):
                        violations.append(
                            Violation(
                                "Rule 6.8.1",
                                "An object shall not be accessed outside of its lifetime.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=pname,
                            )
                        )
                        cpp2023_deleted_ptrs.pop(pname, None)
                if (
                    file_path.suffix in {".h", ".hpp", ".hh", ".hxx"}
                    and brace_depth == 0
                ):
                    hdr_fn_def = re.match(
                        r"^\s*(?!inline\b)(?!static\b)(?:[\w:<>~]+\s+)+([A-Za-z_]\w*)\s*\([^;{}()]*\)\s*\{",
                        line_no_comment,
                    )
                    hdr_obj_def = re.match(
                        r"^\s*(?!inline\b)(?!static\b)(?!constexpr\b)(?:[\w:<>]+\s+)+([A-Za-z_]\w*)\s*=\s*[^;]+;",
                        line_no_comment,
                    )
                    if hdr_fn_def or hdr_obj_def:
                        header_trigger = (
                            hdr_fn_def.group(1)
                            if hdr_fn_def
                            else (hdr_obj_def.group(1) if hdr_obj_def else "")
                        )
                        violations.append(
                            Violation(
                                "Rule 6.2.4",
                                "A header file shall not contain definitions of functions or objects that are non-inline and have external linkage.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=header_trigger,
                            )
                        )
                typed_ptr_decl = re.match(
                    r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if typed_ptr_decl:
                    cpp2023_ptr_decl_types[typed_ptr_decl.group(2)] = (
                        typed_ptr_decl.group(1)
                    )
                void_ptr_decl = re.match(
                    r"^\s*(?:const\s+)?void\s*\*\s*([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if void_ptr_decl:
                    cpp2023_void_ptr_vars.add(void_ptr_decl.group(1))
                integral_decl = re.match(
                    r"^\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long)\b[^;=]*\b([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if integral_decl:
                    cpp2023_integral_vars.add(integral_decl.group(1))
                array_decl = re.match(
                    r"^\s*(?:const\s+)?(?:[A-Za-z_]\w*(?:\s+|::))*[A-Za-z_]\w*(?:\s*<[^;>]+>)?\s+([A-Za-z_]\w*)\s*\[\s*[^\]]*\s*\]\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if array_decl:
                    cpp2023_array_vars.add(array_decl.group(1))
                array_decl_sized = re.match(
                    r"^\s*(?:const\s+)?(?:[A-Za-z_]\w*(?:\s+|::))*[A-Za-z_]\w*(?:\s*<[^;>]+>)?\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if array_decl_sized:
                    cpp2023_array_sizes[array_decl_sized.group(1)] = int(
                        array_decl_sized.group(2)
                    )
                float_decl = re.match(
                    r"^\s*(?:const\s+)?(?:float|double|long\s+double)\b[^;=]*\b([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if float_decl:
                    cpp2023_float_vars.add(float_decl.group(1))
                bool_decl = re.match(
                    r"^\s*bool\s+([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if bool_decl:
                    cpp2023_bool_vars.add(bool_decl.group(1))
                lambda_match = re.search(
                    r"\[([^\]]*)\]\s*(?:\([^)]*\))?\s*\{([^}]*)\}",
                    line_no_comment,
                )
                if lambda_match:
                    capture_text = lambda_match.group(1).strip()
                    lambda_body = lambda_match.group(2)
                    default_capture = bool(
                        capture_text == "="
                        or capture_text == "&"
                        or capture_text.startswith("=,")
                        or capture_text.startswith("&,")
                    )
                    if default_capture:
                        violations.append(
                            Violation(
                                "Rule 8.1.2",
                                "Variables should be captured explicitly in a non-transient lambda.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=capture_text,
                            )
                        )
                        if re.search(r"\bthis\b|\*this|this->", lambda_body):
                            violations.append(
                                Violation(
                                    "Rule 8.1.1",
                                    "A non-transient lambda shall not implicitly capture this.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger="this",
                                )
                            )
                fnptr_cast_cpp = re.search(
                    r"\b(?:static_cast|reinterpret_cast)\s*<\s*[^>]*\(\s*\*[^)]*\)\s*\([^)]*\)\s*>\s*\(\s*([A-Za-z_]\w*)\s*\)",
                    line_no_comment,
                )
                cstyle_fnptr_cast_cpp = re.search(
                    r"\(\s*[^)]*\(\s*\*[^)]*\)\s*\([^)]*\)\s*\)\s*([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                cast_src = None
                if fnptr_cast_cpp:
                    cast_src = fnptr_cast_cpp.group(1)
                elif cstyle_fnptr_cast_cpp:
                    cast_src = cstyle_fnptr_cast_cpp.group(1)
                if (
                    cast_src
                    and cast_src in cpp_declared_functions
                    and "&" not in line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 7.11.3",
                            "A conversion from function type to pointer-to-function type shall only occur in appropriate contexts.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=cast_src,
                        )
                    )
                vbase_cast = re.search(
                    r"\b(?:static_cast|reinterpret_cast)\s*<\s*([A-Za-z_]\w*)\s*\*\s*>\s*\(\s*([A-Za-z_]\w*)\s*\)",
                    line_no_comment,
                )
                cstyle_vbase_cast = re.search(
                    r"\(\s*([A-Za-z_]\w*)\s*\*\s*\)\s*([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                cast_target = None
                cast_var = None
                if vbase_cast:
                    cast_target, cast_var = vbase_cast.group(
                        1
                    ), vbase_cast.group(2)
                elif cstyle_vbase_cast:
                    cast_target, cast_var = cstyle_vbase_cast.group(
                        1
                    ), cstyle_vbase_cast.group(2)
                if cast_target and cast_var:
                    src_type = cpp2023_ptr_decl_types.get(cast_var)
                    if src_type is None and cpp2023_virtual_base_types:
                        for lookback in range(max(0, idx - 4), idx):
                            prev_source_line = lines[lookback].split("//", 1)[
                                0
                            ]
                            m_prev = re.search(
                                rf"\b([A-Za-z_]\w*)\s*\*\s*{re.escape(cast_var)}\b",
                                prev_source_line,
                            )
                            if m_prev:
                                src_type = m_prev.group(1)
                                break
                    if (
                        src_type in cpp2023_virtual_base_types
                        and cast_target != src_type
                        and "dynamic_cast" not in line_no_comment
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.2.1",
                                "A virtual base class shall only be cast to a derived class by means of dynamic_cast.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=cast_var,
                            )
                        )
                ptr_from_array = re.match(
                    r"^\s*(?:const\s+)?[A-Za-z_]\w*\s*\*\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;",
                    line_no_comment,
                )
                if (
                    ptr_from_array
                    and ptr_from_array.group(2) in cpp2023_array_sizes
                ):
                    cpp2023_ptr_base[ptr_from_array.group(1)] = (
                        ptr_from_array.group(2)
                    )
                ptr_arith = re.match(
                    r"^\s*(?:const\s+)?[A-Za-z_]\w*\s*\*\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*([\+\-])\s*(\d+)\s*;",
                    line_no_comment,
                )
                if ptr_arith:
                    _dst, base, op, off_txt = ptr_arith.groups()
                    off = int(off_txt)
                    arr = cpp2023_ptr_base.get(
                        base, base if base in cpp2023_array_sizes else None
                    )
                    if arr is not None:
                        size = cpp2023_array_sizes[arr]
                        invalid = (op == "+" and off >= size) or (
                            op == "-" and off > 0
                        )
                        if invalid:
                            violations.append(
                                Violation(
                                    "Rule 8.7.1",
                                    "Pointer arithmetic shall not form an invalid pointer.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=arr,
                                )
                            )
                ptr_sub = re.search(
                    r"\b([A-Za-z_]\w*)\s*-\s*([A-Za-z_]\w*)\b", line_no_comment
                )
                if ptr_sub:
                    lhs, rhs = ptr_sub.group(1), ptr_sub.group(2)
                    lhs_arr = cpp2023_ptr_base.get(lhs)
                    rhs_arr = cpp2023_ptr_base.get(rhs)
                    if (
                        lhs_arr is not None
                        and rhs_arr is not None
                        and lhs_arr != rhs_arr
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.7.2",
                                "Subtraction between pointers shall only be applied to pointers that address elements of the same array.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=f"{lhs} {rhs}",
                            )
                        )
                ptr_rel = re.search(
                    r"\b([A-Za-z_]\w*)\s*(<=|>=|<|>)\s*([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if ptr_rel:
                    lhs, _op, rhs = ptr_rel.groups()
                    lhs_arr = cpp2023_ptr_base.get(lhs)
                    rhs_arr = cpp2023_ptr_base.get(rhs)
                    if (
                        lhs_arr is not None
                        and rhs_arr is not None
                        and lhs_arr != rhs_arr
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.9.1",
                                "The built-in relational operators >, >=, < and <= shall not be applied to objects of pointer type, except where they point to elements of the same array.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=f"{lhs} {rhs}",
                            )
                        )
                overlap_copy = re.search(
                    r"\b(?:std::|::)?(memcpy|memmove)\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,",
                    line_no_comment,
                )
                if overlap_copy:
                    _fn, dst_expr, src_expr = overlap_copy.groups()

                    def _base_obj(expr: str) -> Optional[str]:
                        e = expr.strip()
                        e = re.sub(r"^\([^)]*\)\s*", "", e)
                        e = e.lstrip("&*").strip()
                        e = re.split(r"[+\-\[]", e, maxsplit=1)[0].strip()
                        m = re.match(r"^([A-Za-z_]\w*)\b", e)
                        return m.group(1) if m else None

                    dst_base = _base_obj(dst_expr)
                    src_base = _base_obj(src_expr)
                    if (
                        dst_base is not None
                        and src_base is not None
                        and dst_base == src_base
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.18.1",
                                "An object or sub-object must not be copied to an overlapping object.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=dst_base,
                            )
                        )
                switch_open = re.search(
                    r"\bswitch\s*\([^)]*\)\s*\{", line_no_comment
                )
                if switch_open:
                    cpp2023_switch_ctx = {
                        "base_depth": brace_depth,
                        "switch_depth": brace_depth
                        + line_no_comment.count("{")
                        - line_no_comment.count("}"),
                        "seen_label": False,
                    }
                if cpp2023_switch_ctx is not None:
                    if re.search(
                        r"^\s*(?:case\b|default\s*:)", line_no_comment
                    ):
                        cpp2023_switch_ctx["seen_label"] = True
                    else:
                        # Rule 9.4.2 heuristic: statements before first case/default label.
                        if (
                            not cpp2023_switch_ctx["seen_label"]
                            and "switch" not in line_no_comment
                            and line_no_comment.strip()
                            and line_no_comment.strip() not in {"{", "}"}
                        ):
                            violations.append(
                                Violation(
                                    "Rule 9.4.2",
                                    "The structure of a switch statement shall be appropriate.",
                                    file_path,
                                    idx,
                                    detector="clang-fallback-scan",
                                    trigger=line_no_comment.strip(),
                                )
                            )
                            cpp2023_switch_ctx["seen_label"] = True
                    if (
                        brace_depth <= cpp2023_switch_ctx["base_depth"]
                        and "}" in line_no_comment
                    ):
                        cpp2023_switch_ctx = None
                range_for = re.search(
                    r"\bfor\s*\([^:;]*:\s*([^)]+)\)", line_no_comment
                )
                if range_for:
                    range_init = range_for.group(1)
                    call_count = len(
                        re.findall(
                            r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\(",
                            range_init,
                        )
                    )
                    if call_count > 1:
                        violations.append(
                            Violation(
                                "Rule 9.5.2",
                                "A for-range-initializer shall contain at most one function call.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=range_init.strip(),
                            )
                        )
                legacy_for = re.search(
                    r"\bfor\s*\(\s*([^;]*);\s*([^;]*);\s*([^)]+)\)",
                    line_no_comment,
                )
                if legacy_for and ":" not in line_no_comment:
                    init_clause, cond_clause, step_clause = legacy_for.groups()
                    looks_complex = (
                        "," in init_clause
                        or "," in cond_clause
                        or "," in step_clause
                        or bool(
                            re.search(
                                r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\(",
                                init_clause,
                            )
                        )
                        or bool(
                            re.search(
                                r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\(",
                                cond_clause,
                            )
                        )
                        or bool(
                            re.search(
                                r"\b[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s*\(",
                                step_clause,
                            )
                        )
                    )
                    if looks_complex:
                        violations.append(
                            Violation(
                                "Rule 9.5.1",
                                "Legacy for statements should be simple.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
                any_call = re.match(
                    r"^\s*([A-Za-z_]\w*)\s*\(([^;]*)\)\s*;", line_no_comment
                )
                if any_call and any_call.group(1) not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                    "return",
                    "sizeof",
                }:
                    args = [a.strip() for a in any_call.group(2).split(",")]
                    if any(arg in cpp2023_array_vars for arg in args):
                        violations.append(
                            Violation(
                                "Rule 7.11.2",
                                "An array passed as a function argument shall not decay to a pointer.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=any_call.group(1),
                            )
                        )
                pred_call = re.search(
                    r"\bstd::(?:find_if|count_if|any_of|all_of|none_of|remove_if|sort)\s*\([^;]*\[[^\]]*\]\s*\([^)]*\)\s*\{([^}]*)\}",
                    line_no_comment,
                )
                if pred_call:
                    body = pred_call.group(1)
                    has_side_effect = bool(
                        re.search(r"\+\+|--", body)
                        or re.search(r"(?<![=!<>])=(?!=)", body)
                    )
                    if has_side_effect:
                        violations.append(
                            Violation(
                                "Rule 28.3.1",
                                "Predicates shall not have persistent side effects.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=body.strip(),
                            )
                        )
                non_bool_from_bool = re.match(
                    r"^\s*(?!bool\b)(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long|float|double)\b[^=;]*=\s*([A-Za-z_]\w*|true|false)\s*;",
                    line_no_comment,
                )
                if non_bool_from_bool:
                    rhs = non_bool_from_bool.group(1)
                    if rhs in {"true", "false"} or rhs in cpp2023_bool_vars:
                        violations.append(
                            Violation(
                                "Rule 7.0.1",
                                "There shall be no conversion from type bool.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=rhs,
                            )
                        )
                bool_from_non_bool = re.match(
                    r"^\s*bool\b[^=;]*=\s*([A-Za-z_]\w*|\d+)\s*;",
                    line_no_comment,
                )
                if bool_from_non_bool:
                    rhs = bool_from_non_bool.group(1)
                    if rhs.isdigit() or rhs not in cpp2023_bool_vars:
                        violations.append(
                            Violation(
                                "Rule 7.0.2",
                                "There shall be no conversion to type bool.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=rhs,
                            )
                        )
                assign_match = re.match(
                    r"^\s*([A-Za-z_]\w*)\s*=\s*([^;]+);", line_no_comment
                )
                if assign_match:
                    lhs = assign_match.group(1)
                    rhs = assign_match.group(2)
                    rhs_is_float = bool(
                        re.search(r"\b\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]?\b", rhs)
                        or any(
                            re.search(rf"\b{re.escape(v)}\b", rhs)
                            for v in cpp2023_float_vars
                        )
                    )
                    rhs_is_integral = bool(
                        re.search(r"\b\d+[uU]?\b", rhs)
                        or any(
                            re.search(rf"\b{re.escape(v)}\b", rhs)
                            for v in cpp2023_integral_vars
                        )
                    )
                    if (lhs in cpp2023_integral_vars and rhs_is_float) or (
                        lhs in cpp2023_float_vars and rhs_is_integral
                    ):
                        violations.append(
                            Violation(
                                "Rule 7.0.6",
                                "Assignment between numeric types shall be appropriate.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=lhs,
                            )
                        )
                if re.search(
                    r"(?<!\+)\+(?!\+)\s*[A-Za-z_\(]", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 8.3.2",
                            "The built-in unary + operator should not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                cast_to_ptr = re.search(
                    r"\b(?:static_cast|reinterpret_cast)\s*<\s*[^>]*\*\s*>\s*\(\s*([A-Za-z_]\w*|0|NULL|nullptr)\s*\)",
                    line_no_comment,
                )
                if cast_to_ptr:
                    src = cast_to_ptr.group(1)
                    if (
                        src in {"0", "NULL"}
                        or src in cpp2023_void_ptr_vars
                        or src in cpp2023_integral_vars
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.2.6",
                                "An object with integral, enumerated, or pointer to void type shall not be cast to a pointer type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=src,
                            )
                        )
                c_style_ptr_cast = re.search(
                    r"\(\s*[^)]+\*\s*\)\s*([A-Za-z_]\w*|0|NULL)\b",
                    line_no_comment,
                )
                if c_style_ptr_cast:
                    src = c_style_ptr_cast.group(1)
                    if (
                        src in {"0", "NULL"}
                        or src in cpp2023_void_ptr_vars
                        or src in cpp2023_integral_vars
                    ):
                        violations.append(
                            Violation(
                                "Rule 8.2.6",
                                "An object with integral, enumerated, or pointer to void type shall not be cast to a pointer type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=src,
                            )
                        )
                cast_ptr_to_integral = re.search(
                    r"\breinterpret_cast\s*<\s*([^>]+)\s*>\s*\(\s*([A-Za-z_]\w*|&\s*[A-Za-z_]\w*)\s*\)",
                    line_no_comment,
                )
                if cast_ptr_to_integral:
                    dst_type = cast_ptr_to_integral.group(1).replace(" ", "")
                    src = cast_ptr_to_integral.group(2).replace(" ", "")
                    is_allowed = dst_type in {
                        "std::uintptr_t",
                        "std::intptr_t",
                    }
                    is_pointer_src = (
                        src.startswith("&") or src in cpp2023_pointer_vars
                    )
                    if is_pointer_src and not is_allowed:
                        violations.append(
                            Violation(
                                "Rule 8.2.8",
                                "An object pointer type shall not be cast to an integral type other than std::uintptr_t or std::intptr_t.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=src,
                            )
                        )
                if re.match(
                    r"^\s*(?:static\s+|const\s+|constexpr\s+)?[A-Za-z_:\<\>\s\*&]+\s+[A-Za-z_]\w*\s*\[[^\]]*\]\s*(?:=[^;]*)?;",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 11.3.1",
                            "Variables of array type should not be declared.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if brace_depth > 0 and re.match(
                    r"^\s*static\s+(?:const\s+)?[A-Za-z_:\<\>\s\*&]+\s+[A-Za-z_]\w*\s*(?:=[^;]*)?;",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 6.7.1",
                            "Local variables shall not have static storage duration.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if (
                    re.match(
                        r"^\s*(?!for\s*\()(?:static\s+|constexpr\s+|const\s+)?(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*(?:\s*<[^;>]+>)?[\s\*&]+[A-Za-z_]\w*[^;]*,[^;]*;\s*$",
                        line_no_comment,
                    )
                    and "(" not in line_no_comment.split(",", 1)[0]
                ):
                    violations.append(
                        Violation(
                            "Rule 10.0.1",
                            "A declaration should not declare more than one variable or member variable.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                enum_decl = re.match(
                    r"^\s*enum\s+(class\s+)?([A-Za-z_]\w*)?\s*(.*)$",
                    line_no_comment,
                )
                if enum_decl:
                    is_scoped = bool(enum_decl.group(1))
                    trailer = enum_decl.group(3) or ""
                    enum_name = enum_decl.group(2)
                    if not is_scoped:
                        violations.append(
                            Violation(
                                "Rule 10.2.2",
                                "Unscoped enumerations should not be declared.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=(enum_name or line_no_comment.strip()),
                            )
                        )
                    if ":" not in trailer:
                        violations.append(
                            Violation(
                                "Rule 10.2.1",
                                "An enumeration shall be defined with an explicit underlying type.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=(enum_name or line_no_comment.strip()),
                            )
                        )
                    body_match = re.search(r"\{([^}]*)\}", line_no_comment)
                    if body_match and not is_scoped and ":" not in trailer:
                        body = body_match.group(1)
                        for part in body.split(","):
                            name_match = re.match(
                                r"\s*([A-Za-z_]\w*)", part.strip()
                            )
                            if name_match:
                                cpp2023_unscoped_enum_constants.add(
                                    name_match.group(1)
                                )
                if re.search(r"\*\s*\*\s*\*", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 11.3.2",
                            "The declaration of an object should contain no more than two levels of pointer indirection.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                enum_numeric_use = re.match(
                    r"^\s*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long)\b[^=;]*=\s*([A-Za-z_]\w*)\b",
                    line_no_comment,
                )
                if (
                    enum_numeric_use
                    and enum_numeric_use.group(1)
                    in cpp2023_unscoped_enum_constants
                ):
                    violations.append(
                        Violation(
                            "Rule 10.2.3",
                            "The numeric value of an unscoped enumeration with no fixed underlying type shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=enum_numeric_use.group(1),
                        )
                    )
                if re.search(r"\bconst_cast\s*<", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 8.2.3",
                            "A cast shall not remove any const or volatile qualification from the type accessed via a pointer or by reference.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(r"\breinterpret_cast\s*<", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 8.2.5",
                            "reinterpret_cast shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(
                    r"\breinterpret_cast\s*<\s*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|long\s+long)\b[^>]*>\s*\(\s*(?:&\s*[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\)",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 8.2.7",
                            "A cast should not convert a pointer type to an integral type.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(r"\?\?[=/'\(\)\!<>\-]", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 5.0.1",
                            "Trigraph-like sequences should not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.match(
                    r"^\s*(?:static_cast|reinterpret_cast|const_cast|dynamic_cast)\s*<[^>]+>\s*\([^)]*\)\s*;\s*$",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 9.2.1",
                            "An explicit type conversion shall not be an expression statement.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if file_path.suffix in {
                    ".h",
                    ".hpp",
                    ".hh",
                    ".hxx",
                } and re.search(r"\bnamespace\s*\{\s*$", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 10.3.1",
                            "There should be no unnamed namespaces in header files.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(r"\bstd::auto_ptr\s*<", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 4.1.2",
                            "Deprecated features should not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger="std::auto_ptr",
                        )
                    )
                if re.search(
                    r"\b\d+[lL]{1}\b", line_no_comment
                ) and not re.search(
                    r"\b\d+(?:u|U)?(?:ll|LL|Ll|lL)\b", line_no_comment
                ):
                    violations.append(
                        Violation(
                            "Rule 5.13.6",
                            "An integer-literal of type long long shall not use a single L or l in any suffix.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                if re.search(r"(?<![\w:])NULL(?![\w:])", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 7.11.1",
                            "nullptr shall be the only form of the null-pointer-constant.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger="NULL",
                        )
                    )
                template_decl = re.match(
                    r"^\s*template\s*<([^>]+)>", line_no_comment
                )
                if template_decl:
                    template_params_text = template_decl.group(1)
                    cpp2023_pending_template_params = set(
                        re.findall(
                            r"\b(?:typename|class)\s+([A-Za-z_]\w*)\b",
                            template_params_text,
                        )
                    )
                op_delete_decl = re.match(
                    r"^\s*(?:inline\s+)?void\s+operator\s+delete(?:\s*\[\s*\])?\s*\(([^)]*)\)",
                    line_no_comment,
                )
                if op_delete_decl:
                    params = op_delete_decl.group(1)
                    if "std::size_t" in params or re.search(
                        r"\bsize_t\b", params
                    ):
                        cpp2023_sized_delete_line = (
                            cpp2023_sized_delete_line or idx
                        )
                    else:
                        cpp2023_unsized_delete_line = (
                            cpp2023_unsized_delete_line or idx
                        )
                fn_start = re.match(
                    r"^\s*(?:[\w:<>~,\*&\s]+)\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const\b[^{};]*)?\{",
                    line_no_comment,
                )
                if fn_start and fn_start.group(1) not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                }:
                    cpp2023_fn_end_depth = brace_depth + line_no_comment.count(
                        "{"
                    )
                    cpp2023_moved_vars = {}
                    if cpp2023_pending_template_params:
                        param_text = fn_start.group(2)
                        fwd_params = set()
                        for tname in cpp2023_pending_template_params:
                            for m in re.finditer(
                                rf"\b{re.escape(tname)}\s*&&\s*([A-Za-z_]\w*)",
                                param_text,
                            ):
                                fwd_params.add(m.group(1))
                        if fwd_params:
                            cpp2023_forward_ctx = {
                                "line": idx,
                                "end_depth": cpp2023_fn_end_depth,
                                "params": {
                                    p: {
                                        "forwarded": False,
                                        "used_nonforward": False,
                                    }
                                    for p in fwd_params
                                },
                            }
                        else:
                            cpp2023_forward_ctx = None
                    else:
                        cpp2023_forward_ctx = None
                    cpp2023_pending_template_params = None
                if cpp2023_forward_ctx:
                    for pname, pstate in cast(
                        Dict[str, Dict[str, bool]],
                        cpp2023_forward_ctx["params"],
                    ).items():
                        if re.search(
                            rf"\bstd::forward\s*<[^>]*>\s*\(\s*{re.escape(pname)}\s*\)",
                            line_no_comment,
                        ):
                            pstate["forwarded"] = True
                        if re.search(
                            rf"\b{re.escape(pname)}\b", line_no_comment
                        ) and not re.search(
                            rf"\bstd::forward\s*<[^>]*>\s*\(\s*{re.escape(pname)}\s*\)",
                            line_no_comment,
                        ):
                            pstate["used_nonforward"] = True
                if cpp2023_fn_end_depth is not None:
                    for moved_var, move_line in list(
                        cpp2023_moved_vars.items()
                    ):
                        if re.search(
                            rf"\b{re.escape(moved_var)}\b", line_no_comment
                        ):
                            if not re.search(
                                rf"\bstd::(?:move|forward)\s*\(\s*{re.escape(moved_var)}\s*\)",
                                line_no_comment,
                            ) and not re.search(
                                rf"\b{re.escape(moved_var)}\s*=",
                                line_no_comment,
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 28.6.3",
                                        "An object shall not be used while in a potentially moved-from state.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=moved_var,
                                    )
                                )
                                del cpp2023_moved_vars[moved_var]
                    for m_move in re.finditer(
                        r"\bstd::move\s*\(\s*([A-Za-z_]\w*)\s*\)",
                        line_no_comment,
                    ):
                        cpp2023_moved_vars[m_move.group(1)] = idx
                ptr_decl = re.match(
                    r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\s*(?:[=;,\[])",
                    line_no_comment,
                )
                if (
                    ptr_decl
                    and ptr_decl.group(1)
                    in cpp2023_incomplete_class_candidates
                ):
                    cpp2023_ptr_to_incomplete_class[ptr_decl.group(2)] = (
                        ptr_decl.group(1)
                    )
                del_match = re.search(
                    r"\bdelete\s+([A-Za-z_]\w*)\s*;", line_no_comment
                )
                if del_match:
                    deleted_var = del_match.group(1)
                    if deleted_var in cpp2023_ptr_to_incomplete_class:
                        violations.append(
                            Violation(
                                "Rule 21.6.5",
                                "A pointer to an incomplete class type shall not be deleted.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=deleted_var,
                            )
                        )
                const_decl = re.match(
                    r"^\s*const\b[^;()]*\b([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
                    line_no_comment,
                )
                if const_decl:
                    cpp2023_const_vars.add(const_decl.group(1))
                for move_call in re.finditer(
                    r"\bstd::move\s*\(\s*([A-Za-z_]\w*)\s*\)", line_no_comment
                ):
                    moved_var = move_call.group(1)
                    if moved_var in cpp2023_const_vars:
                        violations.append(
                            Violation(
                                "Rule 28.6.1",
                                "The argument to std::move shall be a non-const lvalue.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=moved_var,
                            )
                        )
                seek_m = re.search(
                    r"\b(?:std::|::)?(?:fseek|fsetpos|rewind|fflush)\s*\(([^)]*)\)",
                    line_no_comment,
                )
                if seek_m:
                    seek_args = [a.strip() for a in seek_m.group(1).split(",")]
                    if seek_args:
                        stream_m = re.search(
                            r"\b([A-Za-z_]\w*)\b", seek_args[0]
                        )
                        if stream_m:
                            cpp2023_stream_last_io.pop(stream_m.group(1), None)
                io_m = re.search(
                    r"\b(?:std::|::)?(fread|fgets|fgetc|getc|fscanf|fwrite|fputs|fputc|putc|fprintf)\s*\(([^)]*)\)",
                    line_no_comment,
                )
                if io_m:
                    fn = io_m.group(1)
                    args = [a.strip() for a in io_m.group(2).split(",")]
                    stream_arg = None
                    if (
                        fn
                        in {
                            "fread",
                            "fgets",
                            "fwrite",
                            "fputs",
                            "fputc",
                            "putc",
                        }
                        and args
                    ):
                        stream_arg = args[-1]
                    elif fn in {"fgetc", "getc"} and args:
                        stream_arg = args[0]
                    elif fn in {"fprintf", "fscanf"} and args:
                        stream_arg = args[0]
                    if stream_arg:
                        stream_m = re.search(r"\b([A-Za-z_]\w*)\b", stream_arg)
                        if stream_m:
                            stream_var = stream_m.group(1)
                            current_op = (
                                "read"
                                if fn
                                in {
                                    "fread",
                                    "fgets",
                                    "fgetc",
                                    "getc",
                                    "fscanf",
                                }
                                else "write"
                            )
                            previous_op = cpp2023_stream_last_io.get(
                                stream_var
                            )
                            if previous_op and previous_op != current_op:
                                violations.append(
                                    Violation(
                                        "Rule 30.0.2",
                                        "Reads and writes on the same file stream shall be separated by a positioning operation.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=stream_var,
                                    )
                                )
                            cpp2023_stream_last_io[stream_var] = current_op
                # Rule 22.3.1: assert shall not use constant-expression.
                assert_m = re.search(
                    r"\bassert\s*\(\s*([^)]+)\s*\)", line_no_comment
                )
                if assert_m:
                    expr = assert_m.group(1).strip()
                    if re.match(r"^(?:0|1|true|false|\d+[uUlL]*)$", expr):
                        violations.append(
                            Violation(
                                "Rule 22.3.1",
                                "The assert macro shall not be used with a constant-expression.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=expr,
                            )
                        )
                # Rule 22.4.1: only zero shall be assigned to errno.
                errno_assign = re.search(
                    r"\berrno\s*=\s*([^;]+);", line_no_comment
                )
                if errno_assign:
                    rhs = errno_assign.group(1).strip()
                    if rhs not in {"0", "(0)"}:
                        violations.append(
                            Violation(
                                "Rule 22.4.1",
                                "The literal value zero shall be the only value assigned to errno.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=rhs,
                            )
                        )
                # Rule 25.5.1: setlocale and std::locale::global shall not be called.
                if re.search(
                    r"\bsetlocale\s*\(", line_no_comment
                ) or re.search(r"\bstd::locale::global\s*\(", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 25.5.1",
                            "The setlocale and std::locale::global functions shall not be called.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
                # Rule 25.5.2 / 25.5.3: pointer-return usage constraints (heuristic).
                cpp_ptr_decl = re.search(
                    r"\b(?:(const)\s+)?(?:char|std::lconv|lconv|std::tm|tm)\s*\*\s*([A-Za-z_]\w*)\s*=\s*(?:std::)?([A-Za-z_]\w*)\s*\(",
                    line_no_comment,
                )
                cpp_ptr_assign = re.search(
                    r"^\s*([A-Za-z_]\w*)\s*=\s*(?:std::)?([A-Za-z_]\w*)\s*\(",
                    line_no_comment,
                )
                if cpp_ptr_decl:
                    is_const = bool(cpp_ptr_decl.group(1))
                    var_name = cpp_ptr_decl.group(2)
                    fn_name = cpp_ptr_decl.group(3)
                    if fn_name in cpp_const_pointer_functions and not is_const:
                        violations.append(
                            Violation(
                                "Rule 25.5.2",
                                "Pointers returned by localeconv/getenv/setlocale/strerror shall be used as pointer-to-const.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=var_name,
                            )
                        )
                    if fn_name in cpp_volatile_pointer_functions:
                        if fn_name in cpp_last_return_ptr_var:
                            prev_var, prev_line = cpp_last_return_ptr_var[
                                fn_name
                            ]
                            cpp_stale_return_ptr_var[prev_var] = (
                                fn_name,
                                prev_line,
                            )
                        cpp_last_return_ptr_var[fn_name] = (var_name, idx)
                elif cpp_ptr_assign:
                    var_name = cpp_ptr_assign.group(1)
                    fn_name = cpp_ptr_assign.group(2)
                    if fn_name in cpp_volatile_pointer_functions:
                        if fn_name in cpp_last_return_ptr_var:
                            prev_var, prev_line = cpp_last_return_ptr_var[
                                fn_name
                            ]
                            cpp_stale_return_ptr_var[prev_var] = (
                                fn_name,
                                prev_line,
                            )
                        cpp_last_return_ptr_var[fn_name] = (var_name, idx)
                for stale_var in list(cpp_stale_return_ptr_var.keys()):
                    if stale_var in line_no_comment and not re.search(
                        rf"=\s*{re.escape(stale_var)}\s*;", line_no_comment
                    ):
                        fn_name, _ = cpp_stale_return_ptr_var[stale_var]
                        violations.append(
                            Violation(
                                "Rule 25.5.3",
                                f"The pointer returned by '{fn_name}' shall not be used following a subsequent call to the same function.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=stale_var,
                            )
                        )
                        del cpp_stale_return_ptr_var[stale_var]
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\b(?:std::|::)?(isalnum|isalpha|isblank|iscntrl|isdigit|isgraph|islower|isprint|ispunct|isspace|isupper|isxdigit|tolower|toupper|iswalpha|iswalnum|iswspace|iswlower|iswupper|towupper|towlower)\s*\(",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 24.5.1",
                        "The character handling functions from <cctype> and <cwctype> shall not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\b(?:std::|::)?(memcpy|memmove|memcmp)\s*\(",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 24.5.2",
                        "The C++ Standard Library functions memcpy, memmove and memcmp from <cstring> shall not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\b(?:std::|::)?(strcpy|strncpy|strcat|strncat|strcmp|strncmp|strlen|strchr|strstr|wcscpy|wcsncpy|wcscat|wcsncat|wcscmp|wcsncmp)\s*\(",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 21.2.2",
                        "The string handling functions from <cstring>, <cstdlib>, <cwchar> and <cinttypes> shall not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\b(?:std::|::)?(abort|exit|quick_exit|_Exit|terminate)\s*\(",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 18.5.2",
                        "Program-terminating functions should not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\b(?:std::|::)?(malloc|calloc|realloc|free)\s*\(",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 21.6.1",
                        "Dynamic memory should not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
                violations.append(
                    Violation(
                        "Rule 21.6.2",
                        "Dynamic memory shall be managed automatically.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
                if re.search(r"\b(?:std::|::)?realloc\s*\(", line_no_comment):
                    violations.append(
                        Violation(
                            "Rule 21.6.3",
                            "Advanced memory management shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"(?<![\w:])new\s+|(?<![\w:])delete\s+", line_no_comment
                )
            ):
                violations.append(
                    Violation(
                        "Rule 21.6.1",
                        "Dynamic memory should not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
                violations.append(
                    Violation(
                        "Rule 21.6.2",
                        "Dynamic memory shall be managed automatically.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
                if re.search(r"\bnew\s*\[", line_no_comment) or re.search(
                    r"\boperator\s+new\b|\boperator\s+delete\b",
                    line_no_comment,
                ):
                    violations.append(
                        Violation(
                            "Rule 21.6.3",
                            "Advanced memory management shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"\bstd::(?:shared_ptr|unique_ptr)\s*<[^>]+>\s*\w*\s*\(\s*new\s+",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 23.11.1",
                        "The raw pointer constructors of std::shared_ptr and std::unique_ptr should not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and (
                    re.match(r"^\s*#\s*pragma\b", line_no_comment)
                    or re.search(r"\b_Pragma\s*\(", line_no_comment)
                )
            ):
                violations.append(
                    Violation(
                        "Rule 19.6.1",
                        "The #pragma directive and the _Pragma operator should not be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(r"\bstd::vector\s*<\s*bool\b", line_no_comment)
            ):
                violations.append(
                    Violation(
                        "Rule 26.3.1",
                        "std::vector should not be specialized with bool.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and profile_key == "cpp2023"
                and re.search(
                    r"^\s*(?:std::)?(?:remove|remove_if|unique)\s*\(|^\s*[^=;]+\.\s*empty\s*\(\s*\)\s*;",
                    line_no_comment,
                )
            ):
                violations.append(
                    Violation(
                        "Rule 28.6.4",
                        "The result of std::remove, std::remove_if, std::unique and empty shall be used.",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and re.match(r"^\s*#\s*(define|undef)\b", line)
                and brace_depth > 0
            ):
                violations.append(
                    Violation(
                        "Rule 16-0-2",
                        "Macros shall only be #define'd or #undef'd in the global namespace.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
            if re.match(r"^\s*#\s*define\b", line):
                m_def = re.match(
                    r"^\s*#\s*define\s+([A-Za-z_]\w*)\b", line_no_comment
                )
                if m_def:
                    cpp_defined_macros_in_file.add(m_def.group(1))
                if (
                    is_cpp_file
                    and m_def
                    and m_def.group(1) in cpp_stdlib_reserved_macro_or_name
                ):
                    violations.append(
                        Violation(
                            "Rule 17-0-1",
                            f"Reserved standard library macro/name shall not be defined or redefined: '{m_def.group(1)}'.",
                            file_path,
                            idx,
                            trigger=m_def.group(1),
                        )
                    )
                hash_op_count = line_no_comment.count("##") + (
                    line_no_comment.count("#") - 1
                    if "#" in line_no_comment
                    else 0
                )
                if hash_op_count > 1:
                    violations.append(
                        Violation(
                            "Rule 16-3-1",
                            "There shall be at most one occurrence of the # or ## preprocessor operators in a single macro definition.",
                            file_path,
                            idx,
                            trigger=(
                                m_def.group(1)
                                if m_def
                                else line_no_comment.strip()
                            ),
                        )
                    )
                # Rule 20.10: # and ## operators should not be used.
                macro_def_match = re.match(
                    r"^\s*#\s*define\s+[A-Za-z_]\w*(?:\s*\([^)]*\))?\s*(.*)$",
                    line_no_comment,
                )
                macro_body = (
                    macro_def_match.group(1) if macro_def_match else ""
                )
                if "##" in macro_body or re.search(
                    r"(?:^|[^#])#[A-Za-z_]\w*", macro_body
                ):
                    violations.append(
                        Violation(
                            "Rule 20.10",
                            "The # and ## preprocessor operators should not be used.",
                            file_path,
                            idx,
                            trigger=(
                                m_def.group(1)
                                if m_def
                                else line_no_comment.strip()
                            ),
                        )
                    )
                # Rule 20.7: function-like macro parameter uses should be parenthesized.
                fn_macro_match = re.match(
                    r"^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(.*)$",
                    line_no_comment,
                )
                if fn_macro_match:
                    param_text = fn_macro_match.group(2)
                    body = fn_macro_match.group(3)
                    params = [
                        p.strip()
                        for p in param_text.split(",")
                        if p.strip() and p.strip() != "..."
                    ]
                    for param in params:
                        for occ in re.finditer(
                            rf"\b{re.escape(param)}\b", body
                        ):
                            left = body[: occ.start()].rstrip()
                            right = body[occ.end() :].lstrip()
                            if not (
                                left.endswith("(") and right.startswith(")")
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 20.7",
                                        "In the definition of a function-like macro, each instance of a parameter should be enclosed in parentheses.",
                                        file_path,
                                        idx,
                                        trigger=param,
                                    )
                                )
                                if profile_key == "cpp2023":
                                    violations.append(
                                        Violation(
                                            "Rule 19.3.4",
                                            "Parentheses shall be used to ensure macro arguments are expanded appropriately.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=param,
                                        )
                                    )
                                break
                        else:
                            continue
                        break
                    # Rule 20.11: parameter immediately after # shall not be followed by ##.
                    for param in params:
                        if re.search(rf"#\s*{re.escape(param)}\s*##", body):
                            violations.append(
                                Violation(
                                    "Rule 20.11",
                                    "A macro parameter immediately following a # operator shall not immediately be followed by a ## operator.",
                                    file_path,
                                    idx,
                                    trigger=param,
                                )
                            )
                            break
                    # Rule 23.7: macro-expanded generic selection should evaluate its argument once.
                    if "_Generic" in body:
                        for param in params:
                            use_count = len(
                                re.findall(rf"\b{re.escape(param)}\b", body)
                            )
                            if use_count > 1:
                                violations.append(
                                    Violation(
                                        "Rule 23.7",
                                        "A generic selection that is expanded from a macro should evaluate its argument only once.",
                                        file_path,
                                        idx,
                                        detector="clang-fallback-scan",
                                        trigger=param,
                                    )
                                )
                                break
                    # Rule 20.12: parameter used with #/## should only appear as #/## operand.
                    hashed_params = set()
                    normal_params = set()
                    for param in params:
                        if (
                            re.search(rf"#\s*{re.escape(param)}\b", body)
                            or re.search(rf"\b{re.escape(param)}\s*##", body)
                            or re.search(rf"##\s*{re.escape(param)}\b", body)
                        ):
                            hashed_params.add(param)
                        stripped_body = re.sub(
                            rf"#\s*{re.escape(param)}\b|##\s*{re.escape(param)}\b|\b{re.escape(param)}\s*##",
                            " ",
                            body,
                        )
                        if re.search(
                            rf"\b{re.escape(param)}\b", stripped_body
                        ):
                            normal_params.add(param)
                    mixed = hashed_params & normal_params
                    if mixed:
                        param = sorted(mixed)[0]
                        violations.append(
                            Violation(
                                "Rule 20.12",
                                f"Macro parameter '{param}' is used as operand to #/## and also in normal replacement context.",
                                file_path,
                                idx,
                                trigger=param,
                            )
                        )
                        if profile_key == "cpp2023":
                            mixed_indexes = {
                                i for i, p in enumerate(params) if p in mixed
                            }
                            if mixed_indexes:
                                cpp2023_mixed_use_macro_params[
                                    fn_macro_match.group(1)
                                ] = mixed_indexes
            if is_cpp_file and re.match(r"^\s*#\s*undef\b", line):
                m_undef = re.match(
                    r"^\s*#\s*undef\s+([A-Za-z_]\w*)\b", line_no_comment
                )
                if (
                    m_undef
                    and m_undef.group(1) in cpp_stdlib_reserved_macro_or_name
                ):
                    violations.append(
                        Violation(
                            "Rule 17-0-1",
                            f"Reserved standard library macro/name shall not be undefined: '{m_undef.group(1)}'.",
                            file_path,
                            idx,
                            trigger=m_undef.group(1),
                        )
                    )
                if (
                    profile_key == "cpp2023"
                    and m_undef
                    and m_undef.group(1) not in cpp_defined_macros_in_file
                ):
                    violations.append(
                        Violation(
                            "Rule 19.0.4",
                            "#undef should only be used for macros defined previously in the same file.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=m_undef.group(1),
                        )
                    )
            if not re.match(r"^\s*#", line_no_comment):
                if (
                    is_cpp_file
                    and profile_key == "cpp2023"
                    and cpp2023_mixed_use_macro_params
                ):
                    for (
                        macro_name,
                        idx_set,
                    ) in cpp2023_mixed_use_macro_params.items():
                        for call in re.finditer(
                            rf"\b{re.escape(macro_name)}\s*\(([^)]*)\)",
                            line_no_comment,
                        ):
                            args = [
                                a.strip() for a in call.group(1).split(",")
                            ]
                            for midx in idx_set:
                                if midx >= len(args):
                                    continue
                                arg = args[midx]
                                if (
                                    re.match(r"^[A-Za-z_]\w*$", arg)
                                    and arg in cpp_defined_macros_in_file
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 19.3.3",
                                            "The argument to a mixed-use macro parameter shall not be subject to further expansion.",
                                            file_path,
                                            idx,
                                            detector="clang-fallback-scan",
                                            trigger=arg,
                                        )
                                    )
                                    break
                inv_match = re.search(
                    r"\b([A-Za-z_]\w*)\s*\((.*)\)", line_no_comment
                )
                if inv_match:
                    args_text = inv_match.group(2)
                    if re.search(
                        r"#\s*(define|if|ifdef|ifndef|elif|else|endif|include|undef|pragma)\b",
                        args_text,
                    ):
                        violations.append(
                            Violation(
                                "Rule 20.6",
                                "Arguments to a function-like macro shall not contain tokens that look like preprocessing directives.",
                                file_path,
                                idx,
                                trigger=args_text,
                            )
                        )
            if is_cpp_file and re.match(r"^\s*#\s*pragma\b", line):
                prev_idx = idx - 2
                documented = False
                while prev_idx >= 0:
                    prev_doc_line = lines[prev_idx].strip()
                    if not prev_doc_line:
                        prev_idx -= 1
                        continue
                    documented = (
                        prev_doc_line.startswith("//")
                        or prev_doc_line.startswith("/*")
                        or prev_doc_line.endswith("*/")
                    )
                    break
                if not documented:
                    violations.append(
                        Violation(
                            "Rule 16-6-1",
                            "All uses of the #pragma directive shall be documented and explained.",
                            file_path,
                            idx,
                            trigger=line_no_comment.strip(),
                        )
                    )
            if is_cpp_file and "throw NULL" in line:
                violations.append(
                    Violation(
                        "Rule 15-1-2",
                        "NULL shall not be thrown explicitly.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
            if (
                is_cpp_file
                and re.match(r"^\s*#\s*(if|elif)\b", line)
                and "defined" in line
            ):
                test_line = line
                test_line = re.sub(
                    r"defined\s*\(\s*[A-Za-z_]\w*\s*\)", " ", test_line
                )
                test_line = re.sub(r"defined\s+[A-Za-z_]\w*", " ", test_line)
                if "defined" in test_line:
                    violations.append(
                        Violation(
                            "Rule 16-1-1",
                            "The defined preprocessor operator shall only be used in one of the two standard forms.",
                            file_path,
                            idx,
                            trigger=line_no_comment.strip(),
                        )
                    )
                    if profile_key == "cpp2023":
                        violations.append(
                            Violation(
                                "Rule 19.1.1",
                                "The defined preprocessor operator shall be used appropriately.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=line_no_comment.strip(),
                            )
                        )
            if is_cpp_file and re.search(r"\boffsetof\s*\(", line):
                violations.append(
                    Violation(
                        "Rule 18-2-1",
                        "The macro offsetof shall not be used.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
                if profile_key == "cpp2023":
                    violations.append(
                        Violation(
                            "Rule 21.2.4",
                            "The macro offsetof shall not be used.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=line_no_comment.strip(),
                        )
                    )
            if is_cpp_file and re.search(r"\berrno\b", line):
                violations.append(
                    Violation(
                        "Rule 19-3-1",
                        "The error indicator errno shall not be used.",
                        file_path,
                        idx,
                        trigger=line_no_comment.strip(),
                    )
                )
            if "bsearch(" in line or "qsort(" in line:
                violations.append(
                    Violation(
                        "Rule 21.9",
                        "The bsearch and qsort functions of <stdlib.h> shall not be used",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if re.search(
                r"\(\s*[A-Za-z_][\w\s]*\*\s*\)\s*[0-9]*\.[0-9]+([eE][+-]?[0-9]+)?[fFlL]?\b",
                line,
            ):
                violations.append(
                    Violation(
                        "Rule 11.7",
                        "A cast shall not be performed between pointer to object and a non-integer arithmetic type",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            if re.search(r"\[\s*\]\s*=\s*\{[^}]*\[[^]]+\]\s*=", line):
                violations.append(
                    Violation(
                        "Rule 9.5",
                        "Array initialized with designated initializers must have explicit size",
                        file_path,
                        idx,
                        detector="clang-fallback-scan",
                        trigger=line_no_comment.strip(),
                    )
                )
            brace_depth += line.count("{") - line.count("}")
            if is_cpp_file and profile_key == "cpp2023":
                while (
                    cpp2023_catch_depth_stack
                    and brace_depth < cpp2023_catch_depth_stack[-1]
                ):
                    cpp2023_catch_depth_stack.pop()
                if cpp2023_current_fn and brace_depth < cast(
                    int, cpp2023_current_fn.get("end_depth", -1)
                ):
                    if cpp2023_current_fn.get(
                        "has_try"
                    ) and not cpp2023_current_fn.get("has_catch_all"):
                        violations.append(
                            Violation(
                                "Rule 18.3.1",
                                "There should be at least one exception handler to catch all otherwise unhandled exceptions.",
                                file_path,
                                cast(
                                    int,
                                    cpp2023_current_fn.get("start_line", idx),
                                ),
                                detector="clang-fallback-scan",
                                trigger=str(
                                    cpp2023_current_fn.get("start_line", idx)
                                ),
                            )
                        )
                    cpp2023_current_fn = None
                    cpp2023_labels_in_fn = {}
                if (
                    cpp2023_forward_ctx
                    and brace_depth < cpp2023_forward_ctx["end_depth"]
                ):
                    for pname, pstate in cast(
                        Dict[str, Dict[str, bool]],
                        cpp2023_forward_ctx["params"],
                    ).items():
                        if (
                            pstate["used_nonforward"]
                            and not pstate["forwarded"]
                        ):
                            violations.append(
                                Violation(
                                    "Rule 28.6.2",
                                    "Forwarding references and std::forward shall be used together.",
                                    file_path,
                                    cast(int, cpp2023_forward_ctx["line"]),
                                    detector="clang-fallback-scan",
                                    trigger=pname,
                                )
                            )
                            break
                    cpp2023_forward_ctx = None
                if (
                    cpp2023_fn_end_depth is not None
                    and brace_depth < cpp2023_fn_end_depth
                ):
                    cpp2023_fn_end_depth = None
                    cpp2023_moved_vars = {}
            if not is_cpp_file:
                while (
                    c_union_depth_stack
                    and brace_depth < c_union_depth_stack[-1]
                ):
                    c_union_depth_stack.pop()
                if c_current_fn and brace_depth < c_current_fn.get(
                    "end_depth", -1
                ):
                    if c_current_fn.get(
                        "looks_noreturn"
                    ) and not c_current_fn.get("is_noreturn"):
                        violations.append(
                            Violation(
                                "Rule 17.11",
                                "A function that never returns should be declared with a _Noreturn function specifier.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=c_current_fn.get("name", ""),
                            )
                        )
                    for _, lock_line in c_current_fn.get(
                        "mtx_locked", {}
                    ).items():
                        violations.append(
                            Violation(
                                "Rule 22.16",
                                "All mutex objects locked by a thread shall be explicitly unlocked by the same thread.",
                                file_path,
                                lock_line,
                                detector="clang-fallback-scan",
                                trigger="mutex",
                            )
                        )
                    c_current_fn = None
        if not is_cpp_file:
            if c_errno_used_in_file and c_pending_errno_call is not None:
                prev_name, prev_line = c_pending_errno_call
                violations.append(
                    Violation(
                        "Rule 22.9",
                        f"The value of errno shall be tested against zero after calling an errno-setting-function ('{prev_name}').",
                        file_path,
                        prev_line,
                        detector="clang-fallback-scan",
                        trigger=prev_name,
                    )
                )
            # Rule 2.8: file-scope object definition appears unused (heuristic).
            for obj_name, obj_line in c_file_scope_objects:
                obj_occurrences = re.findall(
                    rf"\b{re.escape(obj_name)}\b", source_text
                )
                if len(obj_occurrences) <= 1:
                    violations.append(
                        Violation(
                            "Rule 2.8",
                            "A project should not contain unused object definitions.",
                            file_path,
                            obj_line,
                            detector="clang-fallback-scan",
                            trigger=obj_name,
                        )
                    )
            # Rule 8.15: same object declarations must specify same explicit alignment.
            for obj_name, specs in c_align_specs.items():
                vals = {v for v, _ in specs}
                if len(vals) > 1:
                    for _, spec_line in specs:
                        violations.append(
                            Violation(
                                "Rule 8.15",
                                "All declarations of an object with an explicit alignment specification shall specify the same alignment.",
                                file_path,
                                spec_line,
                                detector="clang-fallback-scan",
                                trigger=obj_name,
                            )
                        )
            # Rule 12.6: direct member access on atomic aggregate object.
            for obj_name, decl_line in c_atomic_aggregate_objects:
                for idx, raw in enumerate(lines, start=1):
                    line_nc = raw.split("//", 1)[0]
                    if re.search(rf"\b{re.escape(obj_name)}\s*\.", line_nc):
                        violations.append(
                            Violation(
                                "Rule 12.6",
                                "Structure and union members of atomic objects shall not be directly accessed.",
                                file_path,
                                idx,
                                detector="clang-fallback-scan",
                                trigger=obj_name,
                            )
                        )
                        break
            # Rule 17.12: function identifier should be used with & or call list.
            c_known_funcs = {
                # common C library and compiler intrinsics/macros that may appear without local declarations
                "sizeof",
                "_Alignof",
                "_Generic",
                "__builtin_expect",
                "__builtin_prefetch",
                "__builtin_unreachable",
                "__builtin_types_compatible_p",
                "memcpy",
                "memmove",
                "memcmp",
                "memset",
                "strtol",
                "strtoul",
                "strtoll",
                "strtoull",
                "fputs",
                "fgetc",
                "isalpha",
                "srand",
                "rand",
            } | cpp_stdlib_reserved_macro_or_name

            # Rule 17.3: use of undeclared function identifier (source-scan fallback).
            for idx, raw in enumerate(lines, start=1):
                line_nc = raw.split("//", 1)[0]
                if not line_nc.strip() or line_nc.lstrip().startswith("#"):
                    continue
                # Skip function declarations/definitions and function pointer declarators.
                if re.search(
                    r"^\s*(?:extern\s+)?(?:_Noreturn\s+)?(?:[A-Za-z_]\w*[\s\*]+)+[A-Za-z_]\w*\s*\([^;{}]*\)\s*[;{]\s*$",
                    line_nc,
                ):
                    continue
                if "(*" in line_nc and ")" in line_nc and "=" not in line_nc:
                    continue
                # Keep this conservative: trigger on plain call statements only.
                m_stmt = re.match(
                    r"^\s*(?:(?:[A-Za-z_]\w*|\([^)]*\))\s*=\s*)?(?:\(\s*void\s*\)\s*)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*$",
                    line_nc,
                )
                if not m_stmt:
                    continue
                fn = m_stmt.group(1)
                if fn in {"if", "for", "while", "switch", "return", "sizeof"}:
                    continue
                if fn.startswith("_"):
                    continue
                if fn.isupper():
                    continue
                if fn.startswith(("thrd_", "mtx_", "cnd_", "tss_", "atomic_")):
                    continue
                if fn in c_known_funcs:
                    continue
                if fn not in c_declared_functions:
                    violations.append(
                        Violation(
                            "Rule 17.3",
                            "A function shall not be declared implicitly",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=fn,
                        )
                    )

            # Rule 17.12: function identifier should be used with & or call list.
            for idx, raw in enumerate(lines, start=1):
                line_nc = raw.split("//", 1)[0]
                if "=" not in line_nc or "==" in line_nc:
                    continue
                m_rhs = re.search(r"=\s*([A-Za-z_]\w*)\s*;", line_nc)
                if not m_rhs:
                    continue
                fn = m_rhs.group(1)
                # Member assignments are too ambiguous in source-scan mode (often
                # function-pointer struct members); skip to avoid false positives.
                lhs = line_nc.split("=", 1)[0].replace(" ", "")
                if "." in lhs or "->" in lhs:
                    continue
                if fn in c_declared_functions and not re.search(
                    rf"=\s*&\s*{re.escape(fn)}\s*;", line_nc
                ):
                    violations.append(
                        Violation(
                            "Rule 17.12",
                            "A function identifier should only be used with either a preceding &, or with a parenthesised parameter list.",
                            file_path,
                            idx,
                            detector="clang-fallback-scan",
                            trigger=fn,
                        )
                    )
        if is_cpp_file and profile_key == "cpp2023":
            for key, defs in cpp2023_fn_def_sigs.items():
                if len(defs) > 1:
                    for _, def_line in defs:
                        violations.append(
                            Violation(
                                "Rule 6.2.1",
                                "The one-definition rule shall not be violated.",
                                file_path,
                                def_line,
                                detector="clang-fallback-scan",
                                trigger=str(key),
                            )
                        )
                        violations.append(
                            Violation(
                                "Rule 6.2.3",
                                "The source code used to implement an entity shall appear only once.",
                                file_path,
                                def_line,
                                detector="clang-fallback-scan",
                                trigger=str(key),
                            )
                        )
            for key, decls in cpp2023_fn_decl_sigs.items():
                ret_types = set()
                for decl_text, _line in decls + cpp2023_fn_def_sigs.get(
                    key, []
                ):
                    m_ret = re.match(r"^\s*([\w:<>~]+)\s+", decl_text)
                    if m_ret:
                        ret_types.add(m_ret.group(1))
                if len(ret_types) > 1:
                    for _decl, decl_line in decls + cpp2023_fn_def_sigs.get(
                        key, []
                    ):
                        violations.append(
                            Violation(
                                "Rule 6.2.2",
                                "All declarations of a variable or function shall have the same type.",
                                file_path,
                                decl_line,
                                detector="clang-fallback-scan",
                                trigger=str(key),
                            )
                        )
            alias_map = {}
            for m in re.finditer(
                r"^\s*using\s+([A-Za-z_]\w*)\s*=\s*([^;]+);",
                source_text,
                flags=re.MULTILINE,
            ):
                alias_map[m.group(1)] = m.group(2).strip()
            for m in re.finditer(
                r"^\s*typedef\s+([^;]+)\s+([A-Za-z_]\w*)\s*;",
                source_text,
                flags=re.MULTILINE,
            ):
                alias_map[m.group(2)] = m.group(1).strip()
            fn_alias_usage: Dict[Any, List[Tuple[str, int]]] = {}
            for key, decls in cpp2023_fn_decl_sigs.items():
                for decl_text, decl_line in decls:
                    m_ret = re.match(r"^\s*([\w:<>~]+)\s+", decl_text)
                    if not m_ret:
                        continue
                    ret_t = m_ret.group(1)
                    if ret_t in alias_map:
                        fn_alias_usage.setdefault(key, []).append(
                            (ret_t, decl_line)
                        )
            for key, uses in fn_alias_usage.items():
                used_names = {u for u, _ in uses}
                if len(used_names) > 1:
                    for _name, use_line in uses:
                        violations.append(
                            Violation(
                                "Rule 6.9.1",
                                "The same type aliases shall be used in all declarations of the same entity.",
                                file_path,
                                use_line,
                                detector="clang-fallback-scan",
                                trigger=str(key),
                            )
                        )
            if re.search(r"\b(?:std::)?u?int(?:8|16|32|64)_t\b", source_text):
                first = re.search(
                    r"\b(?:std::)?u?int(?:8|16|32|64)_t\b", source_text
                )
                if first:
                    first_line = source_text[: first.start()].count("\n") + 1
                    violations.append(
                        Violation(
                            "Rule 6.9.2",
                            "The names of the standard signed integer types and standard unsigned integer types should not be used.",
                            file_path,
                            first_line,
                            detector="clang-fallback-scan",
                            trigger=first.group(0),
                        )
                    )
            class_bodies: Dict[str, Tuple[str | None, str, int]] = {}
            for m in re.finditer(
                r"class\s+([A-Za-z_]\w*)\s*(?::\s*public\s+([A-Za-z_]\w*))?\s*\{([\s\S]*?)\};",
                source_text,
                flags=re.MULTILINE,
            ):
                class_bodies[m.group(1)] = (
                    m.group(2),
                    m.group(3),
                    source_text[: m.start()].count("\n") + 1,
                )
            class_method_names: Dict[str, Set[str]] = {}
            for cname, (_base, body, _line) in class_bodies.items():
                names = set(
                    n
                    for n in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body)
                    if n
                    not in {cname, "if", "for", "while", "switch", "return"}
                )
                class_method_names[cname] = names
            for cname, (base, body, class_line) in class_bodies.items():
                if base and base in class_method_names:
                    if class_method_names[cname] & class_method_names[base]:
                        violations.append(
                            Violation(
                                "Rule 6.4.2",
                                "Derived classes shall not conceal functions that are inherited from their bases.",
                                file_path,
                                class_line,
                                detector="clang-fallback-scan",
                                trigger=cname,
                            )
                        )
                if base and base in class_method_names:
                    for dm in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body):
                        if dm in {
                            "if",
                            "for",
                            "while",
                            "switch",
                            "return",
                            cname,
                        }:
                            continue
                        if re.search(
                            rf"class\s+{re.escape(base)}\b[\s\S]*?\{{[\s\S]*?\b{re.escape(dm)}\s*\(",
                            source_text,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 6.4.2",
                                    "Derived classes shall not conceal functions that are inherited from their bases.",
                                    file_path,
                                    class_line,
                                    detector="clang-fallback-scan",
                                    trigger=dm,
                                )
                            )
                            break
            dep_base = re.search(
                r"template\s*<[^>]+>\s*class\s+([A-Za-z_]\w*)\s*:\s*public\s+([A-Za-z_]\w*)\s*\{([\s\S]*?)\};",
                source_text,
                flags=re.MULTILINE,
            )
            if dep_base:
                body = dep_base.group(3)
                dline = source_text[: dep_base.start()].count("\n") + 1
                dep_unqualified = re.search(
                    r"\b[A-Za-z_]\w*\s*\(\s*\)\s*;", body
                )
                if (
                    dep_unqualified
                    and "this->" not in body
                    and "::" not in body
                ):
                    violations.append(
                        Violation(
                            "Rule 6.4.3",
                            "A name that is present in a dependent base shall not be resolved by unqualified lookup.",
                            file_path,
                            dline,
                            detector="clang-fallback-scan",
                            trigger=dep_base.group(1),
                        )
                    )
            header_candidates = []
            for parent in [file_path.parent, file_path.parent.parent]:
                if parent and parent.exists():
                    header_candidates.extend(
                        [
                            p
                            for p in parent.rglob("*")
                            if p.suffix in {".h", ".hpp", ".hh", ".hxx"}
                        ]
                    )
            for name, ext_line in cpp2023_file_scope_external_fns.items():
                if not name.startswith("r6_5_"):
                    continue
                in_header = False
                for hp in header_candidates:
                    try:
                        txt = hp.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    if re.search(rf"\b{re.escape(name)}\s*\(", txt):
                        in_header = True
                        break
                name_occurrences = len(
                    re.findall(rf"\b{re.escape(name)}\b", source_text)
                )
                if not in_header:
                    if name_occurrences <= 2:
                        violations.append(
                            Violation(
                                "Rule 6.5.2",
                                "Internal linkage should be specified appropriately.",
                                file_path,
                                ext_line,
                                detector="clang-fallback-scan",
                                trigger=name,
                            )
                        )
                    else:
                        violations.append(
                            Violation(
                                "Rule 6.5.1",
                                "A function or object with external linkage should be introduced in a header file.",
                                file_path,
                                ext_line,
                                detector="clang-fallback-scan",
                                trigger=name,
                            )
                        )
            for var_name, var_line in cpp2023_file_scope_static_vars:
                var_occurrences = re.findall(
                    rf"\b{re.escape(var_name)}\b", source_text
                )
                if len(var_occurrences) <= 1:
                    violations.append(
                        Violation(
                            "Rule 0.2.1",
                            "Variables with limited visibility should be used at least once.",
                            file_path,
                            var_line,
                            detector="clang-fallback-scan",
                            trigger=var_name,
                        )
                    )
            for fn_name, fn_line in cpp2023_file_scope_static_fns.items():
                call_occ = re.findall(
                    rf"\b{re.escape(fn_name)}\s*\(", source_text
                )
                if len(call_occ) <= 1:
                    violations.append(
                        Violation(
                            "Rule 0.2.4",
                            "Functions with limited visibility should be used at least once.",
                            file_path,
                            fn_line,
                            detector="clang-fallback-scan",
                            trigger=fn_name,
                        )
                    )
            for type_name, type_line in cpp2023_file_scope_types.items():
                type_occurrences = re.findall(
                    rf"\b{re.escape(type_name)}\b", source_text
                )
                if len(type_occurrences) <= 1:
                    violations.append(
                        Violation(
                            "Rule 0.2.3",
                            "Types with limited visibility should be used at least once.",
                            file_path,
                            type_line,
                            detector="clang-fallback-scan",
                            trigger=type_name,
                        )
                    )
            if bool(cpp2023_unsized_delete_line) ^ bool(
                cpp2023_sized_delete_line
            ):
                violations.append(
                    Violation(
                        "Rule 21.6.4",
                        "If a project defines either a sized or unsized version of a global delete operator, then both shall be defined.",
                        file_path,
                        cpp2023_unsized_delete_line
                        or cpp2023_sized_delete_line
                        or 1,
                        detector="clang-fallback-scan",
                        trigger="sized/unsized delete mismatch",
                    )
                )
        if is_cpp_file:
            if profile_key == "cpp2023":
                for spec_line, _spec_name in cpp_explicit_specializations:
                    violations.append(
                        Violation(
                            "Rule 17.8.1",
                            "Function templates shall not be explicitly specialized.",
                            file_path,
                            spec_line,
                            detector="clang-fallback-scan",
                            trigger=_spec_name,
                        )
                    )
                # Rule 0.0.1: conservative local unreachable statement detection.
                for line_no in _find_unreachable_statement_lines(lines):
                    trigger = _strip_line_comment(lines[line_no - 1]).strip()
                    violations.append(
                        Violation(
                            "Rule 0.0.1",
                            "A function shall not contain unreachable statements",
                            file_path,
                            line_no,
                            detector="clang-fallback-scan",
                            trigger=trigger[:80],
                        )
                    )
                # Rule 9.6.5: non-void function shall return a value on all paths.
                fn_re = re.compile(
                    r"^\s*(?:inline\s+|static\s+|constexpr\s+|virtual\s+|friend\s+|extern\s+\"C\"\s+)*([A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)?)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
                )
                for i, raw in enumerate(lines, start=1):
                    m_fn = fn_re.match(raw.split("//", 1)[0])
                    if not m_fn:
                        continue
                    ret_t = m_fn.group(1)
                    fn_name = m_fn.group(2)
                    if ret_t == "void":
                        continue
                    depth = raw.count("{") - raw.count("}")
                    j = i
                    body = [raw]
                    while depth > 0 and j < len(lines):
                        j += 1
                        ln = lines[j - 1]
                        body.append(ln)
                        depth += ln.count("{") - ln.count("}")
                    last_stmt = ""
                    for ln in reversed(body):
                        s = ln.split("//", 1)[0].strip()
                        if s and s not in {"{", "}"}:
                            last_stmt = s
                            break
                    if last_stmt and not last_stmt.startswith("return"):
                        violations.append(
                            Violation(
                                "Rule 9.6.5",
                                "A function with non-void return type shall return a value on all paths",
                                file_path,
                                i,
                                detector="clang-fallback-scan",
                                trigger=fn_name,
                            )
                        )
            # Rule 14-7-1: template entities should be instantiated at least once (TU-local heuristic).
            all_templates = {}
            all_templates.update(cpp_class_templates)
            all_templates.update(cpp_function_templates)
            for name, decl_line in all_templates.items():
                if (
                    name not in cpp_template_uses
                    and name not in cpp_function_specializations
                ):
                    violations.append(
                        Violation(
                            "Rule 14-7-1",
                            f"Template '{name}' appears to have no instantiation in this translation unit.",
                            file_path,
                            decl_line,
                            trigger=name,
                        )
                    )

            # Rule 14-8-2: avoid mixed viable sets (heuristic via explicit template-id call sites).
            mixed_names = (
                set(cpp_function_templates.keys())
                & cpp_function_specializations
            )
            if mixed_names:
                for idx, raw in enumerate(lines, start=1):
                    line = raw.split("//", 1)[0].strip()
                    if line.startswith("template"):
                        continue
                    for nm in mixed_names:
                        if not re.search(
                            rf"\b{re.escape(nm)}\s*<[^>]+>\s*\(", line
                        ):
                            continue
                        # Skip template specialization declarations/definitions.
                        if not line.lstrip().startswith("return") and re.match(
                            rf"^\s*[\w:\<\>\~\*&\s]+\b{re.escape(nm)}\s*<[^>]+>\s*\([^)]*\)\s*(\{{|;|:)",
                            line,
                        ):
                            continue
                        if re.search(
                            rf"\b(return|=|,|\()\s*{re.escape(nm)}\s*<[^>]+>\s*\(",
                            line,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 14-8-2",
                                    (
                                        "The viable function set for a function call should either contain no "
                                        "function specializations, or consist only of function specializations."
                                    ),
                                    file_path,
                                    idx,
                                    trigger=nm,
                                )
                            )
                            break

            # Rule 14-7-3: specializations should be in same file as primary template (TU heuristic).
            for s_line, s_name in cpp_specializations:
                if s_name not in cpp_primary_templates:
                    violations.append(
                        Violation(
                            "Rule 14-7-3",
                            (
                                "All partial and explicit specializations for a template shall be declared in the "
                                "same file as the declaration of their primary template."
                            ),
                            file_path,
                            s_line,
                            trigger=s_name,
                        )
                    )
            if profile_key == "cpp2008":
                # cpp2008 hardening for template coverage gaps:
                # 0-1-1, 5-0-17, 5-0-18, 7-1-2, 8-4-3, 8-5-1
                pointer_vars = set()
                local_decl_line: Dict[str, int] = {}
                assigned_after_decl = set()
                for idx, raw in enumerate(lines, start=1):
                    line = raw.split("//", 1)[0]
                    stripped = line.strip()
                    if not stripped:
                        continue

                    for m_ptr in re.finditer(
                        r"\b[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*\s*\*\s*([A-Za-z_]\w*)",
                        stripped,
                    ):
                        pointer_vars.add(m_ptr.group(1))
                    for m_decl in re.finditer(
                        r"\b(?:int|long|short|char|float|double|bool|unsigned|signed)\s+([A-Za-z_]\w*)\s*;",
                        stripped,
                    ):
                        local_decl_line.setdefault(m_decl.group(1), idx)
                    for name in list(local_decl_line.keys()):
                        if re.search(rf"\b{re.escape(name)}\s*=", stripped):
                            assigned_after_decl.add(name)
                    # Rule 5-0-17
                    m_sub = re.search(
                        r"\b([A-Za-z_]\w*)\s*-\s*([A-Za-z_]\w*)\b", stripped
                    )
                    if (
                        m_sub
                        and m_sub.group(1) in pointer_vars
                        and m_sub.group(2) in pointer_vars
                    ):
                        violations.append(
                            Violation(
                                "Rule 5-0-17",
                                "Subtraction between pointers shall only be applied to pointers that address elements of the same array.",
                                file_path,
                                idx,
                                trigger=f"{m_sub.group(1)} - {m_sub.group(2)}",
                            )
                        )
                    # Rule 5-0-18
                    m_rel = re.search(
                        r"\b([A-Za-z_]\w*)\s*(<|<=|>|>=)\s*([A-Za-z_]\w*)\b",
                        stripped,
                    )
                    if (
                        m_rel
                        and m_rel.group(1) in pointer_vars
                        and m_rel.group(3) in pointer_vars
                    ):
                        violations.append(
                            Violation(
                                "Rule 5-0-18",
                                "Relational operators shall not be applied to objects of pointer type except where they point into the same object.",
                                file_path,
                                idx,
                                trigger=f"{m_rel.group(1)} {m_rel.group(2)} {m_rel.group(3)}",
                            )
                        )
                    # Rule 8-5-1
                    m_ret = re.search(
                        r"\breturn\s+([A-Za-z_]\w+)\s*;", stripped
                    )
                    if m_ret:
                        ret_name = m_ret.group(1)
                        if (
                            ret_name in local_decl_line
                            and ret_name not in assigned_after_decl
                        ):
                            violations.append(
                                Violation(
                                    "Rule 8-5-1",
                                    f"Variable '{ret_name}' is used before it has been set.",
                                    file_path,
                                    idx,
                                    trigger=ret_name,
                                )
                            )
                # Rule 0-1-1: conservative local unreachable statement detection.
                for line_no in _find_unreachable_statement_lines(lines):
                    trigger = _strip_line_comment(lines[line_no - 1]).strip()
                    violations.append(
                        Violation(
                            "Rule 0-1-1",
                            "A project shall not contain unreachable code.",
                            file_path,
                            line_no,
                            trigger=trigger[:80],
                        )
                    )

                # Rule 8-4-3 is intentionally not approximated here for C++.
                # The text fallback is too noisy for branching functions; rely on
                # clang diagnostics for trustworthy findings.

                # Rule 7-1-2: pointer params read-only should be const-qualified.
                fn_sig_re = re.compile(
                    r"^\s*[^;{}]*\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{"
                )
                for i, raw in enumerate(lines, start=1):
                    m_sig = fn_sig_re.match(raw.split("//", 1)[0])
                    if not m_sig:
                        continue
                    params = m_sig.group(2) or ""
                    ptr_params = []
                    for pm in re.finditer(
                        r"([^,()]*\*+\s*([A-Za-z_]\w+))", params
                    ):
                        decl_txt = pm.group(1)
                        p_name = pm.group(2)
                        if "const" in decl_txt:
                            continue
                        ptr_params.append(p_name)
                    if not ptr_params:
                        continue
                    depth = raw.count("{") - raw.count("}")
                    j = i
                    body = [raw]
                    while depth > 0 and j < len(lines):
                        j += 1
                        ln = lines[j - 1]
                        body.append(ln)
                        depth += ln.count("{") - ln.count("}")
                    body_txt = "\n".join(body)
                    for p_name in ptr_params:
                        has_write = bool(
                            re.search(
                                rf"\*\s*{re.escape(p_name)}\s*=", body_txt
                            )
                            or re.search(
                                rf"{re.escape(p_name)}\s*\[[^\]]*\]\s*=",
                                body_txt,
                            )
                            or re.search(
                                rf"{re.escape(p_name)}\s*->[^;]*=", body_txt
                            )
                        )
                        if has_write:
                            continue
                        if re.search(rf"\b{re.escape(p_name)}\b", body_txt):
                            violations.append(
                                Violation(
                                    "Rule 7-1-2",
                                    f"A pointer should point to a const-qualified type whenever possible: '{p_name}'.",
                                    file_path,
                                    i,
                                    trigger=p_name,
                                )
                            )
    except Exception as exc:
        logging.getLogger(__name__).debug(
            "Fallback scan failed for %s: %s",
            file_path,
            exc,
            exc_info=True,
        )
    if is_cpp_file and profile_key != "cpp2023":
        violations = [
            v for v in violations if v.rule not in CPP2023_ONLY_FALLBACK_RULES
        ]
    deduped: List[Violation] = []
    for v in violations:
        dedupe_key = (v.rule, str(v.file), v.line, v.message, v.detector)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        deduped.append(v)
    return deduped
