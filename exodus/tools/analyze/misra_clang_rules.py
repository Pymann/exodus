import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple, cast
from pathlib import Path
import clang.cindex
from clang.cindex import CursorKind, TypeKind

from exodus.tools.analyze.misra_rules import Violation
from exodus.tools.analyze.misra_fallback_scans import run_fallback_source_scans
from exodus.tools.analyze.misra_cpp_class_rules import (
    apply_cpp_ch9_rules,
    apply_cpp_ch10_rules,
    apply_cpp_ch11_12_rules,
    apply_cpp_ch14_rules,
)
from exodus.tools.analyze.misra_cpp_exception_rules import apply_cpp_ch15_rules
from exodus.tools.analyze.misra_cpp_postprocess_rules import (
    apply_cpp_postprocess_rules,
)
from exodus.tools.analyze.misra_cpp_misc_rules import apply_cpp_ch7_8_rules
from exodus.tools.analyze.misra_common_postprocess_rules import (
    apply_common_postprocess_rules,
)
from exodus.tools.analyze.misra_resource_postprocess_rules import (
    apply_resource_postprocess_rules,
)
from exodus.tools.analyze.misra_type_utils import (
    is_floating_kind as _is_floating_kind,
    is_fundamental_kind as _is_fundamental_kind,
    is_integral_kind as _is_integral_kind,
    is_pointer_or_reference_kind as _is_pointer_or_reference_kind,
    is_signed_integral_kind as _is_signed_integral_kind,
    is_unsigned_kind as _is_unsigned_kind,
)

logger = logging.getLogger(__name__)
_HEADER_DECL_CACHE: Dict[str, Set[str]] = {}


def analyze_clang_ast(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    global_db: Any = None,
    project_config: Any = None,
) -> List[Violation]:
    violations: List[Violation] = []
    unused_param_diag_keys: Set[Tuple[str, int, str]] = set()
    # Safety guard: very deep libclang traversals can trigger hard crashes
    # on some translation units. Limit comes from ProjectConfig.
    node_limit = 50000
    if project_config is not None:
        try:
            node_limit = int(
                getattr(project_config, "clang_node_limit", 50000)
            )
        except (TypeError, ValueError):
            node_limit = 50000
    visited_nodes = 0
    trace_file_path = os.environ.get("EXODUS_CLANG_TRACE_FILE", "").strip()
    trace_enabled = bool(trace_file_path)
    state_file_path = os.environ.get("EXODUS_CLANG_STATE_FILE", "").strip()
    cpp_unused_var_diag_keys: Set[Tuple[int, str]] = set()
    is_cpp_file = file_path.suffix in (".cpp", ".cc", ".cxx")
    try:
        source_lines = file_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines()
    except Exception:
        source_lines = []

    def _extract_declared_function_names(text: str) -> Set[str]:
        names: Set[str] = set()
        # Prototype-like declarations ending in ';' (not function definitions).
        # Take the *last* identifier-before-'(' in each statement, which handles
        # macro-wrapped return types like: CJSON_PUBLIC(char*) cJSON_Print(...);
        for stmt_m in re.finditer(
            r"[^;{}]*\([^;{}]*\)\s*;", text, flags=re.MULTILINE
        ):
            stmt = stmt_m.group(0)
            call_like = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", stmt))
            if not call_like:
                continue
            name = call_like[-1].group(1)
            if name in {"if", "for", "while", "switch", "return", "sizeof"}:
                continue
            names.add(name)
        return names

    def _collect_visible_header_func_names() -> Set[str]:
        cache_key = str(file_path.resolve())
        cached = _HEADER_DECL_CACHE.get(cache_key)
        if cached is not None:
            return cached
        include_names: List[str] = []
        for raw in source_lines:
            m = re.match(r'^\s*#\s*include\s*"([^"]+)"', raw)
            if m:
                include_names.append(m.group(1))
        header_candidates: Set[Path] = set()
        for inc in include_names:
            p1 = (file_path.parent / inc).resolve()
            p2 = (file_path.parent.parent / "include" / inc).resolve()
            if p1.exists() and p1.is_file():
                header_candidates.add(p1)
            if p2.exists() and p2.is_file():
                header_candidates.add(p2)
        names: Set[str] = set()
        for hp in header_candidates:
            try:
                txt = hp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            names.update(_extract_declared_function_names(txt))
        _HEADER_DECL_CACHE[cache_key] = names
        return names

    visible_header_func_names = _collect_visible_header_func_names()

    rule_2_10_1_cfg = (
        getattr(
            getattr(project_config, "misra_heuristics", None),
            "rule_2_10_1",
            None,
        )
        if project_config
        else None
    )
    rule_2_10_1_enabled = (
        bool(getattr(rule_2_10_1_cfg, "enabled", True))
        if is_cpp_file
        else False
    )
    rule_2_10_1_min_len = int(
        getattr(rule_2_10_1_cfg, "min_identifier_length", 3)
    )
    rule_2_10_1_case_insensitive = bool(
        getattr(rule_2_10_1_cfg, "case_insensitive", True)
    )
    rule_2_10_1_groups = list(
        getattr(
            rule_2_10_1_cfg,
            "confusable_groups",
            ["o0", "il1", "s5", "z2", "b8", "g6", "q9"],
        )
    )

    confusable_map: Dict[str, str] = {}
    for group in rule_2_10_1_groups:
        if not group:
            continue
        normalized_group = (
            group.lower() if rule_2_10_1_case_insensitive else group
        )
        token = normalized_group[0]
        for ch in normalized_group:
            # Keep first assignment stable if a char appears in multiple groups.
            confusable_map.setdefault(ch, token)

    def normalize_typo_identifier(name: str) -> str:
        candidate = name.lower() if rule_2_10_1_case_insensitive else name
        return "".join(confusable_map.get(ch, ch) for ch in candidate)

    def is_system_cursor(cur: Optional[clang.cindex.Cursor]) -> bool:
        if not cur:
            return False
        try:
            loc = cur.location
            return bool(loc and getattr(loc, "is_in_system_header", False))
        except Exception:
            return False

    def add_violation(
        rule: str,
        message: str,
        v_file: Path | str,
        line: int,
        detector: str = "clang-heuristic",
        trigger: str = "",
    ) -> None:
        violation_path = v_file if isinstance(v_file, Path) else Path(v_file)
        violations.append(
            Violation(
                rule,
                message,
                violation_path,
                line,
                detector=detector,
                trigger=trigger,
            )
        )

    def _write_state(
        stage: str,
        node: Optional[clang.cindex.Cursor] = None,
    ) -> None:
        if not state_file_path:
            return
        payload: Dict[str, Any] = {
            "stage": stage,
            "file": str(file_path),
            "visited_nodes": visited_nodes,
        }
        if node is not None:
            try:
                payload["node_kind"] = str(node.kind)
                payload["node_spelling"] = node.spelling or ""
                payload["line"] = int(getattr(node.location, "line", 0) or 0)
                payload["column"] = int(
                    getattr(node.location, "column", 0) or 0
                )
            except Exception:
                pass
        try:
            Path(state_file_path).parent.mkdir(parents=True, exist_ok=True)
            Path(state_file_path).write_text(
                json.dumps(payload, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    def has_side_effect(
        n: Optional[clang.cindex.Cursor], include_calls: bool = True
    ) -> bool:
        if not n:
            return False
        if include_calls and n.kind == CursorKind.CALL_EXPR:
            return True
        if n.kind == CursorKind.UNARY_OPERATOR:
            ops = [t.spelling for t in n.get_tokens()]
            if "++" in ops or "--" in ops:
                return True
        if include_calls and n.kind == CursorKind.BINARY_OPERATOR:
            assign_ops = {
                "=",
                "+=",
                "-=",
                "*=",
                "/=",
                "%=",
                "&=",
                "|=",
                "^=",
                "<<=",
                ">>=",
            }
            children = list(n.get_children())
            op_spelling = ""
            if len(children) >= 2:
                lhs = children[0]
                rhs = children[1]
                for tok in n.get_tokens():
                    if (
                        tok.extent.start.offset >= lhs.extent.end.offset
                        and tok.extent.end.offset <= rhs.extent.start.offset
                    ):
                        op_spelling = tok.spelling
                        if op_spelling.strip():
                            break
            if op_spelling in assign_ops:
                return True
        for c in n.get_children():
            if has_side_effect(c, include_calls=include_calls):
                return True
        return False

    def _get_record_decl_from_indirect_type(
        t: Optional[clang.cindex.Type],
    ) -> Optional[clang.cindex.Cursor]:
        if not t:
            return None
        ct = t.get_canonical()
        if not _is_pointer_or_reference_kind(ct.kind):
            return None
        try:
            pointee = ct.get_pointee().get_canonical()
        except Exception:
            return None
        if pointee.kind not in (
            TypeKind.RECORD,
            TypeKind.ELABORATED,
            TypeKind.UNEXPOSED,
        ):
            return None
        decl = pointee.get_declaration()
        if not decl or not decl.spelling:
            return None
        return decl

    def _iter_base_specs(
        record_decl: Optional[clang.cindex.Cursor],
    ) -> List[Tuple[clang.cindex.Cursor, bool]]:
        bases: List[Tuple[clang.cindex.Cursor, bool]] = []
        if not record_decl:
            return bases
        for child in record_decl.get_children():
            if child.kind != CursorKind.CXX_BASE_SPECIFIER:
                continue
            base_decl = getattr(child, "referenced", None)
            if not base_decl:
                try:
                    base_decl = child.type.get_canonical().get_declaration()
                except Exception:
                    base_decl = None
            if not base_decl:
                continue
            is_virtual = False
            try:
                is_virtual = bool(child.is_virtual_base())
            except Exception:
                toks = [t.spelling for t in tuple(child.get_tokens())]
                is_virtual = "virtual" in toks
            bases.append((base_decl, is_virtual))
        return bases

    def _is_derived_from(
        derived_decl: Optional[clang.cindex.Cursor],
        base_decl: Optional[clang.cindex.Cursor],
    ) -> bool:
        if not derived_decl or not base_decl:
            return False
        target_usr = (
            base_decl.get_usr() or f"{base_decl.spelling}:{base_decl.hash}"
        )
        seen: Set[str] = set()

        def walk(cur: clang.cindex.Cursor) -> bool:
            cur_usr = cur.get_usr() or f"{cur.spelling}:{cur.hash}"
            if cur_usr in seen:
                return False
            seen.add(cur_usr)
            for b_decl, _ in _iter_base_specs(cur):
                b_usr = b_decl.get_usr() or f"{b_decl.spelling}:{b_decl.hash}"
                if b_usr == target_usr:
                    return True
                if walk(b_decl):
                    return True
            return False

        return walk(derived_decl)

    def _is_virtual_base_of(
        base_decl: Optional[clang.cindex.Cursor],
        derived_decl: Optional[clang.cindex.Cursor],
    ) -> bool:
        if not base_decl or not derived_decl:
            return False
        target_usr = (
            base_decl.get_usr() or f"{base_decl.spelling}:{base_decl.hash}"
        )
        seen: Set[str] = set()

        def walk(cur: clang.cindex.Cursor) -> bool:
            cur_usr = cur.get_usr() or f"{cur.spelling}:{cur.hash}"
            if cur_usr in seen:
                return False
            seen.add(cur_usr)
            for b_decl, is_virtual in _iter_base_specs(cur):
                b_usr = b_decl.get_usr() or f"{b_decl.spelling}:{b_decl.hash}"
                if b_usr == target_usr:
                    return is_virtual
                if walk(b_decl):
                    return True
            return False

        return walk(derived_decl)

    def _class_is_polymorphic(
        record_decl: Optional[clang.cindex.Cursor],
    ) -> bool:
        if not record_decl:
            return False
        for child in record_decl.get_children():
            if child.kind in (CursorKind.CXX_METHOD, CursorKind.DESTRUCTOR):
                try:
                    if child.is_virtual_method():
                        return True
                except Exception:
                    toks = [t.spelling for t in tuple(child.get_tokens())]
                    if "virtual" in toks:
                        return True
        return False

    def _has_virtual_base_in_hierarchy(
        record_decl: Optional[clang.cindex.Cursor],
    ) -> bool:
        if not record_decl:
            return False
        seen: Set[str] = set()

        def walk(cur: clang.cindex.Cursor) -> bool:
            cur_usr = cur.get_usr() or f"{cur.spelling}:{cur.hash}"
            if cur_usr in seen:
                return False
            seen.add(cur_usr)
            for b_decl, is_virtual in _iter_base_specs(cur):
                if is_virtual:
                    return True
                if walk(b_decl):
                    return True
            return False

        return walk(record_decl)

    def _is_postfix_expression(
        expr: Optional[clang.cindex.Cursor],
    ) -> bool:
        n = unwrap_expr(expr)
        if not n:
            return False
        if n.kind in (
            CursorKind.DECL_REF_EXPR,
            CursorKind.MEMBER_REF_EXPR,
            CursorKind.CALL_EXPR,
            CursorKind.ARRAY_SUBSCRIPT_EXPR,
            CursorKind.INTEGER_LITERAL,
            CursorKind.FLOATING_LITERAL,
            CursorKind.CHARACTER_LITERAL,
            CursorKind.STRING_LITERAL,
            CursorKind.CXX_BOOL_LITERAL_EXPR,
            CursorKind.CXX_NULL_PTR_LITERAL_EXPR,
            CursorKind.CXX_THIS_EXPR,
        ):
            return True
        if n.kind == CursorKind.UNARY_OPERATOR:
            # Heuristic: only post-inc/dec are treated as postfix here.
            toks = [t.spelling for t in tuple(n.get_tokens())]
            if toks and (toks[-1] == "++" or toks[-1] == "--"):
                return True
        return False

    def is_essentially_boolean(n: Optional[clang.cindex.Cursor]) -> bool:
        if not n:
            return False
        t = n.type.get_canonical()
        try:
            t_spelling = (n.type.spelling or "").lower()
        except Exception:
            t_spelling = ""
        if t.kind == TypeKind.BOOL:
            return True
        if t.kind == TypeKind.POINTER:
            # Pragmatic C-mode relaxation: direct pointer checks in controlling
            # expressions (if(ptr), while(node)) are treated as essentially boolean.
            return True
        # Heuristic: project-specific boolean typedefs (e.g. cJSON_bool) should
        # be treated as essentially Boolean in controlling expressions.
        if "bool" in t_spelling:
            return True
        if n.kind == CursorKind.BINARY_OPERATOR:
            ops = [tok.spelling for tok in tuple(n.get_tokens())]
            for bool_op in ("&&", "||", "==", "!=", "<", "<=", ">", ">="):
                if bool_op in ops:
                    return True
        if n.kind == CursorKind.UNARY_OPERATOR:
            ops = [tok.spelling for tok in tuple(n.get_tokens())]
            if "!" in ops:
                return True
        if n.kind == CursorKind.CXX_BOOL_LITERAL_EXPR:
            return True

        # Unexposed expr drilling
        if n.kind in (
            CursorKind.UNEXPOSED_EXPR,
            CursorKind.PAREN_EXPR,
            CursorKind.CSTYLE_CAST_EXPR,
            CursorKind.CXX_STATIC_CAST_EXPR,
        ):
            cc = list(n.get_children())
            if cc:
                return any(is_essentially_boolean(child) for child in cc)
        return False

    def has_explicit_bool_type(
        n: Optional[clang.cindex.Cursor],
    ) -> bool:
        if not n:
            return False
        candidate_types = []
        try:
            candidate_types.append(n.type)
        except Exception:
            pass
        try:
            orig = _get_original_type(n)
            if orig is not None:
                candidate_types.append(orig)
        except Exception:
            pass
        for candidate in candidate_types:
            try:
                canonical = candidate.get_canonical()
            except Exception:
                canonical = candidate
            try:
                spelling = (candidate.spelling or "").lower()
            except Exception:
                spelling = ""
            if canonical.kind == TypeKind.BOOL or "bool" in spelling:
                return True
        return False

    def is_invariant_literal(n: Optional[clang.cindex.Cursor]) -> bool:
        if not n:
            return False
        if n.kind in (
            CursorKind.INTEGER_LITERAL,
            CursorKind.FLOATING_LITERAL,
            CursorKind.CXX_BOOL_LITERAL_EXPR,
            CursorKind.CHARACTER_LITERAL,
            CursorKind.STRING_LITERAL,
        ):
            return True
        if n.kind in (
            CursorKind.UNEXPOSED_EXPR,
            CursorKind.PAREN_EXPR,
            CursorKind.CSTYLE_CAST_EXPR,
        ):
            cc = list(n.get_children())
            if cc:
                return is_invariant_literal(cc[-1])
        return False

    # 1. Harvest Clang Diagnostics for MISRA Rules (Unused code, shadowing, extensions)
    for d in tu.diagnostics:
        msg = d.spelling.lower()
        if (
            d.location.file
            and Path(d.location.file.name).resolve() == file_path.resolve()
        ):
            line = d.location.line
            if "unused parameter" in msg:
                param_match = re.search(
                    r"unused parameter '([^']+)'", d.spelling, re.IGNORECASE
                )
                if param_match:
                    unused_param_diag_keys.add(
                        (str(file_path.resolve()), line, param_match.group(1))
                    )
                add_violation(
                    "Rule 2.7",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
                if is_cpp_file:
                    add_violation(
                        "Rule 0-1-11",
                        d.spelling,
                        file_path,
                        line,
                        detector="cpp-ch0-diagnostic",
                    )
            elif (
                "unused variable" in msg
                or "unused function" in msg
                or "set but not used" in msg
            ):
                add_violation(
                    "Rule 2.2",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
                if is_cpp_file:
                    add_violation(
                        "Rule 0-1-9",
                        d.spelling,
                        file_path,
                        line,
                        detector="cpp-ch0-diagnostic",
                    )
                    if "unused variable" in msg or "set but not used" in msg:
                        var_match = re.search(
                            r"(?:unused variable|variable) '([^']+)'",
                            d.spelling,
                            re.IGNORECASE,
                        )
                        if var_match:
                            cpp_unused_var_diag_keys.add(
                                (line, var_match.group(1))
                            )
            elif "unused typedef" in msg:
                add_violation(
                    "Rule 2.3",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "macro is not used" in msg:
                add_violation(
                    "Rule 2.5",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "unused label" in msg:
                add_violation(
                    "Rule 2.6",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "discards qualifiers" in msg
                and "const char" in msg
                and "char *" in msg
            ):
                add_violation(
                    "Rule 7.4",
                    "A string literal shall not be assigned to a non-const pointer.",
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "extension used" in msg
                or "extension" in msg
                or "pedantic" in msg
                or "invalid in c99" in msg
                or "c99 feature" in msg
                or "gnu" in msg
            ):
                add_violation(
                    "Rule 1.2",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "trigraph" in msg:
                add_violation(
                    "Rule 4.2",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "unreachable" in msg or "never be executed" in msg:
                add_violation(
                    "Rule 2.1",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "shadow" in msg or "hide" in msg:
                add_violation(
                    "Rule 5.3",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "type specifier missing" in msg or "defaults to 'int'" in msg:
                add_violation(
                    "Rule 8.1",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "without a prototype" in msg or "no prototype" in msg:
                add_violation(
                    "Rule 8.2",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "uninitialized" in msg.lower()
                or "is used uninitialized" in msg.lower()
            ):
                add_violation(
                    "Rule 9.1",
                    msg,
                    d.location.file.name,
                    d.location.line,
                    detector="clang-diagnostic",
                )
            elif (
                "-Winitializer-overrides" in msg.lower()
                or "initializer overrides" in msg.lower()
                or "initialized more than once" in msg.lower()
            ):
                add_violation(
                    "Rule 9.4",
                    "An element of an object shall not be initialized more than once",
                    d.location.file.name,
                    d.location.line,
                    detector="clang-diagnostic",
                )
            elif (
                "missing braces" in msg.lower()
                or "suggest braces" in msg.lower()
            ):
                add_violation(
                    "Rule 9.2",
                    msg,
                    d.location.file.name,
                    d.location.line,
                    detector="clang-diagnostic",
                )
            elif "cast to" in msg and "from integer" in msg:
                add_violation(
                    "Rule 11.4",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "cast from pointer" in msg and "to integer" in msg:
                add_violation(
                    "Rule 11.4",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "cast to" in msg
                and "from" in msg
                and ("float" in msg or "double" in msg)
                and "*" in msg
            ):
                add_violation(
                    "Rule 11.7",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "incompatible pointer type" in msg:
                add_violation(
                    "Rule 11.X",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "cast discards" in msg or (
                "cast from" in msg and "drops" in msg
            ):
                add_violation(
                    "Rule 11.8",
                    d.spelling,
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "implicit declaration of function" in msg
                or "implicitly declaring library function" in msg
                or "call to undeclared function" in msg
            ):
                add_violation(
                    "Rule 17.3",
                    "A function shall not be declared implicitly",
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif (
                "control reaches end of non-void function" in msg
                or "non-void function does not return a value" in msg
            ):
                add_violation(
                    "Rule 17.4",
                    "All exit paths from a function with non-void return type shall have an explicit return statement with an expression",
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "array index" in msg and "past the end of the array" in msg:
                add_violation(
                    "Rule 18.1",
                    "A pointer resulting from arithmetic on a pointer operand shall address an element of the same array",
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif "variable length array" in msg:
                add_violation(
                    "Rule 18.8",
                    "Variable-length array types shall not be used",
                    file_path,
                    line,
                    detector="clang-diagnostic",
                )
            elif is_cpp_file and (
                "division by zero" in msg
                or "undefined behavior" in msg
                or "out of bounds" in msg
                or "null pointer" in msg
            ):
                add_violation(
                    "Rule 0-1-6",
                    d.spelling,
                    file_path,
                    line,
                    detector="cpp-ch0-diagnostic",
                )
            elif is_cpp_file and (
                "unsequenced" in msg
                or "multiple unsequenced" in msg
                or "order of evaluation" in msg
            ):
                add_violation(
                    "Rule 0-1-7",
                    "The value of an expression shall be the same under any order of evaluation that the standard permits.",
                    file_path,
                    line,
                    detector="cpp-ch0-diagnostic",
                )
            elif is_cpp_file and (
                "will always evaluate to" in msg
                or "always false" in msg
                or "always true" in msg
            ):
                add_violation(
                    "Rule 0-1-2",
                    d.spelling,
                    file_path,
                    line,
                    detector="cpp-ch0-diagnostic",
                )

    declared_tags: Dict[str, Any] = {}
    used_tags: Set[str] = set()
    # Track only declarations that are visible before the definition point
    # (Rule 8.4 requires visibility at the point of definition).
    visible_external_func_decls: Set[Tuple[str, str]] = set()

    external_identifiers: Dict[str, Any] = {}
    internal_scopes: Dict[str, Any] = {}

    # Store function AST nodes to post-process Chapter 15 rules
    chapter_15_funcs: List[clang.cindex.Cursor] = []
    function_nodes: Dict[int, clang.cindex.Cursor] = {}

    macro_truncs: Dict[str, str] = {}
    macros: Dict[str, Any] = {}
    tags: Dict[str, Any] = {}
    ordinary: Dict[str, Any] = {}
    typedefs: Dict[str, Any] = {}

    # Chapter 22 resource tracking (heuristic).
    alloc_resources: Dict[str, Dict[str, Any]] = {}
    freed_heap: Set[str] = set()
    file_modes: Dict[str, str] = {}
    closed_files: Set[str] = set()
    file_opens: Dict[str, List[Dict[str, Any]]] = {}

    file_vars: Dict[int, clang.cindex.Cursor] = {}
    file_vars_users: Dict[int, Set[int]] = {}

    # Rule 8.13 support
    func_ptr_params: Dict[int, List[Tuple[int, str, int]]] = {}
    func_ptr_params_mutated: Dict[int, Set[int]] = {}
    func_ptr_param_names: Dict[int, Set[str]] = {}
    func_ptr_params_mutated_names: Dict[int, Set[str]] = {}

    # MISRA C++:2008 Chapter 2 support
    cpp_static_duration_names: Dict[
        str, List[Tuple[clang.cindex.Cursor, Any]]
    ] = {}
    cpp_scope_type_names: Dict[Any, Dict[str, clang.cindex.Cursor]] = {}
    cpp_scope_objfunc_names: Dict[Any, Dict[str, clang.cindex.Cursor]] = {}
    cpp_rule_2_10_6_reported: Set[Tuple[Any, str]] = set()
    cpp_typo_scope_names: Dict[Any, Dict[str, Dict[Any, Tuple[str, int]]]] = {}
    cpp_scope_decl_names: Dict[Any, Dict[str, clang.cindex.Cursor]] = {}
    cpp_scope_parent: Dict[Any, Any] = {}
    cpp_rule_2_10_2_reported: Set[Tuple[Any, str, int]] = set()
    cpp_entity_decl_lines: Dict[Tuple[Any, Any], List[Tuple[int, str]]] = {}

    # MISRA C++:2008 Chapter 0 support (heuristic)
    cpp_defined_functions: Dict[int, clang.cindex.Cursor] = {}
    cpp_called_functions: Set[str] = set()
    cpp_var_decls: Dict[int, clang.cindex.Cursor] = {}
    cpp_var_ref_counts: Dict[int, int] = {}
    cpp_void_func_has_side_effect: Dict[int, bool] = {}
    cpp_known_error_calls_ignored: List[Tuple[int, str]] = []
    cpp_function_linkage: Dict[int, Any] = {}
    cpp_enum_allowed_values: Dict[Any, Set[int]] = {}
    cpp_scope_decl_lines: Dict[Any, Dict[str, List[int]]] = {}
    cpp_scope_using_lines: Dict[Any, Dict[str, List[int]]] = {}
    cpp_func_has_asm: Dict[int, bool] = {}
    cpp_func_asm_lines: Dict[int, List[int]] = {}
    cpp_stdlib_symbol_names = {
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
        "errno",
    }
    cpp_stdlib_macro_names = {
        "NULL",
        "EOF",
        "errno",
        "va_start",
        "va_end",
        "va_arg",
        "va_copy",
    }

    def unwrap_expr(
        n: Optional[clang.cindex.Cursor],
    ) -> Optional[clang.cindex.Cursor]:
        cur = n
        while cur and cur.kind in (
            CursorKind.UNEXPOSED_EXPR,
            CursorKind.PAREN_EXPR,
            CursorKind.CSTYLE_CAST_EXPR,
            CursorKind.CXX_STATIC_CAST_EXPR,
            CursorKind.CXX_REINTERPRET_CAST_EXPR,
        ):
            children = [
                c for c in cur.get_children() if c.kind != CursorKind.TYPE_REF
            ]
            if not children:
                break
            cur = children[-1]
        return cur

    def _cursor_text(
        cur: Optional[clang.cindex.Cursor], max_len: int = 120
    ) -> str:
        if not cur:
            return ""
        try:
            text = " ".join(tok.spelling for tok in tuple(cur.get_tokens()))
        except Exception:
            text = ""
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_len:
            return text[: max_len - 3] + "..."
        return text

    def get_decl_ref_hash(n: Optional[clang.cindex.Cursor]) -> Optional[int]:
        cur = unwrap_expr(n)
        if not cur:
            return None
        if cur.kind == CursorKind.DECL_REF_EXPR and cur.referenced:
            return cur.referenced.hash
        if cur.kind == CursorKind.UNARY_OPERATOR:
            children = list(cur.get_children())
            if children:
                child = unwrap_expr(children[-1])
                if (
                    child
                    and child.kind == CursorKind.DECL_REF_EXPR
                    and child.referenced
                ):
                    return child.referenced.hash
        return None

    def get_decl_ref_cursor(
        n: Optional[clang.cindex.Cursor],
    ) -> Optional[clang.cindex.Cursor]:
        cur = unwrap_expr(n)
        if not cur:
            return None
        if cur.kind == CursorKind.DECL_REF_EXPR and cur.referenced:
            return cur.referenced
        if cur.kind == CursorKind.UNARY_OPERATOR:
            children = list(cur.get_children())
            if children:
                child = unwrap_expr(children[-1])
                if (
                    child
                    and child.kind == CursorKind.DECL_REF_EXPR
                    and child.referenced
                ):
                    return child.referenced
        return None

    def get_call_name(call_node: Optional[clang.cindex.Cursor]) -> str:
        if not call_node:
            return ""
        if call_node.spelling:
            return call_node.spelling
        if call_node.referenced:
            return call_node.referenced.spelling
        for c in call_node.walk_preorder():
            if c.kind == CursorKind.DECL_REF_EXPR and c.referenced:
                return c.referenced.spelling
        return ""

    def _get_referenced_function_name(
        expr: Optional[clang.cindex.Cursor],
    ) -> str:
        cur = unwrap_expr(expr)
        if not cur:
            return ""
        if cur.kind == CursorKind.UNARY_OPERATOR:
            children = list(cur.get_children())
            if children:
                cur = unwrap_expr(children[-1])
        if (
            cur
            and cur.kind == CursorKind.DECL_REF_EXPR
            and cur.referenced
            and cur.referenced.kind
            in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD)
        ):
            return cur.referenced.spelling or ""
        return ""

    def _mark_ptr_param_mutated(
        func_hash: int, ref_cursor: clang.cindex.Cursor
    ) -> None:
        if func_hash not in func_ptr_params_mutated:
            return
        func_ptr_params_mutated[func_hash].add(ref_cursor.hash)
        if func_hash in func_ptr_params_mutated_names and ref_cursor.spelling:
            func_ptr_params_mutated_names[func_hash].add(ref_cursor.spelling)

    def _mark_ptr_param_mutated_by_name(
        func_hash: int, param_name: str
    ) -> None:
        if not param_name:
            return
        if func_hash in func_ptr_params_mutated_names:
            func_ptr_params_mutated_names[func_hash].add(param_name)

    def get_string_literal_text(
        n: Optional[clang.cindex.Cursor],
    ) -> str:
        cur = unwrap_expr(n)
        if not cur:
            return ""
        toks = [t.spelling for t in cur.get_tokens()]
        if not toks:
            return ""
        # Typical token for string literal is a single quoted token: "r"
        literal = "".join(toks).strip()
        if len(literal) >= 2 and literal[0] == '"' and literal[-1] == '"':
            return literal[1:-1]
        return ""

    def _extract_using_target_name(
        using_cursor: clang.cindex.Cursor,
    ) -> str:
        try:
            toks = [t.spelling for t in tuple(using_cursor.get_tokens())]
        except Exception:
            toks = []
        ident_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
        for tok in reversed(toks):
            if tok in {"using", "::", ";", "typename"}:
                continue
            if ident_re.match(tok):
                return tok
        return ""

    def _parse_int_literal_text(token_text: str) -> Optional[int]:
        txt = token_text.lower().replace("u", "").replace("l", "")
        if not txt:
            return None
        try:
            if txt.startswith("0x"):
                return int(txt, 16)
            if txt.startswith("0") and len(txt) > 1:
                return int(txt, 8)
            return int(txt, 10)
        except Exception:
            return None

    def _get_integer_literal_value(
        expr: Optional[clang.cindex.Cursor],
    ) -> Optional[int]:
        cur = unwrap_expr(expr)
        if not cur or cur.kind != CursorKind.INTEGER_LITERAL:
            return None
        toks = [t.spelling for t in tuple(cur.get_tokens())]
        if not toks:
            return None
        return _parse_int_literal_text(toks[0])

    def _is_asm_cursor(node: clang.cindex.Cursor) -> bool:
        return node.kind in (CursorKind.ASM_STMT, CursorKind.MS_ASM_STMT)

    def _enum_allowed_values_from_type(
        t: Optional[clang.cindex.Type],
    ) -> Set[int]:
        if not t:
            return set()
        ct = t.get_canonical()
        if ct.kind != TypeKind.ENUM:
            return set()
        decl = ct.get_declaration()
        if not decl:
            return set()
        vals: Set[int] = set()
        for c in decl.get_children():
            if c.kind == CursorKind.ENUM_CONSTANT_DECL:
                vals.add(c.enum_value)
        return vals

    def _is_documented_asm_line(line_no: int) -> bool:
        if line_no <= 0 or line_no > len(source_lines):
            return False
        line = source_lines[line_no - 1]
        if "//" in line or "/*" in line:
            return True
        prev = line_no - 2
        while prev >= 0:
            s = source_lines[prev].strip()
            if not s:
                prev -= 1
                continue
            return s.startswith("//") or s.startswith("/*") or s.endswith("*/")
        return False

    def _source_span_text(node: clang.cindex.Cursor) -> str:
        """Best-effort extraction of the source text covered by node extent."""
        try:
            start_line = int(node.extent.start.line)
            end_line = int(node.extent.end.line)
            start_col = int(node.extent.start.column)
            end_col = int(node.extent.end.column)
        except Exception:
            return ""
        if (
            start_line <= 0
            or end_line <= 0
            or start_line > len(source_lines)
            or end_line > len(source_lines)
            or end_line < start_line
        ):
            return ""
        if start_line == end_line:
            line = source_lines[start_line - 1]
            if start_col <= 0 or end_col <= 0 or start_col > len(line) + 1:
                return line
            return line[start_col - 1 : max(start_col - 1, end_col - 1)]
        parts = []
        first = source_lines[start_line - 1]
        if start_col > 0 and start_col <= len(first) + 1:
            parts.append(first[start_col - 1 :])
        else:
            parts.append(first)
        for idx in range(start_line, end_line - 1):
            parts.append(source_lines[idx])
        last = source_lines[end_line - 1]
        if end_col > 0:
            parts.append(last[: max(0, end_col - 1)])
        else:
            parts.append(last)
        return "\n".join(parts)

    def _token_from_current_file(tok: clang.cindex.Token) -> bool:
        try:
            t_file = tok.location.file
            if not t_file:
                return False
            return Path(t_file.name).resolve() == file_path.resolve()
        except Exception:
            return False

    def _has_operator_token_in_current_file(
        node: clang.cindex.Cursor, operators: set[str]
    ) -> bool:
        try:
            for tok in node.get_tokens():
                if tok.spelling in operators and _token_from_current_file(tok):
                    return True
        except Exception:
            return False
        return False

    def is_header_suffix(path_obj: Path) -> bool:
        return path_obj.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}

    def is_class_or_function_scope(kind: Any) -> bool:
        return kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.DESTRUCTOR,
            CursorKind.CLASS_DECL,
            CursorKind.STRUCT_DECL,
            CursorKind.CLASS_TEMPLATE,
            CursorKind.CLASS_TEMPLATE_PARTIAL_SPECIALIZATION,
        )

    def get_returned_decl(
        return_stmt: clang.cindex.Cursor,
    ) -> Optional[clang.cindex.Cursor]:
        children = list(return_stmt.get_children())
        if not children:
            return None
        expr = unwrap_expr(children[0])
        if not expr:
            return None
        if expr.kind == CursorKind.DECL_REF_EXPR and expr.referenced:
            return expr.referenced
        if expr.kind == CursorKind.MEMBER_REF_EXPR and expr.referenced:
            return expr.referenced
        if expr.kind == CursorKind.UNARY_OPERATOR:
            toks = [t.spelling for t in tuple(expr.get_tokens())]
            if "&" in toks:
                expr_children = list(expr.get_children())
                if expr_children:
                    target = unwrap_expr(expr_children[-1])
                    if (
                        target
                        and target.kind == CursorKind.DECL_REF_EXPR
                        and target.referenced
                    ):
                        return target.referenced
                    if (
                        target
                        and target.kind == CursorKind.MEMBER_REF_EXPR
                        and target.referenced
                    ):
                        return target.referenced
        return None

    def _is_function_ref_without_address(
        expr: Optional[clang.cindex.Cursor],
    ) -> bool:
        cur = unwrap_expr(expr)
        if not cur:
            return False
        if cur.kind == CursorKind.CALL_EXPR:
            return False
        if cur.kind == CursorKind.UNARY_OPERATOR:
            toks = [t.spelling for t in tuple(cur.get_tokens())]
            if "&" in toks:
                children = list(cur.get_children())
                if children:
                    target = unwrap_expr(children[-1])
                    if (
                        target
                        and target.kind == CursorKind.DECL_REF_EXPR
                        and target.referenced
                    ):
                        return target.referenced.kind in (
                            CursorKind.FUNCTION_DECL,
                            CursorKind.CXX_METHOD,
                        )
                return False
        if cur.kind == CursorKind.DECL_REF_EXPR and cur.referenced:
            return cur.referenced.kind in (
                CursorKind.FUNCTION_DECL,
                CursorKind.CXX_METHOD,
            )
        return False

    def _method_has_default_argument(
        method_cursor: clang.cindex.Cursor,
    ) -> bool:
        for c in method_cursor.get_children():
            if c.kind != CursorKind.PARM_DECL:
                continue
            # Parameter default argument shows up as a non-TYPE_REF child.
            for ch in c.get_children():
                if ch.kind != CursorKind.TYPE_REF:
                    return True
        return False

    def _returns_non_const_handle(t: Optional[clang.cindex.Type]) -> bool:
        if not t:
            return False
        ct = t.get_canonical()
        if ct.kind not in (
            TypeKind.POINTER,
            TypeKind.LVALUEREFERENCE,
            TypeKind.RVALUEREFERENCE,
        ):
            return False
        try:
            pointee = ct.get_pointee()
            return not pointee.is_const_qualified()
        except Exception:
            return False

    def _method_sig_key(
        method_cursor: clang.cindex.Cursor,
    ) -> Tuple[str, int]:
        try:
            argc = len(list(method_cursor.get_arguments() or ()))
        except Exception:
            argc = -1
        return (method_cursor.spelling, argc)

    def _method_has_virtual_keyword(
        method_cursor: clang.cindex.Cursor,
    ) -> bool:
        try:
            toks = [t.spelling for t in tuple(method_cursor.get_tokens())]
        except Exception:
            toks = []
        return "virtual" in toks

    def _collect_base_member_names(
        base_decl: Optional[clang.cindex.Cursor],
    ) -> Set[str]:
        names: Set[str] = set()
        if not base_decl:
            return names
        for m in base_decl.get_children():
            if m.kind in (CursorKind.CXX_METHOD, CursorKind.FIELD_DECL):
                if m.spelling:
                    names.add(m.spelling)
        return names

    def _record_decl_from_type(
        t: Optional[clang.cindex.Type],
    ) -> Optional[clang.cindex.Cursor]:
        if not t:
            return None
        ct = t.get_canonical()
        if ct.kind in (
            TypeKind.LVALUEREFERENCE,
            TypeKind.RVALUEREFERENCE,
            TypeKind.POINTER,
        ):
            try:
                ct = ct.get_pointee().get_canonical()
            except Exception:
                return None
        if ct.kind in (
            TypeKind.RECORD,
            TypeKind.ELABORATED,
            TypeKind.UNEXPOSED,
        ):
            d = ct.get_declaration()
            if d and d.spelling:
                return d
        return None

    def is_write_mode(mode: str) -> bool:
        # fopen write-capable modes: w*, a*, r+, w+, a+
        if not mode:
            return False
        m = mode.lower()
        return m.startswith("w") or m.startswith("a") or "+" in m

    def is_read_only_mode(mode: str) -> bool:
        if not mode:
            return False
        m = mode.lower()
        return m.startswith("r") and "+" not in m

    def is_pod_like_type(t: Optional[clang.cindex.Type]) -> bool:
        if not t:
            return False
        tk = t.get_canonical().kind
        return tk in (
            TypeKind.BOOL,
            TypeKind.CHAR_S,
            TypeKind.SCHAR,
            TypeKind.UCHAR,
            TypeKind.SHORT,
            TypeKind.USHORT,
            TypeKind.INT,
            TypeKind.UINT,
            TypeKind.LONG,
            TypeKind.ULONG,
            TypeKind.LONGLONG,
            TypeKind.ULONGLONG,
            TypeKind.FLOAT,
            TypeKind.DOUBLE,
            TypeKind.LONGDOUBLE,
            TypeKind.ENUM,
            TypeKind.POINTER,
        )

    def get_namespace(n):
        if n.kind == CursorKind.LABEL_STMT:
            return "label"
        if n.kind in (
            CursorKind.STRUCT_DECL,
            CursorKind.UNION_DECL,
            CursorKind.ENUM_DECL,
        ):
            return "tag"
        if n.kind == CursorKind.FIELD_DECL:
            return "member"
        return "ordinary"

    def visit(node: clang.cindex.Cursor, current_func=None):
        nonlocal visited_nodes
        # Keep traversal focused on the current translation unit's source file.
        # Counting/traversing system-header subtrees quickly exhausts node_limit
        # and causes us to miss project-local diagnostics.
        if node.kind != CursorKind.TRANSLATION_UNIT:
            if (
                not node.location.file
                or Path(node.location.file.name).resolve()
                != file_path.resolve()
            ):
                return

        visited_nodes += 1
        if node_limit > 0 and visited_nodes > node_limit:
            return
        if visited_nodes == 1:
            _write_state("ast-walk-start", node)
        elif visited_nodes % 250 == 0:
            _write_state("ast-walk-progress", node)
        if trace_enabled:
            try:
                if (
                    node.location.file
                    and Path(node.location.file.name).resolve()
                    == file_path.resolve()
                ):
                    with open(trace_file_path, "a", encoding="utf-8") as tf:
                        tf.write(
                            f"{visited_nodes}\t{node.kind}\t{getattr(node.location, 'line', 0)}\t{node.spelling or ''}\n"
                        )
            except Exception:
                pass
        next_func = current_func
        if node.kind == CursorKind.TRANSLATION_UNIT or (
            node.location.file
            and Path(node.location.file.name).resolve() == file_path.resolve()
        ):
            if (
                node.kind in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD)
                and node.is_definition()
            ):
                next_func = node.hash
                chapter_15_funcs.append(node)
                function_nodes[node.hash] = node
                if is_cpp_file:
                    cpp_defined_functions[node.hash] = node
                    cpp_function_linkage[node.hash] = getattr(
                        node, "linkage", None
                    )
                    if (
                        node.result_type
                        and node.result_type.kind == TypeKind.VOID
                    ):
                        cpp_void_func_has_side_effect[node.hash] = False

                # Rule 17.4 is handled via compiler diagnostics.
                # The previous local "last statement must be return" heuristic caused
                # many false positives for valid control-flow structures (goto labels,
                # early returns, guarded returns).

            if (
                current_func
                and node.kind == CursorKind.DECL_REF_EXPR
                and node.referenced
            ):
                ref = node.referenced
                if ref.hash in file_vars_users:
                    file_vars_users[ref.hash].add(current_func)
                if is_cpp_file and ref.kind == CursorKind.VAR_DECL:
                    cpp_var_ref_counts[ref.hash] = (
                        cpp_var_ref_counts.get(ref.hash, 0) + 1
                    )

            if is_cpp_file and node.kind == CursorKind.VAR_DECL:
                cpp_var_decls[node.hash] = node
                cpp_var_ref_counts.setdefault(node.hash, 0)

            if global_db and node.kind == CursorKind.DECL_REF_EXPR:
                ref = node.referenced
                if (
                    ref
                    and hasattr(ref, "linkage")
                    and ref.linkage == clang.cindex.LinkageKind.EXTERNAL
                ):
                    # Ignore references whose declaration is in system headers
                    # (e.g. printf/malloc/cout), otherwise Rule 8.6 becomes noisy.
                    if not is_system_cursor(ref):
                        global_db.update_ext(
                            ref.spelling, None, False, str(file_path)
                        )

            if node.spelling:
                spelling = node.spelling

                if node.kind in (
                    CursorKind.MACRO_DEFINITION,
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                ):
                    if re.match(r"^_[_A-Z]", spelling) or spelling.startswith(
                        "__"
                    ):
                        if node.kind == CursorKind.MACRO_DEFINITION:
                            violations.append(
                                Violation(
                                    "Rule 21.1",
                                    f"#define and #undef shall not be used on a reserved identifier or reserved macro name: '{spelling}'",
                                    file_path,
                                    node.location.line,
                                    trigger=spelling,
                                )
                            )
                        else:
                            violations.append(
                                Violation(
                                    "Rule 21.2",
                                    f"A reserved identifier or macro name shall not be declared: '{spelling}'",
                                    file_path,
                                    node.location.line,
                                    trigger=spelling,
                                )
                            )

                if is_cpp_file:
                    # Rule 17-0-2 / 17-0-3: standard-library names shall not be reused.
                    if (
                        node.kind
                        in (
                            CursorKind.VAR_DECL,
                            CursorKind.FIELD_DECL,
                            CursorKind.FUNCTION_DECL,
                            CursorKind.CXX_METHOD,
                        )
                        and spelling in cpp_stdlib_symbol_names
                    ):
                        violations.append(
                            Violation(
                                "Rule 17-0-2",
                                f"The name of a standard library object/function shall not be reused: '{spelling}'.",
                                file_path,
                                node.location.line,
                                trigger=spelling,
                            )
                        )
                    if (
                        node.kind == CursorKind.MACRO_DEFINITION
                        and spelling in cpp_stdlib_macro_names
                    ):
                        violations.append(
                            Violation(
                                "Rule 17-0-3",
                                f"The name of a standard library macro shall not be reused: '{spelling}'.",
                                file_path,
                                node.location.line,
                                trigger=spelling,
                            )
                        )

                if global_db and node.kind in (
                    CursorKind.MACRO_DEFINITION,
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                    CursorKind.ENUM_CONSTANT_DECL,
                ):
                    loc_file = (
                        node.location.file.name if node.location.file else ""
                    )
                    linkage_str = (
                        str(node.linkage)
                        if hasattr(node, "linkage")
                        else "None"
                    )

                    category = "ordinary"
                    if node.kind == CursorKind.MACRO_DEFINITION:
                        category = "macro"
                    elif node.kind == CursorKind.TYPEDEF_DECL:
                        category = "typedef"
                    elif node.kind in (
                        CursorKind.STRUCT_DECL,
                        CursorKind.UNION_DECL,
                        CursorKind.ENUM_DECL,
                    ):
                        category = "tag"

                    global_db.add(
                        spelling,
                        loc_file,
                        node.location.line,
                        linkage_str,
                        category,
                    )

                if node.kind == CursorKind.FUNCTION_DECL:
                    if (
                        hasattr(node, "linkage")
                        and node.linkage == clang.cindex.LinkageKind.EXTERNAL
                        and node.lexical_parent
                        and node.lexical_parent.kind
                        == CursorKind.TRANSLATION_UNIT
                    ):
                        # Include type in key to avoid collisions between overloaded declarations in C++.
                        decl_key = (node.spelling, node.type.spelling)
                        if not node.is_definition():
                            visible_external_func_decls.add(decl_key)

                if global_db and node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                ):
                    if node.kind == CursorKind.FUNCTION_DECL:
                        is_defn_local = node.is_definition()
                        # Rule 8.13 collection should not depend on external linkage:
                        # static/internal function definitions can also violate const-correctness.
                        if is_defn_local:
                            func_ptr_params[node.hash] = []
                            func_ptr_param_names[node.hash] = set()
                            func_ptr_params_mutated[node.hash] = set()
                            func_ptr_params_mutated_names[node.hash] = set()
                            try:
                                for arg in node.get_arguments():
                                    arg_type = (
                                        arg.type.get_canonical()
                                        if arg.type
                                        else None
                                    )
                                    if (
                                        arg_type
                                        and arg_type.kind == TypeKind.POINTER
                                    ):
                                        pointee = arg_type.get_pointee()
                                        if not pointee.is_const_qualified():
                                            func_ptr_params[node.hash].append(
                                                (
                                                    arg.hash,
                                                    arg.spelling,
                                                    arg.location.line,
                                                )
                                            )
                                            if arg.spelling:
                                                func_ptr_param_names[
                                                    node.hash
                                                ].add(arg.spelling)
                            except Exception:
                                pass
                    if hasattr(node, "linkage"):
                        if node.linkage == clang.cindex.LinkageKind.EXTERNAL:
                            is_defn = node.is_definition()
                            loc_file = (
                                node.location.file.name
                                if node.location.file
                                else ""
                            )
                            global_db.update_ext(
                                spelling, loc_file, is_defn, None
                            )

                            params = []
                            if node.kind == CursorKind.FUNCTION_DECL:
                                try:
                                    for arg in node.get_arguments():
                                        params.append(
                                            (arg.type.spelling, arg.spelling)
                                        )
                                except Exception:
                                    pass

                            global_db.add_decl_signature(
                                spelling,
                                loc_file,
                                node.location.line,
                                node.type.spelling,
                                params,
                            )

                            if (
                                node.kind == CursorKind.VAR_DECL
                                and node.type.kind == TypeKind.INCOMPLETEARRAY
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 8.11",
                                        f"Array '{spelling}' with external linkage declared without explicit size.",
                                        file_path,
                                        node.location.line,
                                        trigger=spelling,
                                    )
                                )

                        elif (
                            node.linkage == clang.cindex.LinkageKind.INTERNAL
                            and spelling
                        ):
                            tokens = [t.spelling for t in node.get_tokens()]
                            if "static" not in tokens:
                                violations.append(
                                    Violation(
                                        "Rule 8.8",
                                        f"The 'static' storage class specifier shall be used in all declarations of objects and functions that have internal linkage: '{spelling}'",
                                        file_path,
                                        node.location.line,
                                        trigger=spelling,
                                    )
                                )

                if (
                    node.kind == CursorKind.VAR_DECL
                    and node.lexical_parent
                    and node.lexical_parent.kind == CursorKind.TRANSLATION_UNIT
                ):
                    is_extern_storage = (
                        getattr(node, "storage_class", None)
                        == clang.cindex.StorageClass.EXTERN
                    )
                    if not is_extern_storage and node.is_definition():
                        file_vars[node.hash] = node
                        file_vars_users[node.hash] = set()

                if is_cpp_file and node.kind == CursorKind.FIELD_DECL:
                    try:
                        is_bitfield = bool(node.is_bitfield())
                    except Exception:
                        is_bitfield = False
                    if is_bitfield:
                        violations.append(
                            Violation(
                                "Rule 9-6-1",
                                "Bit-fields shall not be declared.",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(node),
                            )
                        )
                        field_kind = (
                            node.type.get_canonical().kind
                            if node.type
                            else None
                        )
                        if field_kind == TypeKind.ENUM:
                            violations.append(
                                Violation(
                                    "Rule 9-6-3",
                                    "Bit-fields shall not have enum types.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        if field_kind not in (
                            TypeKind.UCHAR,
                            TypeKind.USHORT,
                            TypeKind.UINT,
                            TypeKind.ULONG,
                            TypeKind.ULONGLONG,
                            TypeKind.UINT128,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 9-6-2",
                                    "Bit-fields shall have an explicitly specified unsigned type.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        if node.spelling and _is_signed_integral_kind(
                            field_kind
                        ):
                            try:
                                width = int(node.get_bitfield_width())
                            except Exception:
                                width = None
                            if width is not None and width <= 1:
                                violations.append(
                                    Violation(
                                        "Rule 9-6-4",
                                        "Named bit-fields with signed integer type shall have a length of more than one bit.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

                # Chapter 22: Track resources obtained in variable initializers
                if node.kind == CursorKind.VAR_DECL:
                    # Rule 4-10-1: NULL shall not be used as an integer value.
                    if is_cpp_file and node.type:
                        t_kind = node.type.get_canonical().kind
                        if t_kind in (
                            TypeKind.BOOL,
                            TypeKind.CHAR_S,
                            TypeKind.SCHAR,
                            TypeKind.UCHAR,
                            TypeKind.SHORT,
                            TypeKind.USHORT,
                            TypeKind.INT,
                            TypeKind.UINT,
                            TypeKind.LONG,
                            TypeKind.ULONG,
                            TypeKind.LONGLONG,
                            TypeKind.ULONGLONG,
                            TypeKind.WCHAR,
                        ):
                            vtoks = [
                                t.spelling for t in tuple(node.get_tokens())
                            ]
                            init_null_like = any(
                                tok in {"NULL", "__null", "nullptr"}
                                for tok in vtoks
                            )
                            if not init_null_like:
                                init_children = [
                                    c
                                    for c in node.get_children()
                                    if c.kind != CursorKind.TYPE_REF
                                ]
                                for ic in init_children:
                                    ktxt = str(ic.kind)
                                    if (
                                        "GNU_NULL_EXPR" in ktxt
                                        or "CXX_NULL_PTR_LITERAL_EXPR" in ktxt
                                    ):
                                        init_null_like = True
                                        break
                            if init_null_like:
                                violations.append(
                                    Violation(
                                        "Rule 4-10-1",
                                        "NULL shall not be used as an integer value.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                    init_expr = None
                    for c in node.get_children():
                        if c.kind != CursorKind.TYPE_REF:
                            init_expr = unwrap_expr(c)
                            break
                    if (
                        is_cpp_file
                        and init_expr
                        and _is_function_ref_without_address(init_expr)
                    ):
                        violations.append(
                            Violation(
                                "Rule 8-4-4",
                                "A function identifier shall either be used to call the function or it shall be preceded by '&'.",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(init_expr)
                                or _cursor_text(node),
                            )
                        )
                    # Rule 9.2 (heuristic): brace-elision in nested aggregate initialization.
                    # If nested aggregate type is initialized by a flat init-list (without nested init-lists),
                    # emit a violation similar to missing-braces diagnostics.
                    if (
                        init_expr
                        and init_expr.kind == CursorKind.INIT_LIST_EXPR
                    ):
                        t = node.type.get_canonical()
                        is_nested_aggregate = False
                        if t.kind == TypeKind.CONSTANTARRAY:
                            et = t.element_type.get_canonical()
                            if et.kind in (
                                TypeKind.CONSTANTARRAY,
                                TypeKind.RECORD,
                            ):
                                is_nested_aggregate = True
                        elif t.kind == TypeKind.RECORD:
                            decl = t.get_declaration()
                            if decl and decl.kind in (
                                CursorKind.STRUCT_DECL,
                                CursorKind.UNION_DECL,
                            ):
                                for field in decl.get_children():
                                    if field.kind == CursorKind.FIELD_DECL:
                                        ft = field.type.get_canonical()
                                        if ft.kind in (
                                            TypeKind.CONSTANTARRAY,
                                            TypeKind.RECORD,
                                        ):
                                            is_nested_aggregate = True
                                            break
                        if is_nested_aggregate:
                            children = list(init_expr.get_children())
                            has_nested_list = any(
                                c.kind == CursorKind.INIT_LIST_EXPR
                                for c in children
                            )
                            if children and not has_nested_list:
                                violations.append(
                                    Violation(
                                        "Rule 9.2",
                                        "Initializer for a nested aggregate should be enclosed in braces.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(init_expr),
                                    )
                                )
                    if init_expr and init_expr.kind == CursorKind.CALL_EXPR:
                        called = get_call_name(init_expr)
                        if called in ("malloc", "calloc", "realloc"):
                            alloc_resources[node.hash] = {
                                "name": node.spelling,
                                "line": node.location.line,
                                "kind": "heap",
                            }
                        elif called == "fopen":
                            call_args = list(init_expr.get_arguments())
                            mode = ""
                            fname = ""
                            if len(call_args) >= 2:
                                mode = get_string_literal_text(call_args[1])
                            if len(call_args) >= 1:
                                fname = get_string_literal_text(call_args[0])
                            alloc_resources[node.hash] = {
                                "name": node.spelling,
                                "line": node.location.line,
                                "kind": "file",
                            }
                            file_modes[node.hash] = mode
                            if fname:
                                if fname not in file_opens:
                                    file_opens[fname] = []
                                file_opens[fname].append(
                                    {
                                        "hash": node.hash,
                                        "mode": mode,
                                        "line": node.location.line,
                                    }
                                )
                    # C++ Chapter 5 implicit conversion checks on initialization.
                    if is_cpp_file and init_expr:
                        dst_t = node.type.get_canonical()
                        src_expr = unwrap_expr(init_expr)
                        src_t = (
                            src_expr.type.get_canonical()
                            if src_expr and src_expr.type
                            else None
                        )
                        if src_t:
                            dst_k = dst_t.kind
                            src_k = src_t.kind
                            if _is_integral_kind(dst_k) and _is_integral_kind(
                                src_k
                            ):
                                if _is_unsigned_kind(
                                    dst_k
                                ) != _is_unsigned_kind(src_k):
                                    trigger_text = _cursor_text(
                                        src_expr
                                    ) or _cursor_text(init_expr)
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-4",
                                            "An implicit integral conversion shall not change the signedness of the underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-3",
                                            "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                try:
                                    if src_t.get_size() > dst_t.get_size():
                                        trigger_text = _cursor_text(
                                            src_expr
                                        ) or _cursor_text(init_expr)
                                        violations.append(
                                            Violation(
                                                "Rule 5-0-6",
                                                "An implicit conversion to a narrower type shall not occur.",
                                                file_path,
                                                node.location.line,
                                                trigger=trigger_text,
                                            )
                                        )
                                        violations.append(
                                            Violation(
                                                "Rule 5-0-3",
                                                "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                                file_path,
                                                node.location.line,
                                                trigger=trigger_text,
                                            )
                                        )
                                except Exception:
                                    pass
                            if (
                                _is_integral_kind(dst_k)
                                and _is_floating_kind(src_k)
                            ) or (
                                _is_floating_kind(dst_k)
                                and _is_integral_kind(src_k)
                            ):
                                trigger_text = _cursor_text(
                                    src_expr
                                ) or _cursor_text(init_expr)
                                violations.append(
                                    Violation(
                                        "Rule 5-0-5",
                                        "There shall be no implicit conversions between floating-point and integer types.",
                                        file_path,
                                        node.location.line,
                                        trigger=trigger_text,
                                    )
                                )
                                violations.append(
                                    Violation(
                                        "Rule 5-0-3",
                                        "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                        file_path,
                                        node.location.line,
                                        trigger=trigger_text,
                                    )
                                )
                            if (
                                dst_k == TypeKind.CHAR_S
                                and src_expr
                                and src_expr.kind
                                in (
                                    CursorKind.INTEGER_LITERAL,
                                    CursorKind.BINARY_OPERATOR,
                                    CursorKind.UNARY_OPERATOR,
                                )
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 5-0-11",
                                        "The plain char type shall only be used for the storage and use of character values.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(src_expr),
                                    )
                                )
                            if (
                                dst_k in (TypeKind.SCHAR, TypeKind.UCHAR)
                                and src_expr
                                and src_expr.kind
                                == CursorKind.CHARACTER_LITERAL
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 5-0-12",
                                        "Signed and unsigned char type shall only be used for the storage and use of numeric values.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(src_expr),
                                    )
                                )

            if is_cpp_file and node.kind in (
                CursorKind.CSTYLE_CAST_EXPR,
                CursorKind.CXX_STATIC_CAST_EXPR,
                CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
            ):
                dst_t = node.type.get_canonical() if node.type else None
                if dst_t and dst_t.kind == TypeKind.ENUM:
                    children = list(node.get_children())
                    if children:
                        rhs_val = _get_integer_literal_value(children[-1])
                        if rhs_val is not None:
                            allowed_vals = _enum_allowed_values_from_type(
                                dst_t
                            )
                            if allowed_vals and rhs_val not in allowed_vals:
                                violations.append(
                                    Violation(
                                        "Rule 7-2-1",
                                        "An expression with enum underlying type shall only have values corresponding to the enumerators.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(children[-1]),
                                    )
                                )

            if node.kind == CursorKind.ENUM_DECL:
                enum_usr = (
                    node.get_usr()
                    or f"{file_path}:{node.location.line}:{node.spelling}"
                )
                cpp_enum_allowed_values.setdefault(enum_usr, set())
                seen_values = set()
                for idx, enum_const in enumerate(node.get_children()):
                    if enum_const.kind == CursorKind.ENUM_CONSTANT_DECL:
                        val = enum_const.enum_value
                        cpp_enum_allowed_values[enum_usr].add(val)
                        is_explicit = False
                        for _ in enum_const.get_children():
                            is_explicit = True
                            break
                        if is_cpp_file and idx > 0 and is_explicit:
                            violations.append(
                                Violation(
                                    "Rule 8-5-3",
                                    "In an enumerator list, '=' should not be used to explicitly initialize members other than the first.",
                                    file_path,
                                    enum_const.location.line,
                                    trigger=enum_const.spelling,
                                )
                            )
                        if not is_explicit:
                            if val in seen_values:
                                violations.append(
                                    Violation(
                                        "Rule 8.12",
                                        f"Implicitly-specified enumeration constant '{enum_const.spelling}' has a non-unique value of {val}.",
                                        file_path,
                                        enum_const.location.line,
                                        trigger=enum_const.spelling,
                                    )
                                )
                        seen_values.add(val)

                if node.kind == CursorKind.MACRO_DEFINITION:
                    macros[spelling] = node
                    trunc31 = spelling[:31]
                    if (
                        trunc31 in macro_truncs
                        and macro_truncs[trunc31] != spelling
                    ):
                        violations.append(
                            Violation(
                                "Rule 5.4",
                                f"Macro identifiers shall be distinct: '{spelling}' vs '{macro_truncs[trunc31]}'",
                                file_path,
                                node.location.line,
                                trigger=spelling,
                            )
                        )
                    macro_truncs[trunc31] = spelling

                    # Chapter 20 Rules for MACRO_DEFINITION
                    try:
                        toks = [t.spelling for t in tuple(node.get_tokens())]
                        if len(toks) > 1:
                            name_idx = -1
                            for i, t in enumerate(toks):
                                if t == spelling:
                                    name_idx = i
                                    break

                            if name_idx != -1:
                                # Rule 20.10
                                if (
                                    "#" in toks[name_idx + 1 :]
                                    or "##" in toks[name_idx + 1 :]
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 20.10",
                                            "The # and ## preprocessor operators should not be used",
                                            file_path,
                                            node.location.line,
                                            trigger=spelling,
                                        )
                                    )

                                # Rule 20.11
                                for i in range(name_idx + 1, len(toks) - 2):
                                    if toks[i] == "#" and toks[i + 2] == "##":
                                        violations.append(
                                            Violation(
                                                "Rule 20.11",
                                                "A macro parameter immediately following a # operator shall not immediately be followed by a ## operator",
                                                file_path,
                                                node.location.line,
                                                trigger=spelling,
                                            )
                                        )

                                # Rule 20.12 Heuristic:
                                # If a parameter appears both as operand to #/## and as normal token, it is
                                # likely still subject to further replacement outside #/## context.
                                if (
                                    len(toks) > name_idx + 1
                                    and toks[name_idx + 1] == "("
                                ):
                                    param_end = name_idx + 1
                                    while (
                                        param_end < len(toks)
                                        and toks[param_end] != ")"
                                    ):
                                        param_end += 1
                                    if param_end < len(toks):
                                        raw_params = [
                                            p
                                            for p in toks[
                                                name_idx + 2 : param_end
                                            ]
                                            if p not in {",", "..."}
                                        ]
                                        params = set(raw_params)
                                        repl_list = toks[param_end + 1 :]
                                        if params and repl_list:
                                            hashed_use = set()
                                            normal_use = set()
                                            for j, tok in enumerate(repl_list):
                                                if tok not in params:
                                                    continue
                                                prev_tok = (
                                                    repl_list[j - 1]
                                                    if j > 0
                                                    else ""
                                                )
                                                next_tok = (
                                                    repl_list[j + 1]
                                                    if j + 1 < len(repl_list)
                                                    else ""
                                                )
                                                if (
                                                    prev_tok in {"#", "##"}
                                                    or next_tok == "##"
                                                ):
                                                    hashed_use.add(tok)
                                                else:
                                                    normal_use.add(tok)
                                            mixed = sorted(
                                                hashed_use & normal_use
                                            )
                                            for param in mixed:
                                                violations.append(
                                                    Violation(
                                                        "Rule 20.12",
                                                        f"Macro parameter '{param}' is used as operand to #/## and also in normal replacement context.",
                                                        file_path,
                                                        node.location.line,
                                                        trigger=param,
                                                    )
                                                )

                                # Rule 20.7 is handled via the fallback source scan where
                                # parameter-level parenthesization can be checked more precisely.
                    except Exception:
                        pass
                elif node.kind == CursorKind.MACRO_INSTANTIATION:
                    # Rule 20.6
                    try:
                        toks = [t.spelling for t in tuple(node.get_tokens())]
                        directives = {
                            "define",
                            "undef",
                            "include",
                            "if",
                            "ifdef",
                            "ifndef",
                            "elif",
                            "else",
                            "endif",
                            "line",
                            "error",
                            "pragma",
                        }
                        for i in range(len(toks) - 1):
                            if toks[i] == "#" and toks[i + 1] in directives:
                                violations.append(
                                    Violation(
                                        "Rule 20.6",
                                        "Tokens that look like a preprocessing directive shall not occur within a macro argument",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                                break
                    except Exception:
                        pass
                elif node.kind == CursorKind.TYPEDEF_DECL:
                    typedefs[spelling] = node
                elif node.kind in (
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                ):
                    tags[spelling] = node
                elif node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                    CursorKind.FIELD_DECL,
                    CursorKind.ENUM_CONSTANT_DECL,
                    CursorKind.LABEL_STMT,
                ):
                    ordinary[spelling] = node

            if is_cpp_file and node.kind == CursorKind.USING_DECLARATION:
                parent = node.lexical_parent or node.semantic_parent
                scope_hash = parent.hash if parent else 0
                target_name = _extract_using_target_name(node)
                if target_name:
                    cpp_scope_using_lines.setdefault(
                        scope_hash, {}
                    ).setdefault(target_name, []).append(node.location.line)

            if is_cpp_file and _is_asm_cursor(node):
                line = node.location.line
                violations.append(
                    Violation(
                        "Rule 7-4-2",
                        "Assembler instructions shall only be introduced using the asm declaration.",
                        file_path,
                        line,
                        trigger="asm",
                    )
                )
                if not _is_documented_asm_line(line):
                    violations.append(
                        Violation(
                            "Rule 7-4-1",
                            "All usage of assembler shall be documented.",
                            file_path,
                            line,
                            trigger="asm",
                        )
                    )
                if current_func:
                    cpp_func_has_asm[current_func] = True
                    cpp_func_asm_lines.setdefault(current_func, []).append(
                        line
                    )

            if is_cpp_file and node.kind == CursorKind.USING_DIRECTIVE:
                violations.append(
                    Violation(
                        "Rule 7-3-4",
                        "using-directives shall not be used.",
                        file_path,
                        node.location.line,
                        trigger=_cursor_text(node),
                    )
                )

            if is_cpp_file and node.kind in (
                CursorKind.USING_DECLARATION,
                CursorKind.USING_DIRECTIVE,
            ):
                try:
                    if is_header_suffix(file_path):
                        parent = node.semantic_parent or node.lexical_parent
                        parent_kind = parent.kind if parent else None
                        if not is_class_or_function_scope(parent_kind):
                            violations.append(
                                Violation(
                                    "Rule 7-3-6",
                                    "using-directives and using-declarations shall not be used in header files outside class/function scope.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                except Exception:
                    pass

            if is_cpp_file and node.kind == CursorKind.NAMESPACE:
                try:
                    if (
                        is_header_suffix(file_path)
                        and not (node.spelling or "").strip()
                    ):
                        violations.append(
                            Violation(
                                "Rule 7-3-3",
                                "There shall be no unnamed namespaces in header files.",
                                file_path,
                                node.location.line,
                                trigger="{namespace}",
                            )
                        )
                except Exception:
                    pass

            if is_cpp_file and node.spelling:
                # Rule 7-3-1: global namespace contents are restricted.
                if node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.CLASS_DECL,
                ):
                    parent = node.lexical_parent or node.semantic_parent
                    if parent and parent.kind == CursorKind.TRANSLATION_UNIT:
                        allowed = (
                            node.kind == CursorKind.FUNCTION_DECL
                            and node.spelling == "main"
                        )
                        if not allowed:
                            violations.append(
                                Violation(
                                    "Rule 7-3-1",
                                    (
                                        "The global namespace shall only contain main, namespace declarations "
                                        'and extern "C" declarations.'
                                    ),
                                    file_path,
                                    node.location.line,
                                    trigger=node.spelling,
                                )
                            )

                if (
                    node.kind
                    in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD)
                    and node.spelling == "main"
                ):
                    parent = node.semantic_parent or node.lexical_parent
                    if parent and parent.kind != CursorKind.TRANSLATION_UNIT:
                        violations.append(
                            Violation(
                                "Rule 7-3-2",
                                "The identifier 'main' shall not be used for a function other than the global function main.",
                                file_path,
                                node.location.line,
                                trigger=node.spelling,
                            )
                        )
                if node.kind in (
                    CursorKind.FUNCTION_DECL,
                    CursorKind.CXX_METHOD,
                ):
                    op_name = node.spelling.replace(" ", "")
                    if op_name == "operator&":
                        violations.append(
                            Violation(
                                "Rule 5-3-3",
                                "The unary & operator shall not be overloaded.",
                                file_path,
                                node.location.line,
                                trigger=node.spelling,
                            )
                        )
                scope_parent = node.lexical_parent or node.semantic_parent
                scope_hash = scope_parent.hash if scope_parent else 0
                if scope_parent:
                    parent_scope = (
                        scope_parent.lexical_parent
                        or scope_parent.semantic_parent
                    )
                    cpp_scope_parent.setdefault(
                        scope_hash, parent_scope.hash if parent_scope else 0
                    )

                # Rule 3-2-3: entity should not be declared multiple times in one TU (heuristic).
                if node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.CLASS_DECL,
                ):
                    usr = (
                        node.get_usr()
                        or f"{scope_hash}:{node.kind}:{node.spelling}"
                    )
                    key = (str(node.kind), usr)
                    cpp_entity_decl_lines.setdefault(key, []).append(
                        (node.location.line, node.spelling)
                    )

                    # Rule 7-3-5 support: declaration lines in same namespace scope.
                    if node.kind in (
                        CursorKind.VAR_DECL,
                        CursorKind.FUNCTION_DECL,
                        CursorKind.TYPEDEF_DECL,
                        CursorKind.STRUCT_DECL,
                        CursorKind.UNION_DECL,
                        CursorKind.ENUM_DECL,
                        CursorKind.CLASS_DECL,
                    ):
                        cpp_scope_decl_lines.setdefault(
                            scope_hash, {}
                        ).setdefault(node.spelling, []).append(
                            node.location.line
                        )

                # Rule 3-9-2: encourage size/signedness typedef usage over basic numeric types (heuristic).
                if node.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                    type_spelling = node.type.spelling if node.type else ""
                    should_check = False
                    if (
                        node.kind == CursorKind.VAR_DECL
                        and getattr(node, "linkage", None)
                        == clang.cindex.LinkageKind.EXTERNAL
                    ):
                        should_check = True
                    elif node.kind == CursorKind.PARM_DECL:
                        parent = node.semantic_parent or node.lexical_parent
                        if (
                            parent
                            and parent.kind == CursorKind.FUNCTION_DECL
                            and getattr(parent, "linkage", None)
                            == clang.cindex.LinkageKind.EXTERNAL
                        ):
                            should_check = True
                    if should_check and type_spelling in {
                        "short",
                        "unsigned short",
                        "int",
                        "unsigned int",
                        "long",
                        "unsigned long",
                        "long long",
                        "unsigned long long",
                    }:
                        violations.append(
                            Violation(
                                "Rule 3-9-2",
                                (
                                    f"Basic numerical type '{type_spelling}' used for '{node.spelling}'; "
                                    "typedefs indicating size and signedness should be preferred."
                                ),
                                file_path,
                                node.location.line,
                                trigger=node.spelling or type_spelling,
                            )
                        )

                # Rule 2-10-2: inner-scope declaration should not hide outer declaration.
                if node.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                    ancestor_scope = cpp_scope_parent.get(scope_hash, 0)
                    while ancestor_scope:
                        anc_map = cpp_scope_decl_names.get(ancestor_scope, {})
                        if node.spelling in anc_map:
                            key = (
                                scope_hash,
                                node.spelling,
                                node.location.line,
                            )
                            if key not in cpp_rule_2_10_2_reported:
                                cpp_rule_2_10_2_reported.add(key)
                                violations.append(
                                    Violation(
                                        "Rule 5.3",
                                        f"Identifier '{node.spelling}' declared in an inner scope hides an identifier declared in an outer scope.",
                                        file_path,
                                        node.location.line,
                                        trigger=node.spelling,
                                    )
                                )
                            break
                        ancestor_scope = cpp_scope_parent.get(
                            ancestor_scope, 0
                        )
                    cpp_scope_decl_names.setdefault(scope_hash, {}).setdefault(
                        node.spelling, node
                    )

                # Rule 2-10-5: non-member object/function with static storage duration should not be reused.
                if node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                ):
                    parent = node.semantic_parent or node.lexical_parent
                    parent_kind = parent.kind if parent else None
                    is_non_member = parent_kind in (
                        CursorKind.TRANSLATION_UNIT,
                        CursorKind.NAMESPACE,
                    )
                    if is_non_member:
                        linkage = getattr(node, "linkage", None)
                        is_static_duration = linkage in (
                            clang.cindex.LinkageKind.EXTERNAL,
                            clang.cindex.LinkageKind.INTERNAL,
                        )
                        if is_static_duration:
                            usr = (
                                node.get_usr()
                                or f"{node.kind}:{node.spelling}:{node.location.line}"
                            )
                            cpp_static_duration_names.setdefault(
                                node.spelling, []
                            ).append((node, usr))

                # Rule 2-10-6: type identifier shall not also refer to object/function in same scope.
                if node.kind in (
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.CLASS_DECL,
                ):
                    cpp_scope_type_names.setdefault(scope_hash, {}).setdefault(
                        node.spelling, node
                    )
                elif node.kind in (
                    CursorKind.VAR_DECL,
                    CursorKind.FUNCTION_DECL,
                ):
                    cpp_scope_objfunc_names.setdefault(
                        scope_hash, {}
                    ).setdefault(node.spelling, node)
                    type_map = cpp_scope_type_names.get(scope_hash, {})
                    if node.spelling in type_map:
                        key = (scope_hash, node.spelling)
                        if key not in cpp_rule_2_10_6_reported:
                            cpp_rule_2_10_6_reported.add(key)
                            violations.append(
                                Violation(
                                    "Rule 2-10-6",
                                    f"Identifier '{node.spelling}' refers to both a type and an object/function in the same scope.",
                                    file_path,
                                    node.location.line,
                                    trigger=node.spelling,
                                )
                            )
                elif node.kind in (
                    CursorKind.TYPEDEF_DECL,
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.CLASS_DECL,
                ):
                    obj_map = cpp_scope_objfunc_names.get(scope_hash, {})
                    if node.spelling in obj_map:
                        key = (scope_hash, node.spelling)
                        if key not in cpp_rule_2_10_6_reported:
                            cpp_rule_2_10_6_reported.add(key)
                            violations.append(
                                Violation(
                                    "Rule 2-10-6",
                                    f"Identifier '{node.spelling}' refers to both a type and an object/function in the same scope.",
                                    file_path,
                                    node.location.line,
                                    trigger=node.spelling,
                                )
                            )

                # Rule 2-10-1: Different identifiers shall be typographically unambiguous.
                if (
                    rule_2_10_1_enabled
                    and len(node.spelling) >= rule_2_10_1_min_len
                ):
                    if node.kind in (
                        CursorKind.VAR_DECL,
                        CursorKind.FUNCTION_DECL,
                        CursorKind.PARM_DECL,
                        CursorKind.FIELD_DECL,
                        CursorKind.TYPEDEF_DECL,
                        CursorKind.STRUCT_DECL,
                        CursorKind.UNION_DECL,
                        CursorKind.ENUM_DECL,
                        CursorKind.CLASS_DECL,
                        CursorKind.ENUM_CONSTANT_DECL,
                    ):
                        scope_parent = (
                            node.lexical_parent or node.semantic_parent
                        )
                        scope_hash = scope_parent.hash if scope_parent else 0
                        norm = normalize_typo_identifier(node.spelling)
                        usr = node.get_usr() or (
                            f"{node.kind}:{node.spelling}:{node.location.line}"
                        )
                        scope_map = cpp_typo_scope_names.setdefault(
                            scope_hash, {}
                        )
                        norm_map = scope_map.setdefault(norm, {})
                        if usr not in norm_map:
                            norm_map[usr] = (node.spelling, node.location.line)

            if (
                is_cpp_file
                and current_func
                and current_func in cpp_void_func_has_side_effect
            ):
                if node.kind in (
                    CursorKind.BINARY_OPERATOR,
                    CursorKind.UNARY_OPERATOR,
                    CursorKind.CALL_EXPR,
                    CursorKind.CXX_NEW_EXPR,
                    CursorKind.CXX_DELETE_EXPR,
                    CursorKind.CXX_THROW_EXPR,
                ):
                    if node.kind == CursorKind.BINARY_OPERATOR:
                        op_toks = [
                            t.spelling for t in tuple(node.get_tokens())
                        ]
                        if any(
                            op in op_toks
                            for op in (
                                "=",
                                "+=",
                                "-=",
                                "*=",
                                "/=",
                                "%=",
                                "&=",
                                "|=",
                                "^=",
                                "<<=",
                                ">>=",
                            )
                        ):
                            cpp_void_func_has_side_effect[current_func] = True
                    elif node.kind == CursorKind.UNARY_OPERATOR:
                        op_toks = [
                            t.spelling for t in tuple(node.get_tokens())
                        ]
                        if (
                            "++" in op_toks
                            or "--" in op_toks
                            or "*" in op_toks
                        ):
                            cpp_void_func_has_side_effect[current_func] = True
                    else:
                        cpp_void_func_has_side_effect[current_func] = True

            if node.kind == CursorKind.INTEGER_LITERAL:
                if node.type.kind in (
                    clang.cindex.TypeKind.UINT,
                    clang.cindex.TypeKind.ULONG,
                    clang.cindex.TypeKind.ULONGLONG,
                ):
                    tokens = list(node.get_tokens())
                    if tokens:
                        orig = tokens[0].spelling
                        text = orig.lower()
                        if "u" not in text:
                            violations.append(
                                Violation(
                                    "Rule 7.2",
                                    f"A 'u' or 'U' suffix shall be applied to all integer constants that are represented in an unsigned type: '{orig}'",
                                    file_path,
                                    node.location.line,
                                    trigger=orig,
                                )
                            )
                            if is_cpp_file and text.startswith(("0x", "0")):
                                violations.append(
                                    Violation(
                                        "Rule 2-13-3",
                                        f"A 'U' suffix shall be applied to octal or hexadecimal constants of unsigned type: '{orig}'",
                                        file_path,
                                        node.location.line,
                                        trigger=orig,
                                    )
                                )

            if node.kind in (
                CursorKind.VAR_DECL,
                CursorKind.PARM_DECL,
                CursorKind.FIELD_DECL,
                CursorKind.FUNCTION_DECL,
            ):
                # Rule 18.5: Declarations should contain no more than two levels of pointer nesting
                def get_pointer_depth(t):
                    depth = 0
                    while t.kind == TypeKind.POINTER:
                        depth += 1
                        t = t.get_pointee()
                    return depth

                check_type = (
                    node.result_type
                    if node.kind == CursorKind.FUNCTION_DECL
                    else node.type
                )
                if get_pointer_depth(check_type) > 2:
                    violations.append(
                        Violation(
                            "Rule 18.5",
                            "Declarations should contain no more than two levels of pointer nesting",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(node),
                        )
                    )

            if node.kind in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL):
                # Rule 18.8: Variable-length array types shall not be used
                if node.type.kind == TypeKind.VARIABLEARRAY:
                    violations.append(
                        Violation(
                            "Rule 18.8",
                            "Variable-length array types shall not be used",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(node),
                        )
                    )

            if node.kind == CursorKind.FIELD_DECL:
                # Rule 18.7: Flexible array members shall not be declared
                if node.type.kind == TypeKind.INCOMPLETEARRAY:
                    violations.append(
                        Violation(
                            "Rule 18.7",
                            "Flexible array members shall not be declared",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(node),
                        )
                    )

            if node.spelling and node.kind in (
                CursorKind.VAR_DECL,
                CursorKind.FUNCTION_DECL,
                CursorKind.STRUCT_DECL,
                CursorKind.UNION_DECL,
                CursorKind.ENUM_DECL,
                CursorKind.TYPEDEF_DECL,
                CursorKind.ENUM_CONSTANT_DECL,
                CursorKind.LABEL_STMT,
                CursorKind.FIELD_DECL,
            ):
                spelling = node.spelling
                # Rule 5.1: External (31 chars)
                if node.linkage == clang.cindex.LinkageKind.EXTERNAL:
                    trunc31 = spelling[:31]
                    if (
                        trunc31 in external_identifiers
                        and external_identifiers[trunc31] != spelling
                    ):
                        violations.append(
                            Violation(
                                "Rule 5.1",
                                f"External identifiers shall be distinct: '{spelling}' vs '{external_identifiers[trunc31]}'",
                                file_path,
                                node.location.line,
                                trigger=spelling,
                            )
                        )
                    external_identifiers[trunc31] = spelling
                else:
                    # Rule 5.2: Internal/Scope (63 chars)
                    parent = node.lexical_parent
                    if parent:
                        scope_key = (parent.hash, get_namespace(node))
                        if scope_key not in internal_scopes:
                            internal_scopes[scope_key] = {}
                        trunc63 = spelling[:63]
                        if (
                            trunc63 in internal_scopes[scope_key]
                            and internal_scopes[scope_key][trunc63] != spelling
                        ):
                            violations.append(
                                Violation(
                                    "Rule 5.2",
                                    f"Identifiers in same scope shall be distinct: '{spelling}' vs '{internal_scopes[scope_key][trunc63]}'",
                                    file_path,
                                    node.location.line,
                                    trigger=spelling,
                                )
                            )
                        internal_scopes[scope_key][trunc63] = spelling

            # Track tags for Rules 2.3 and 2.4
            if (
                node.kind
                in (
                    CursorKind.STRUCT_DECL,
                    CursorKind.UNION_DECL,
                    CursorKind.ENUM_DECL,
                    CursorKind.TYPEDEF_DECL,
                )
                and node.spelling
            ):
                declared_tags[node.hash] = node
            elif node.kind == CursorKind.TYPE_REF and node.referenced:
                used_tags.add(node.referenced.hash)
            # Chapter 11 AST checks (Pointer Type Conversions)
            if node.kind in (
                CursorKind.CSTYLE_CAST_EXPR,
                CursorKind.CXX_STATIC_CAST_EXPR,
                CursorKind.CXX_REINTERPRET_CAST_EXPR,
                CursorKind.VAR_DECL,
                CursorKind.BINARY_OPERATOR,
            ):
                children = list(node.get_children())

                is_assignment = False
                if (
                    node.kind == CursorKind.BINARY_OPERATOR
                    and len(children) >= 2
                ):
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break
                    if op_spelling == "=":
                        is_assignment = True

                if children and (
                    node.kind != CursorKind.BINARY_OPERATOR or is_assignment
                ):
                    init_expr = None
                    if node.kind in (
                        CursorKind.VAR_DECL,
                        CursorKind.CSTYLE_CAST_EXPR,
                        CursorKind.CXX_STATIC_CAST_EXPR,
                        CursorKind.CXX_REINTERPRET_CAST_EXPR,
                    ):
                        if node.kind == CursorKind.VAR_DECL:
                            # Declarations without initializer are not conversions.
                            node_toks = [
                                t.spelling for t in tuple(node.get_tokens())
                            ]
                            if "=" not in node_toks:
                                init_expr = None
                            else:
                                for c in children:
                                    if c.kind != CursorKind.TYPE_REF:
                                        init_expr = c
                                        break
                        else:
                            # skip type_ref
                            for c in children:
                                if c.kind != CursorKind.TYPE_REF:
                                    init_expr = c
                                    break
                    elif node.kind == CursorKind.BINARY_OPERATOR:
                        init_expr = children[1] if len(children) > 1 else None

                    if init_expr:
                        # For unexposed implicit casts, the real source is wrapped inside
                        # e.g. for `void *pv = pi;` init_expr is an UNEXPOSED_EXPR with type `void*`
                        # but its child is the `pi` DECL_REF_EXPR with type `struct incomplete*`
                        src_type = None
                        if init_expr.kind == CursorKind.UNEXPOSED_EXPR:
                            cast_children = list(init_expr.get_children())
                            if cast_children:
                                src_type = cast_children[
                                    0
                                ].type.get_canonical()
                        if not src_type:
                            src_type = init_expr.type.get_canonical()

                        dst_type = (
                            node.type.get_canonical()
                            if node.kind not in (CursorKind.BINARY_OPERATOR,)
                            else children[0].type.get_canonical()
                        )

                        src_k = src_type.kind
                        dst_k = dst_type.kind

                        def is_ptr(t):
                            return t.kind == TypeKind.POINTER

                        def is_func_type(t):
                            return t.kind in (
                                TypeKind.FUNCTIONPROTO,
                                TypeKind.FUNCTIONNOPROTO,
                            )

                        def is_func_ptr(t):
                            if not is_ptr(t):
                                return False
                            return t.get_pointee().kind in (
                                TypeKind.FUNCTIONPROTO,
                                TypeKind.FUNCTIONNOPROTO,
                            )

                        def is_incomplete_ptr(t):
                            if not is_ptr(t):
                                return False
                            pte = t.get_pointee()
                            # Rule 11.2 is aimed at pointers to incomplete object types
                            # (e.g. forward-declared struct/union), not generic arrays.
                            if pte.kind == TypeKind.VOID:
                                return False
                            if pte.kind not in (
                                TypeKind.RECORD,
                                TypeKind.ELABORATED,
                                TypeKind.UNEXPOSED,
                            ):
                                return False
                            return pte.get_size() < 0

                        def is_void_ptr(t):
                            return (
                                is_ptr(t)
                                and t.get_pointee().kind == TypeKind.VOID
                            )

                        def is_obj_ptr(t):
                            return (
                                is_ptr(t)
                                and not is_func_ptr(t)
                                and not is_incomplete_ptr(t)
                                and not is_void_ptr(t)
                            )

                        def is_int(t):
                            return t.kind in (
                                TypeKind.INT,
                                TypeKind.UINT,
                                TypeKind.LONG,
                                TypeKind.ULONG,
                                TypeKind.LONGLONG,
                                TypeKind.ULONGLONG,
                                TypeKind.CHAR_S,
                                TypeKind.SCHAR,
                                TypeKind.UCHAR,
                                TypeKind.SHORT,
                                TypeKind.USHORT,
                                TypeKind.ENUM,
                            )

                        def is_float(t):
                            return t.kind in (
                                TypeKind.FLOAT,
                                TypeKind.DOUBLE,
                                TypeKind.LONGDOUBLE,
                            )

                        def is_char_like_pointee_kind(k):
                            return k in (
                                TypeKind.CHAR_S,
                                TypeKind.SCHAR,
                                TypeKind.UCHAR,
                                TypeKind.CHAR_U,
                            )

                        def is_null_pointer_constant_expr(expr):
                            if not expr:
                                return False
                            leaf = expr
                            while leaf and leaf.kind in (
                                CursorKind.UNEXPOSED_EXPR,
                                CursorKind.PAREN_EXPR,
                                CursorKind.CSTYLE_CAST_EXPR,
                            ):
                                c = [
                                    x
                                    for x in leaf.get_children()
                                    if x.kind != CursorKind.TYPE_REF
                                ]
                                if not c:
                                    break
                                leaf = c[-1]
                            if not leaf:
                                return False
                            toks = [
                                t.spelling for t in tuple(leaf.get_tokens())
                            ]
                            if "NULL" in toks:
                                return True
                            if (
                                leaf.kind == CursorKind.INTEGER_LITERAL
                                and toks
                            ):
                                lit = toks[0].lower()
                                lit = re.sub(r"[uUlL]+$", "", lit)
                                try:
                                    if lit.startswith("0x"):
                                        return int(lit, 16) == 0
                                    if lit.startswith("0b"):
                                        return int(lit, 2) == 0
                                    if (
                                        len(lit) > 1
                                        and lit.startswith("0")
                                        and lit.isdigit()
                                    ):
                                        return int(lit, 8) == 0
                                    return int(lit, 10) == 0
                                except ValueError:
                                    return False
                            return False

                        # Prevent redundant flagging if types are identical
                        if src_type != dst_type:
                            is_explicit_cast_node = node.kind in (
                                CursorKind.CSTYLE_CAST_EXPR,
                                CursorKind.CXX_STATIC_CAST_EXPR,
                                CursorKind.CXX_REINTERPRET_CAST_EXPR,
                            )
                            # Rule 11.1
                            if (
                                is_func_ptr(src_type)
                                and not is_func_ptr(dst_type)
                            ) or (
                                not is_func_ptr(src_type)
                                and is_func_ptr(dst_type)
                            ):
                                # Function designator -> function pointer is a standard conversion, not Rule 11.1.
                                if (
                                    is_func_type(src_type)
                                    and is_func_ptr(dst_type)
                                ) or (
                                    is_func_ptr(src_type)
                                    and is_func_type(dst_type)
                                ):
                                    pass
                                # Be strict only for explicit casts; implicit function-designator
                                # and declaration-related conversions are too noisy in practice.
                                elif not is_explicit_cast_node:
                                    pass
                                else:
                                    violations.append(
                                        Violation(
                                            "Rule 11.1",
                                            "Conversions shall not be performed between a pointer to a function and any other type",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                            # Rule 11.2
                            elif (
                                is_incomplete_ptr(src_type)
                                and not is_incomplete_ptr(dst_type)
                            ) or (
                                not is_incomplete_ptr(src_type)
                                and is_incomplete_ptr(dst_type)
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 11.2",
                                        "Conversions shall not be performed between a pointer to an incomplete type and any other type",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

                            # Rule 11.3
                            elif is_obj_ptr(src_type) and is_obj_ptr(dst_type):
                                if is_explicit_cast_node:
                                    src_pointee = (
                                        src_type.get_pointee().get_canonical()
                                    )
                                    dst_pointee = (
                                        dst_type.get_pointee().get_canonical()
                                    )
                                    src_kind = src_pointee.kind
                                    dst_kind = dst_pointee.kind
                                    if src_kind != dst_kind:
                                        violations.append(
                                            Violation(
                                                "Rule 11.3",
                                                "A cast shall not be performed between a pointer to object type and a pointer to a different object type",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(node),
                                            )
                                        )

                            # Rule 11.4
                            elif (
                                is_obj_ptr(src_type) and is_int(dst_type)
                            ) or (is_int(src_type) and is_obj_ptr(dst_type)):
                                if not is_null_pointer_constant_expr(
                                    init_expr
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 11.4",
                                            "A conversion should not be performed between a pointer to object and an integer type",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                            # Rule 11.5
                            elif is_void_ptr(src_type) and is_obj_ptr(
                                dst_type
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 11.5",
                                        "A conversion should not be performed from pointer to void into pointer to object",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

                            # Rule 11.6
                            elif (
                                is_void_ptr(src_type)
                                and (is_int(dst_type) or is_float(dst_type))
                            ) or (
                                (is_int(src_type) or is_float(src_type))
                                and is_void_ptr(dst_type)
                            ):
                                # Only literal 0 is strictly allowed by 11.9, but 11.6 forbids general arithmetic
                                violations.append(
                                    Violation(
                                        "Rule 11.6",
                                        "A cast shall not be performed between pointer to void and an arithmetic type",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

                            # Rule 11.7
                            elif (is_ptr(src_type) and is_float(dst_type)) or (
                                is_float(src_type) and is_ptr(dst_type)
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 11.7",
                                        "A cast shall not be performed between pointer to object and a non-integer arithmetic type",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            elif node.kind in (
                                CursorKind.CSTYLE_CAST_EXPR,
                                CursorKind.CXX_STATIC_CAST_EXPR,
                                CursorKind.CXX_REINTERPRET_CAST_EXPR,
                            ):
                                # Fallback: explicit pointer cast from a floating literal can be missed by type recovery.
                                try:
                                    dst_is_ptr = (
                                        dst_type.kind == TypeKind.POINTER
                                    )
                                    cast_toks = [
                                        t.spelling
                                        for t in tuple(node.get_tokens())
                                    ]
                                    has_float_literal = any(
                                        re.match(
                                            r"^[0-9]*\\.[0-9]+([eE][+-]?[0-9]+)?[fFlL]?$",
                                            tok,
                                        )
                                        for tok in cast_toks
                                    )
                                    if dst_is_ptr and has_float_literal:
                                        violations.append(
                                            Violation(
                                                "Rule 11.7",
                                                "A cast shall not be performed between pointer to object and a non-integer arithmetic type",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(node),
                                            )
                                        )
                                except Exception:
                                    pass

                            # Rule 11.8
                            if is_ptr(src_type) and is_ptr(dst_type):
                                src_pte = src_type.get_pointee()
                                dst_pte = dst_type.get_pointee()
                                if (
                                    src_pte.is_const_qualified()
                                    and not dst_pte.is_const_qualified()
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 11.8",
                                            "A cast shall not remove any const qualification from the type pointed to by a pointer.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                                if (
                                    src_pte.is_volatile_qualified()
                                    and not dst_pte.is_volatile_qualified()
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 11.8",
                                            "A cast shall not remove any volatile qualification from the type pointed to by a pointer.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                        # Rule 11.9: The macro NULL shall be the only permitted form of integer null pointer constant
                        # We look for situations where an integer literal '0' is cast or assigned to a pointer.
                        if is_ptr(dst_type) and init_expr:
                            # Find the underlying leaf expression
                            def get_leaf(n):
                                while n and n.kind in (
                                    CursorKind.UNEXPOSED_EXPR,
                                    CursorKind.PAREN_EXPR,
                                    CursorKind.CSTYLE_CAST_EXPR,
                                ):
                                    c = list(n.get_children())
                                    # Skip over type_ref
                                    child = None
                                    for sub in c:
                                        if sub.kind != CursorKind.TYPE_REF:
                                            child = sub
                                            break
                                    if not child:
                                        break
                                    n = child
                                return n

                            leaf = get_leaf(init_expr)
                            if (
                                leaf
                                and leaf.kind == CursorKind.INTEGER_LITERAL
                            ):
                                toks = list(leaf.get_tokens())
                                if toks and toks[0].spelling == "0":
                                    top_toks = list(init_expr.get_tokens())
                                    if (
                                        "misra_c_2012_part2.c"
                                        in str(file_path)
                                        and node.location.line == 131
                                    ):
                                        logger.debug(
                                            "Rule 11.9 debug (line 131): in_sys=%s toks=%s top_toks=%s",
                                            leaf.location.is_in_system_header,
                                            [t.spelling for t in toks],
                                            [t.spelling for t in top_toks],
                                        )
                                    if not leaf.location.is_in_system_header:
                                        if top_toks and any(
                                            t.spelling == "NULL"
                                            for t in top_toks
                                        ):
                                            pass  # It was NULL
                                        else:
                                            violations.append(
                                                Violation(
                                                    "Rule 11.9",
                                                    "The macro NULL shall be the only permitted form of integer null pointer constant",
                                                    file_path,
                                                    node.location.line,
                                                    trigger=_cursor_text(node),
                                                )
                                            )

            # Chapter 12 Expressions
            if node.kind == CursorKind.BINARY_OPERATOR:
                children = list(node.get_children())
                if len(children) >= 2:
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break

                    if op_spelling:
                        # Rule 12.1: Precedence of operators within expressions should be made explicit
                        # If a binary operator has another binary operator as a child WITHOUT parentheses
                        def get_precedence_group(op):
                            if op in ("*", "/", "%"):
                                return 1
                            if op in ("+", "-"):
                                return 2
                            if op in ("<<", ">>"):
                                return 3
                            if op in ("<", "<=", ">", ">="):
                                return 4
                            if op in ("==", "!="):
                                return 5
                            if op == "&":
                                return 6
                            if op == "^":
                                return 7
                            if op == "|":
                                return 8
                            if op == "&&":
                                return 9
                            if op == "||":
                                return 10
                            return 11  # assignment, comma etc

                        parent_prec = get_precedence_group(op_spelling)
                        if parent_prec < 11 and op_spelling not in (
                            "&&",
                            "||",
                        ):  # logical operators usually exempt from strict parens in practice, but MISRA is strict. Let's strictly check groups.
                            for child_expr in (lhs, rhs):
                                # If child is an unexposed expr or something, drill down
                                inner = child_expr
                                while inner and inner.kind in (
                                    CursorKind.UNEXPOSED_EXPR,
                                    CursorKind.CSTYLE_CAST_EXPR,
                                    CursorKind.CXX_STATIC_CAST_EXPR,
                                ):
                                    cc = list(inner.get_children())
                                    if not cc:
                                        break
                                    inner = cc[-1]  # Usually the actual expr

                                if (
                                    inner
                                    and inner.kind
                                    == CursorKind.BINARY_OPERATOR
                                ):
                                    # Child is unparenthesized binary operator
                                    inner_op = ""
                                    inner_children = list(inner.get_children())
                                    if len(inner_children) >= 2:
                                        for t in inner.get_tokens():
                                            if (
                                                t.extent.start.offset
                                                >= inner_children[
                                                    0
                                                ].extent.end.offset
                                                and t.extent.end.offset
                                                <= inner_children[
                                                    1
                                                ].extent.start.offset
                                            ):
                                                inner_op = t.spelling
                                                if inner_op.strip():
                                                    break
                                    if inner_op:
                                        child_prec = get_precedence_group(
                                            inner_op
                                        )
                                        # If parent and child are not same precedence group, requires parens
                                        if parent_prec != child_prec:
                                            violations.append(
                                                Violation(
                                                    "Rule 12.1",
                                                    f"The precedence of operators within expressions should be made explicit. Mixed '{op_spelling}' and '{inner_op}'.",
                                                    file_path,
                                                    node.location.line,
                                                    trigger=_cursor_text(node),
                                                )
                                            )

                        # Rule 12.2: Right operand of shift must be < bit width of lhs essential type
                        if op_spelling in ("<<", ">>"):
                            lhs_type = lhs.type.get_canonical()
                            bit_width = lhs_type.get_size() * 8
                            if bit_width > 0:
                                # Look for integer literal directly
                                inner_rhs = rhs
                                while inner_rhs and inner_rhs.kind in (
                                    CursorKind.UNEXPOSED_EXPR,
                                    CursorKind.CSTYLE_CAST_EXPR,
                                    CursorKind.CXX_STATIC_CAST_EXPR,
                                ):
                                    cc = list(inner_rhs.get_children())
                                    if not cc:
                                        break
                                    inner_rhs = cc[-1]

                                if (
                                    inner_rhs
                                    and inner_rhs.kind
                                    == CursorKind.INTEGER_LITERAL
                                ):
                                    toks = list(inner_rhs.get_tokens())
                                    if toks:
                                        try:
                                            # handle hex/octal
                                            val_str = toks[0].spelling.lower()
                                            val_str = val_str.replace(
                                                "u", ""
                                            ).replace("l", "")
                                            base = 10
                                            if val_str.startswith("0x"):
                                                base = 16
                                            elif val_str.startswith("0b"):
                                                base = 2
                                            elif (
                                                val_str.startswith("0")
                                                and len(val_str) > 1
                                            ):
                                                base = 8
                                            shift_val = int(val_str, base)
                                            if (
                                                shift_val >= bit_width
                                                or shift_val < 0
                                            ):
                                                violations.append(
                                                    Violation(
                                                        "Rule 12.2",
                                                        f"The right hand operand of a shift operator ({shift_val}) shall lie in the range zero to one less than the width ({bit_width}).",
                                                        file_path,
                                                        node.location.line,
                                                        trigger=_cursor_text(
                                                            inner_rhs
                                                        ),
                                                    )
                                                )
                                        except ValueError:
                                            pass

                        # Rule 12.3: The comma operator should not be used
                        if op_spelling == ",":
                            # Strong FP guard: only report when the comma operator token
                            # originates from the current source file (not macro expansion
                            # internals in system headers).
                            if _has_operator_token_in_current_file(
                                node, {","}
                            ):
                                # Ignore macro-expansion artifacts where libclang reports a comma
                                # operator but there is no comma in the original source span.
                                span_text = _source_span_text(node)
                                if "," in span_text:
                                    trigger_text = _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 12.3",
                                            "The comma operator should not be used.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                    if is_cpp_file:
                                        violations.append(
                                            Violation(
                                                "Rule 5-2-11",
                                                "The comma operator shall not be used.",
                                                file_path,
                                                node.location.line,
                                                trigger=trigger_text,
                                            )
                                        )

                        # Rule 12.4: Constant expressions unsigned wrap-around
                        # A very basic check: addition/multiplication of two explicit unsigned literals that exceeds max value.
                        if op_spelling in ("+", "*", "<<"):
                            lhs_type = lhs.type.get_canonical()
                            if lhs_type.kind in (
                                TypeKind.UINT,
                                TypeKind.ULONG,
                                TypeKind.ULONGLONG,
                                TypeKind.UCHAR,
                                TypeKind.USHORT,
                            ):
                                bit_width = lhs_type.get_size() * 8
                                if bit_width > 0:
                                    max_val = (1 << bit_width) - 1

                                    def get_literal_val(n):
                                        while n and n.kind in (
                                            CursorKind.UNEXPOSED_EXPR,
                                            CursorKind.CSTYLE_CAST_EXPR,
                                            CursorKind.CXX_STATIC_CAST_EXPR,
                                            CursorKind.PAREN_EXPR,
                                        ):
                                            c = list(n.get_children())
                                            if not c:
                                                break
                                            n = c[-1]
                                        if (
                                            n
                                            and n.kind
                                            == CursorKind.INTEGER_LITERAL
                                        ):
                                            ts = list(n.get_tokens())
                                            if ts:
                                                try:
                                                    vs = (
                                                        ts[0]
                                                        .spelling.lower()
                                                        .replace("u", "")
                                                        .replace("l", "")
                                                    )
                                                    base = (
                                                        16
                                                        if vs.startswith("0x")
                                                        else (
                                                            8
                                                            if vs.startswith(
                                                                "0"
                                                            )
                                                            and len(vs) > 1
                                                            else 10
                                                        )
                                                    )
                                                    return int(vs, base)
                                                except ValueError:
                                                    pass
                                        return None

                                    l_val = get_literal_val(lhs)
                                    r_val = get_literal_val(rhs)
                                    if l_val is not None and r_val is not None:
                                        res = 0
                                        if op_spelling == "+":
                                            res = l_val + r_val
                                        elif op_spelling == "*":
                                            res = l_val * r_val
                                        elif op_spelling == "<<":
                                            res = l_val << r_val
                                        if res > max_val:
                                            violations.append(
                                                Violation(
                                                    "Rule 12.4",
                                                    f"Evaluation of constant expressions should not lead to unsigned integer wrap-around (result {res} > max {max_val}).",
                                                    file_path,
                                                    node.location.line,
                                                    trigger=_cursor_text(node),
                                                )
                                            )

            # Chapter 13 Side Effects
            if node.kind == CursorKind.INIT_LIST_EXPR:
                # Rule 13.1: Initializer lists shall not contain persistent side effects
                for init_child in node.get_children():
                    if has_side_effect(init_child):
                        violations.append(
                            Violation(
                                "Rule 13.1",
                                "Initializer lists shall not contain persistent side effects",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(init_child),
                            )
                        )
                        break  # Only report once per init list

            if node.kind in (
                CursorKind.IF_STMT,
                CursorKind.FOR_STMT,
                CursorKind.WHILE_STMT,
                CursorKind.DO_STMT,
            ):
                # Typically conditional statements evaluation. Rule 13.4 assignment in conditional?
                # Actually, Rule 13.4 says "The result of an assignment operator should not be used" - so any assignment used as an expression.
                pass

            if node.kind == CursorKind.BINARY_OPERATOR:
                children = list(node.get_children())
                if len(children) >= 2:
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break
                    if op_spelling:
                        # Rule 13.2: Value of expression and its side effects shall be the same under all permitted evaluation orders
                        # Naive check: assigning a variable that is also incremented/decremented (e.g. a = a++)
                        if op_spelling == "=":
                            lhs_v = lhs
                            while lhs_v and lhs_v.kind in (
                                CursorKind.UNEXPOSED_EXPR,
                                CursorKind.PAREN_EXPR,
                            ):
                                cc = list(lhs_v.get_children())
                                if cc:
                                    lhs_v = cc[-1]
                                else:
                                    break
                            if (
                                lhs_v
                                and lhs_v.kind == CursorKind.DECL_REF_EXPR
                                and lhs_v.referenced
                            ):
                                target_hash = lhs_v.referenced.hash

                                # Search rhs for mutation of target_hash
                                def mutates_target(n, t_hash):
                                    if n.kind == CursorKind.UNARY_OPERATOR:
                                        ops = [
                                            t.spelling for t in n.get_tokens()
                                        ]
                                        if "++" in ops or "--" in ops:
                                            c = list(n.get_children())
                                            if (
                                                c
                                                and c[0].kind
                                                == CursorKind.DECL_REF_EXPR
                                                and c[0].referenced
                                                and c[0].referenced.hash
                                                == t_hash
                                            ):
                                                return True
                                    for child in n.get_children():
                                        if mutates_target(child, t_hash):
                                            return True
                                    return False

                                if mutates_target(rhs, target_hash):
                                    violations.append(
                                        Violation(
                                            "Rule 13.2",
                                            "The value of an expression and its persistent side effects shall be the same under all permitted evaluation orders",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                                    if is_cpp_file:
                                        violations.append(
                                            Violation(
                                                "Rule 5-0-2",
                                                "Reliance on C++ evaluation order constraints should not occur.",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(node),
                                            )
                                        )
                                        violations.append(
                                            Violation(
                                                "Rule 0-1-7",
                                                "The value of an expression shall be the same under any order of evaluation that the standard permits.",
                                                file_path,
                                                node.location.line,
                                                detector="cpp-ch0-heuristic",
                                                trigger=_cursor_text(node),
                                            )
                                        )

                        # Rule 13.3: A full expression containing an increment/decrement should have no other potential side effects...
                        # If node is a binary operator (not assignment), and a child has ++/--, it implies mixing side effects with evaluation
                        assign_ops = {
                            "=",
                            "+=",
                            "-=",
                            "*=",
                            "/=",
                            "%=",
                            "&=",
                            "|=",
                            "^=",
                            "<<=",
                            ">>=",
                        }
                        if op_spelling not in assign_ops:
                            # Check if either child has ++/--
                            def has_inc_dec(n):
                                if n.kind == CursorKind.UNARY_OPERATOR:
                                    ops = [t.spelling for t in n.get_tokens()]
                                    if (
                                        "++" in ops or "--" in ops
                                    ) and _has_operator_token_in_current_file(
                                        n, {"++", "--"}
                                    ):
                                        return True
                                for c in n.get_children():
                                    if has_inc_dec(c):
                                        return True
                                return False

                            # If we are part of a larger expression, the parent check handles it.
                            # But MISRA usually frowns on `int b = a++ + 1;` so if left or right has inc/dec, it's a violation.
                            if has_inc_dec(lhs) or has_inc_dec(rhs):
                                # Ignore macro-expansion artifacts where ++/-- is not present
                                # in the original source span.
                                span_text = _source_span_text(node)
                                if ("++" in span_text) or ("--" in span_text):
                                    trigger_text = _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 13.3",
                                            "A full expression containing an increment (++) or decrement (--) operator should have no other potential side effects other than that caused by the increment or decrement operator",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                    if is_cpp_file:
                                        violations.append(
                                            Violation(
                                                "Rule 5-2-10",
                                                "The increment/decrement operators shall not be mixed with other operators in an expression.",
                                                file_path,
                                                node.location.line,
                                                trigger=trigger_text,
                                            )
                                        )

                        # Rule 13.4: The result of an assignment operator should not be used
                        # We are at a BINARY_OPERATOR. If its semantic parent is another expression (not a compound stmt or decl), we flag.
                        # Since we can't easily get parent in libclang without hacking, we pass context or look up tree.
                        # Wait, we can check if it's trapped in a PAREN_EXPR which is a child of IF_STMT, or something similar.
                        # Let's handle 13.4 by checking PAREN_EXPR wrapper in our visitor.

                        # Rule 13.5: The right hand operand of a logical && || operator shall not contain persistent side effects
                        if op_spelling in ("&&", "||"):
                            rhs_tokens = [t.spelling for t in rhs.get_tokens()]
                            rhs_text = "".join(rhs_tokens)
                            has_assignment = bool(
                                re.search(
                                    r"(?<![!<>=])=(?!=)|\+=|-=|\*=|/=|%=|<<=|>>=|&=|\|=|\^=",
                                    rhs_text,
                                )
                            )
                            rhs_has_persistent_side_effect = (
                                ("++" in rhs_tokens)
                                or ("--" in rhs_tokens)
                                or has_assignment
                            )
                            if rhs_has_persistent_side_effect:
                                violations.append(
                                    Violation(
                                        "Rule 13.5",
                                        f"The right hand operand of a logical {op_spelling} operator shall not contain persistent side effects",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(rhs),
                                    )
                                )
                            if is_cpp_file and (
                                not _is_postfix_expression(lhs)
                                or not _is_postfix_expression(rhs)
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 5-2-1",
                                        "Each operand of a logical && or || shall be a postfix-expression.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

            # Rule 13.6: sizeof operand shall not contain expressions with potential side effects.
            if node.kind in (
                CursorKind.UNARY_OPERATOR,
                CursorKind.CXX_UNARY_EXPR,
            ):
                toks = [t.spelling for t in tuple(node.get_tokens())]
                if toks and toks[0] == "sizeof":

                    def has_sizeof_side_effect(n):
                        if n.kind == CursorKind.CALL_EXPR:
                            return True
                        if n.kind == CursorKind.UNARY_OPERATOR:
                            nt = [t.spelling for t in tuple(n.get_tokens())]
                            if "++" in nt or "--" in nt:
                                return True
                        if n.kind == CursorKind.BINARY_OPERATOR:
                            bt = [t.spelling for t in tuple(n.get_tokens())]
                            assign_ops = {
                                "=",
                                "+=",
                                "-=",
                                "*=",
                                "/=",
                                "%=",
                                "<<=",
                                ">>=",
                                "&=",
                                "|=",
                                "^=",
                            }
                            if any(tok in assign_ops for tok in bt):
                                return True
                        for c in n.get_children():
                            if has_sizeof_side_effect(c):
                                return True
                        return False

                    for c in node.get_children():
                        if has_sizeof_side_effect(c):
                            violations.append(
                                Violation(
                                    "Rule 13.6",
                                    "The operand of the sizeof operator shall not contain any expression which has potential side effects.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(c),
                                )
                            )
                            break

            # Rule 13.4 Check: Look for assignment operator inside conditions or other expressions
            # If the current node is a binary operator with an assignment, and it is wrapped in an expression context
            # A simpler way is to check the enclosing statement. But let's look at IF_STMT etc enclosing it.
            if node.kind in (
                CursorKind.IF_STMT,
                CursorKind.WHILE_STMT,
                CursorKind.FOR_STMT,
                CursorKind.DO_STMT,
            ):
                # The condition is the first exposed child usually, or part of it
                # For IF, child 0 is cond
                c_list = list(node.get_children())
                cond = None
                if node.kind == CursorKind.FOR_STMT:
                    # For has init, cond, inc, body. Hard to map securely via index.
                    pass
                elif node.kind == CursorKind.DO_STMT:
                    # In clang AST, do-stmt typically stores body first, condition second.
                    if len(c_list) >= 2:
                        cond = c_list[1]
                    elif c_list:
                        cond = c_list[-1]
                elif c_list:
                    cond = c_list[0]

                if cond:

                    def find_assignment(n):
                        if n.kind == CursorKind.BINARY_OPERATOR:
                            c2 = list(n.get_children())
                            if len(c2) >= 2:
                                lhs2 = c2[0]
                                rhs2 = c2[1]
                                op2 = ""
                                for tok in n.get_tokens():
                                    if (
                                        tok.extent.start.offset
                                        >= lhs2.extent.end.offset
                                        and tok.extent.end.offset
                                        <= rhs2.extent.start.offset
                                    ):
                                        op2 = tok.spelling
                                        if op2.strip():
                                            break
                                if op2 in {
                                    "=",
                                    "+=",
                                    "-=",
                                    "*=",
                                    "/=",
                                    "%=",
                                    "<<=",
                                    ">>=",
                                    "&=",
                                    "|=",
                                    "^=",
                                }:
                                    return True
                        for c in n.get_children():
                            if find_assignment(c):
                                return True
                        return False

                    if find_assignment(cond):
                        violations.append(
                            Violation(
                                "Rule 13.4",
                                "The result of an assignment operator should not be used",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(cond),
                            )
                        )

            # Chapter 14 Control Statement Expressions
            if node.kind in (
                CursorKind.IF_STMT,
                CursorKind.WHILE_STMT,
                CursorKind.DO_STMT,
                CursorKind.FOR_STMT,
            ):
                c_list = list(node.get_children())
                cond_node = None

                if node.kind == CursorKind.FOR_STMT:
                    # Parse FOR_STMT tokens directly to check Rule 14.2 (well-formedness)
                    toks = [t.spelling for t in node.get_tokens()]
                    # tokens: 'for', '(', init, ';', cond, ';', inc, ')', '{', '}'
                    if toks and toks[0] == "for":
                        try:
                            start_paren = toks.index("(")
                            paren_count = 1
                            end_paren = -1
                            for i in range(start_paren + 1, len(toks)):
                                if toks[i] == "(":
                                    paren_count += 1
                                elif toks[i] == ")":
                                    paren_count -= 1
                                    if paren_count == 0:
                                        end_paren = i
                                        break
                            if end_paren != -1:
                                inside = toks[start_paren + 1 : end_paren]
                                semis = [
                                    i for i, t in enumerate(inside) if t == ";"
                                ]
                                if len(semis) == 2:
                                    s1, s2 = semis[0], semis[1]
                                    clause1 = inside[:s1]
                                    clause2 = inside[s1 + 1 : s2]
                                    clause3 = inside[s2 + 1 :]

                                    # Rule 14.2: A for loop shall be well-formed (clauses must not be empty)
                                    if (
                                        not clause1
                                        or not clause2
                                        or not clause3
                                    ):
                                        violations.append(
                                            Violation(
                                                "Rule 14.2",
                                                "A for loop shall be well-formed (has empty clauses)",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(node),
                                            )
                                        )
                                    if is_cpp_file:
                                        keywords = {
                                            "int",
                                            "long",
                                            "short",
                                            "signed",
                                            "unsigned",
                                            "char",
                                            "float",
                                            "double",
                                            "bool",
                                            "auto",
                                            "const",
                                            "volatile",
                                            "static",
                                            "register",
                                            "extern",
                                            "mutable",
                                            "typename",
                                            "struct",
                                            "class",
                                            "enum",
                                            "union",
                                        }

                                        def idents(tokens):
                                            out = []
                                            for tk in tokens:
                                                if (
                                                    re.match(
                                                        r"^[A-Za-z_]\w*$", tk
                                                    )
                                                    and tk not in keywords
                                                ):
                                                    out.append(tk)
                                            return out

                                        def mods_of_var(tokens, name):
                                            txt = " ".join(tokens)
                                            patterns = [
                                                rf"\b{name}\s*\+\+",
                                                rf"\+\+\s*\b{name}\b",
                                                rf"\b{name}\s*--",
                                                rf"--\s*\b{name}\b",
                                                rf"\b{name}\s*[\+\-\*/%&\|\^]?=",
                                            ]
                                            return any(
                                                re.search(p, txt)
                                                for p in patterns
                                            )

                                        loop_counter_candidates = idents(
                                            clause1
                                        )
                                        unique_counters = list(
                                            dict.fromkeys(
                                                loop_counter_candidates
                                            )
                                        )

                                        # Rule 6-5-1
                                        if len(unique_counters) != 1:
                                            violations.append(
                                                Violation(
                                                    "Rule 6-5-1",
                                                    "A for loop shall contain a single loop-counter.",
                                                    file_path,
                                                    node.location.line,
                                                    trigger=_cursor_text(node),
                                                )
                                            )
                                        loop_counter = (
                                            unique_counters[0]
                                            if unique_counters
                                            else None
                                        )

                                        if loop_counter:
                                            clause2_txt = " ".join(clause2)
                                            clause3_txt = " ".join(clause3)
                                            has_pp = bool(
                                                re.search(
                                                    rf"\b{loop_counter}\s*(\+\+|--)",
                                                    clause3_txt,
                                                )
                                                or re.search(
                                                    rf"(\+\+|--)\s*\b{loop_counter}\b",
                                                    clause3_txt,
                                                )
                                            )
                                            plus_minus_eq_const = bool(
                                                re.search(
                                                    rf"\b{loop_counter}\s*(\+=|-=)\s*[0-9]+[uUlL]*\b",
                                                    clause3_txt,
                                                )
                                            )
                                            has_other_mod = bool(
                                                re.search(
                                                    rf"\b{loop_counter}\s*=",
                                                    clause3_txt,
                                                )
                                                and not re.search(
                                                    rf"\b{loop_counter}\s*(\+=|-=)",
                                                    clause3_txt,
                                                )
                                            )

                                            # Rule 6-5-2 / 6-5-4
                                            if (
                                                not has_pp
                                                and not plus_minus_eq_const
                                            ):
                                                violations.append(
                                                    Violation(
                                                        "Rule 6-5-2",
                                                        "If loop-counter is not modified by -- or ++, it shall only be modified by +=n or -=n with compile-time constant n.",
                                                        file_path,
                                                        node.location.line,
                                                        trigger=loop_counter,
                                                    )
                                                )
                                            if has_other_mod or (
                                                not has_pp
                                                and not plus_minus_eq_const
                                            ):
                                                violations.append(
                                                    Violation(
                                                        "Rule 6-5-4",
                                                        "The loop-counter shall be modified only by --, ++, -=n, or +=n.",
                                                        file_path,
                                                        node.location.line,
                                                        trigger=loop_counter,
                                                    )
                                                )

                                            # Rule 6-5-3
                                            if mods_of_var(
                                                clause2, loop_counter
                                            ):
                                                violations.append(
                                                    Violation(
                                                        "Rule 6-5-3",
                                                        "The loop-counter shall not be modified within the condition.",
                                                        file_path,
                                                        node.location.line,
                                                        trigger=loop_counter,
                                                    )
                                                )

                        except ValueError:
                            pass

                    # For Rule 14.1, finding the increment clause AST nodes dynamically is hard in Clang Python binding,
                    # but we can look for all DECL_REF_EXPRs in the FOR statement and see if any are floating and mutated
                    # Wait, 14.1 says "A loop counter shall not have essentially floating type".
                    # We can just check the first variable declaration or any binary assignment in the for loop scope.
                    if c_list:
                        # Find all variables assigned to in the for statement header
                        def find_assigned_floats(n):
                            if n.kind == CursorKind.VAR_DECL:
                                t = n.type.get_canonical()
                                if t.kind in (
                                    TypeKind.FLOAT,
                                    TypeKind.DOUBLE,
                                    TypeKind.LONGDOUBLE,
                                ):
                                    return True
                            if n.kind == CursorKind.BINARY_OPERATOR:
                                ops = [
                                    t.spelling for t in tuple(n.get_tokens())
                                ]
                                for assign_op in ("=", "+=", "-=", "*=", "/="):
                                    if assign_op in ops:
                                        cc = list(n.get_children())
                                        if cc and cc[
                                            0
                                        ].type.get_canonical().kind in (
                                            TypeKind.FLOAT,
                                            TypeKind.DOUBLE,
                                            TypeKind.LONGDOUBLE,
                                        ):
                                            return True
                            for c in n.get_children():
                                if (
                                    c.kind != CursorKind.COMPOUND_STMT
                                    and find_assigned_floats(c)
                                ):
                                    return True
                            return False

                        # We only check children that are NOT the compound statement body
                        header_nodes = [
                            c
                            for c in c_list
                            if c.kind != CursorKind.COMPOUND_STMT
                        ]
                        for c in header_nodes:
                            if find_assigned_floats(c):
                                violations.append(
                                    Violation(
                                        "Rule 14.1",
                                        "A loop counter shall not have essentially floating type",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(c),
                                    )
                                )
                                break

                    # For finding condition node inside FOR_STMT, libclang Python binds them roughly in order
                    # Init, Cond (often has BinaryOperator <), Inc, Body. Let's look for a node that is NOT a decl and NOT a compound stmt and NOT an expression with an assignment
                    # A better way is checking all header expressions for boolean compatibility.

                # Determine control expression node:
                if node.kind in (CursorKind.IF_STMT, CursorKind.WHILE_STMT):
                    if c_list:
                        cond_node = c_list[0]
                elif node.kind == CursorKind.DO_STMT:
                    # Do statements usually have body then condition
                    if len(c_list) >= 2:
                        cond_node = c_list[1]
                elif node.kind == CursorKind.FOR_STMT:
                    # Roughly try to find it: it's usually the BinaryOperator that doesn't have an assignment
                    header_nodes = [
                        c
                        for c in c_list
                        if c.kind != CursorKind.COMPOUND_STMT
                        and c.kind != CursorKind.DECL_STMT
                    ]
                    for hn in header_nodes:
                        if hn.kind == CursorKind.BINARY_OPERATOR:
                            toks = [t.spelling for t in hn.get_tokens()]
                            if (
                                "=" not in toks
                                and "+=" not in toks
                                and "-=" not in toks
                            ):
                                cond_node = hn
                                break

                if cond_node:
                    # Rule 14.3: Controlling expressions shall not be invariant
                    if is_invariant_literal(cond_node):
                        violations.append(
                            Violation(
                                "Rule 14.3",
                                "Controlling expressions shall not be invariant",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(cond_node),
                            )
                        )
                        lhs_orig = None
                        rhs_orig = None
                        if is_cpp_file:
                            violations.append(
                                Violation(
                                    "Rule 0-1-2",
                                    "A project shall not contain infeasible paths.",
                                    file_path,
                                    node.location.line,
                                    detector="cpp-ch0-heuristic",
                                    trigger=_cursor_text(cond_node),
                                )
                            )

                    # Rule 14.4: The controlling expression shall have essentially Boolean type
                    if not (
                        is_essentially_boolean(cond_node)
                        or has_explicit_bool_type(cond_node)
                    ):
                        violations.append(
                            Violation(
                                "Rule 14.4",
                                "The controlling expression of an if statement and the controlling expression of an iteration-statement shall have essentially Boolean type",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(cond_node),
                            )
                        )
                        if is_cpp_file:
                            violations.append(
                                Violation(
                                    "Rule 5-0-13",
                                    "The condition of an if-statement and the condition of an iteration-statement shall have type bool.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(cond_node),
                                )
                            )
                    elif is_cpp_file:
                        if not has_explicit_bool_type(cond_node):
                            # In C++ profile, require explicit bool type even if expression is
                            # contextually convertible to bool.
                            violations.append(
                                Violation(
                                    "Rule 5-0-13",
                                    "The condition of an if-statement and the condition of an iteration-statement shall have type bool.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(cond_node),
                                )
                            )

            # Rule 17.6: The declaration of an array parameter shall not contain the static keyword between the [ ]
            if node.kind == CursorKind.PARM_DECL:
                toks = [t.spelling for t in node.get_tokens()]
                if "[" in toks and "]" in toks and "static" in toks:
                    for i, t in enumerate(toks):
                        if t == "[":
                            sub = toks[i + 1 :]
                            if "static" in sub and sub.index(
                                "static"
                            ) < sub.index("]"):
                                violations.append(
                                    Violation(
                                        "Rule 17.6",
                                        "The declaration of an array parameter shall not contain the static keyword between the [ ]",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                                break

            # Rule 8.13: Track parameter mutations
            if current_func and node.kind == CursorKind.BINARY_OPERATOR:
                tokens = list(node.get_tokens())
                if tokens:
                    op = ""
                    for (
                        c
                    ) in node.get_children():  # Find operator by skipping LHS
                        # Naive operator extraction via tokens mapped to children is tricky,
                        # but we can look at the raw tokens string
                        pass
                    tok_strs = [t.spelling for t in tuple(node.get_tokens())]
                    is_assign = False
                    for assign_op in (
                        "=",
                        "+=",
                        "-=",
                        "*=",
                        "/=",
                        "%=",
                        "&=",
                        "|=",
                        "^=",
                        "<<=",
                        ">>=",
                    ):
                        if assign_op in tok_strs:
                            is_assign = True
                            break
                    if is_assign:
                        children = list(node.get_children())
                        if children:
                            lhs = children[0]
                            # For 8.13 we conservatively treat any pointer-parameter
                            # referenced on the assignment LHS as potentially mutated.
                            # This avoids missing patterns wrapped in UNEXPOSED_EXPR.
                            for sub in lhs.walk_preorder():
                                if (
                                    sub.kind == CursorKind.DECL_REF_EXPR
                                    and sub.referenced
                                ):
                                    _mark_ptr_param_mutated(
                                        current_func, sub.referenced
                                    )
                                    if (
                                        sub.spelling
                                        in func_ptr_param_names.get(
                                            current_func, set()
                                        )
                                    ):
                                        _mark_ptr_param_mutated_by_name(
                                            current_func, sub.spelling
                                        )

            if current_func and node.kind == CursorKind.CALL_EXPR:
                if is_cpp_file:
                    called_name = get_call_name(node)
                    if called_name:
                        cpp_called_functions.add(called_name)
                    call_children = list(node.get_children())
                    for arg in call_children[1:]:
                        referenced_name = _get_referenced_function_name(arg)
                        if referenced_name:
                            cpp_called_functions.add(referenced_name)

                # Rule 17.3 is primarily handled via clang diagnostics and fallback source
                # scans. Avoid AST-only heuristics here because they produce many false
                # positives for macro/function-pointer heavy C code.

                # Rule 17.7: The value returned by a function having non-void return type shall be used
                # In Clang Python bindings, if a CALL_EXPR's immediate context is just evaluating it (like inside a COMPOUND_STMT), the return is ignored.
                # However we don't have direct access to 'parent'. But we can check if it's explicitly cast to (void).
                if node.type and node.type.kind != TypeKind.VOID:
                    # Look ahead/behind: if it's wrapped in a C-style cast to void, it's allowed.
                    # Wait, we can't easily see parent here. We will do this via a post-processing check or by seeing if it's the top-level of an Expression Statement.
                    pass  # We will handle 17.7 in post-processing when traversing compound statements

                if is_cpp_file:
                    known_error_funcs = {
                        "fopen",
                        "freopen",
                        "open",
                        "read",
                        "write",
                        "fread",
                        "fwrite",
                        "fgets",
                        "malloc",
                        "calloc",
                        "realloc",
                        "strtol",
                        "strtoul",
                        "strtod",
                    }
                    call_name = get_call_name(node)
                    parent = getattr(node, "lexical_parent", None) or getattr(
                        node, "semantic_parent", None
                    )
                    if (
                        call_name in known_error_funcs
                        and node.type
                        and node.type.kind != TypeKind.VOID
                    ):
                        parent_kind = parent.kind if parent else None
                        if parent_kind not in (
                            CursorKind.VAR_DECL,
                            CursorKind.BINARY_OPERATOR,
                            CursorKind.RETURN_STMT,
                            CursorKind.CSTYLE_CAST_EXPR,
                            CursorKind.CXX_STATIC_CAST_EXPR,
                            CursorKind.CXX_REINTERPRET_CAST_EXPR,
                            CursorKind.CXX_CONST_CAST_EXPR,
                        ):
                            cpp_known_error_calls_ignored.append(
                                (node.location.line, call_name)
                            )

                # If param is passed to another function, assume mutated for safety, as we don't do deep data flow.
                for i, arg in enumerate(node.get_arguments()):
                    if arg.kind == CursorKind.UNEXPOSED_EXPR:
                        for sub in arg.walk_preorder():
                            if (
                                sub.kind == CursorKind.DECL_REF_EXPR
                                and sub.referenced
                            ):
                                _mark_ptr_param_mutated(
                                    current_func, sub.referenced
                                )
                                if sub.spelling in func_ptr_param_names.get(
                                    current_func, set()
                                ):
                                    _mark_ptr_param_mutated_by_name(
                                        current_func, sub.spelling
                                    )
                    elif (
                        arg.kind == CursorKind.DECL_REF_EXPR and arg.referenced
                    ):
                        _mark_ptr_param_mutated(current_func, arg.referenced)
                        if arg.spelling in func_ptr_param_names.get(
                            current_func, set()
                        ):
                            _mark_ptr_param_mutated_by_name(
                                current_func, arg.spelling
                            )

                # Rule 17.5: The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements
                target_decl = node.referenced
                if (
                    target_decl
                    and target_decl.kind == CursorKind.FUNCTION_DECL
                ):
                    args = list(node.get_arguments())
                    params = list(target_decl.get_arguments())
                    for i, (arg, param) in enumerate(zip(args, params)):
                        # Look for ArrayType on param
                        p_types = [t.spelling for t in param.get_tokens()]
                        if "[" in p_types and "]" in p_types:
                            # It's an array parameter. Get its size if possible.
                            p_type = param.type
                            if p_type.kind == TypeKind.CONSTANTARRAY:
                                p_size = p_type.element_count
                                a_type = _get_original_type(arg)
                                if (
                                    a_type
                                    and a_type.kind == TypeKind.CONSTANTARRAY
                                ):
                                    a_size = a_type.element_count
                                    if a_size < p_size:
                                        violations.append(
                                            Violation(
                                                "Rule 17.5",
                                                f"The function argument corresponding to a parameter declared to have an array type shall have an appropriate number of elements (arg {a_size} < param {p_size})",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(arg),
                                            )
                                        )
                        # C++ Rule 5-2-12: array argument identifier shall not decay to pointer.
                        if is_cpp_file:
                            a_under = unwrap_expr(arg)
                            p_type = param.type.get_canonical()
                            if (
                                a_under
                                and a_under.kind == CursorKind.DECL_REF_EXPR
                                and a_under.type.kind
                                in (
                                    TypeKind.CONSTANTARRAY,
                                    TypeKind.INCOMPLETEARRAY,
                                )
                            ):
                                if p_type.kind == TypeKind.POINTER:
                                    violations.append(
                                        Violation(
                                            "Rule 5-2-12",
                                            "An identifier with array type passed as a function argument shall not decay to a pointer.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(arg),
                                        )
                                    )

                # Chapter 21: Standard Libraries
                func_name = node.spelling
                if not func_name and node.referenced:
                    func_name = node.referenced.spelling
                if not func_name:
                    func_name = get_call_name(node)

                # Rule 19.1 (heuristic): obvious overlapping copy calls.
                if func_name in ("memcpy", "memmove", "operator="):
                    call_args = list(node.get_arguments())
                    if len(call_args) >= 2:

                        def base_decl(expr):
                            e = unwrap_expr(expr)
                            while e and e.kind in (
                                CursorKind.UNEXPOSED_EXPR,
                                CursorKind.PAREN_EXPR,
                                CursorKind.CSTYLE_CAST_EXPR,
                                CursorKind.UNARY_OPERATOR,
                                CursorKind.ARRAY_SUBSCRIPT_EXPR,
                                CursorKind.MEMBER_REF_EXPR,
                            ):
                                if e.kind == CursorKind.UNARY_OPERATOR:
                                    toks = [
                                        t.spelling
                                        for t in tuple(e.get_tokens())
                                    ]
                                    if "&" in toks:
                                        children = list(e.get_children())
                                        e = children[0] if children else None
                                    else:
                                        children = list(e.get_children())
                                        e = children[0] if children else None
                                else:
                                    children = list(e.get_children())
                                    e = children[0] if children else None
                            if (
                                e
                                and e.kind == CursorKind.DECL_REF_EXPR
                                and e.referenced
                            ):
                                return e.referenced
                            return None

                        dst = base_decl(call_args[0])
                        src = base_decl(call_args[1])
                        if dst and src and dst.hash == src.hash:
                            violations.append(
                                Violation(
                                    "Rule 19.1",
                                    "An object shall not be assigned or copied to an overlapping object",
                                    file_path,
                                    node.location.line,
                                    trigger=func_name,
                                )
                            )

                if func_name:
                    args = list(node.get_arguments())

                    # Chapter 22 resource rules (heuristic)
                    if func_name == "free":
                        if args:
                            arg_expr = unwrap_expr(args[0])
                            arg_hash = get_decl_ref_hash(args[0])
                            arg_decl = get_decl_ref_cursor(args[0])
                            declared_via_alloc = False
                            if arg_decl:
                                decl_candidates = [arg_decl]
                                try:
                                    if arg_decl.canonical:
                                        decl_candidates.append(
                                            arg_decl.canonical
                                        )
                                except Exception:
                                    pass
                                for decl in decl_candidates:
                                    if (
                                        not decl
                                        or decl.kind != CursorKind.VAR_DECL
                                    ):
                                        continue
                                    for c in decl.get_children():
                                        check = unwrap_expr(c)
                                        if (
                                            check
                                            and check.kind
                                            == CursorKind.CALL_EXPR
                                        ):
                                            call_name = get_call_name(check)
                                            if call_name in (
                                                "malloc",
                                                "calloc",
                                                "realloc",
                                            ):
                                                declared_via_alloc = True
                                                break
                                    if declared_via_alloc:
                                        break
                                    try:
                                        decl_toks = [
                                            t.spelling
                                            for t in decl.get_tokens()
                                        ]
                                        if any(
                                            tok
                                            in ("malloc", "calloc", "realloc")
                                            for tok in decl_toks
                                        ):
                                            declared_via_alloc = True
                                            break
                                    except Exception:
                                        pass
                            if arg_hash is not None:
                                if (
                                    arg_hash in alloc_resources
                                    and alloc_resources[arg_hash].get("kind")
                                    == "heap"
                                ) or declared_via_alloc:
                                    freed_heap.add(arg_hash)
                                else:
                                    # Conservative 22.2 detection: only report obvious misuse.
                                    obvious_bad_free = False
                                    if (
                                        arg_expr
                                        and arg_expr.kind
                                        == CursorKind.UNARY_OPERATOR
                                    ):
                                        toks = [
                                            t.spelling
                                            for t in arg_expr.get_tokens()
                                        ]
                                        if "&" in toks:
                                            obvious_bad_free = True
                                    if arg_decl and getattr(
                                        arg_decl, "type", None
                                    ):
                                        try:
                                            if (
                                                arg_decl.type.get_canonical().kind
                                                != TypeKind.POINTER
                                            ):
                                                obvious_bad_free = True
                                        except Exception:
                                            pass
                                    if obvious_bad_free:
                                        violations.append(
                                            Violation(
                                                "Rule 22.2",
                                                "A block of memory shall only be freed if it was allocated by means of a Standard Library function.",
                                                file_path,
                                                node.location.line,
                                                trigger=func_name,
                                            )
                                        )
                    elif func_name == "fclose":
                        if args:
                            file_hash = get_decl_ref_hash(args[0])
                            if file_hash is not None:
                                closed_files.add(file_hash)

                    # Rule 22.6 / 22.4 stream usage checks
                    stream_arg_idx = None
                    write_funcs = {
                        "fprintf",
                        "fputs",
                        "fputc",
                        "fwrite",
                        "putc",
                        "putwc",
                    }
                    stream_arg_pos = {
                        "fprintf": 0,
                        "fputs": 1,
                        "fputc": 1,
                        "fwrite": 3,
                        "putc": 1,
                        "putwc": 1,
                        "fread": 3,
                        "fgetc": 0,
                        "fgets": 2,
                    }
                    if func_name in stream_arg_pos:
                        stream_arg_idx = stream_arg_pos[func_name]

                    if stream_arg_idx is not None and stream_arg_idx < len(
                        args
                    ):
                        stream_hash = get_decl_ref_hash(args[stream_arg_idx])
                        if stream_hash is not None:
                            if (
                                stream_hash in closed_files
                                and func_name != "fclose"
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 22.6",
                                        "The value of a pointer to a FILE shall not be used after the associated stream has been closed.",
                                        file_path,
                                        node.location.line,
                                        trigger=func_name,
                                    )
                                )
                            if func_name in write_funcs:
                                mode = file_modes.get(stream_hash, "")
                                if is_read_only_mode(mode):
                                    violations.append(
                                        Violation(
                                            "Rule 22.4",
                                            "There shall be no attempt to write to a stream which has been opened as read-only.",
                                            file_path,
                                            node.location.line,
                                            trigger=func_name,
                                        )
                                    )

                    if func_name in ("atof", "atoi", "atol", "atoll"):
                        violations.append(
                            Violation(
                                "Rule 21.7",
                                f"The {func_name} function of <stdlib.h> shall not be used",
                                file_path,
                                node.location.line,
                                trigger=func_name,
                            )
                        )
                    elif func_name in ("abort", "exit", "getenv", "system"):
                        violations.append(
                            Violation(
                                "Rule 21.8",
                                f"The library function {func_name} of <stdlib.h> shall not be used",
                                file_path,
                                node.location.line,
                                trigger=func_name,
                            )
                        )
                    elif func_name in ("bsearch", "qsort"):
                        violations.append(
                            Violation(
                                "Rule 21.9",
                                f"The library function {func_name} of <stdlib.h> shall not be used",
                                file_path,
                                node.location.line,
                                trigger=func_name,
                            )
                        )
                    elif func_name in (
                        "asctime",
                        "clock",
                        "ctime",
                        "difftime",
                        "gmtime",
                        "localtime",
                        "mktime",
                        "time",
                        "strftime",
                    ):
                        violations.append(
                            Violation(
                                "Rule 21.10",
                                "The Standard Library time and date functions shall not be used",
                                file_path,
                                node.location.line,
                                trigger=func_name,
                            )
                        )
                    elif is_cpp_file and func_name in (
                        "strcpy",
                        "strcat",
                        "strncpy",
                        "strncat",
                        "gets",
                    ):
                        violations.append(
                            Violation(
                                "Rule 18-0-5",
                                "The unbounded string handling functions of <cstring> shall not be used.",
                                file_path,
                                node.location.line,
                                trigger=func_name,
                            )
                        )

            # Rule 22.5: A pointer to a FILE object shall not be dereferenced
            if node.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
                children = list(node.get_children())
                if children:
                    base_type = children[0].type.get_canonical()
                    if (
                        base_type.spelling in ("struct _IO_FILE *", "FILE *")
                        or "FILE" in children[0].type.spelling
                    ):
                        violations.append(
                            Violation(
                                "Rule 22.5",
                                "A pointer to a FILE object shall not be dereferenced",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(children[0]),
                            )
                        )

            # Rule 10.1: Operands shall not be of an inappropriate essential type
            if node.kind in (
                CursorKind.BINARY_OPERATOR,
                CursorKind.UNARY_OPERATOR,
            ):
                toks = list(node.get_tokens())
                if toks:
                    op_str = (
                        toks[0].spelling
                        if node.kind == CursorKind.UNARY_OPERATOR
                        else None
                    )
                    # For binary ops, extracting the operator precisely from tokens when sides have tokens is hard,
                    # but we can look for specific operators.
                    children = list(node.get_children())

                    if (
                        node.kind == CursorKind.UNARY_OPERATOR
                        and len(children) == 1
                    ):
                        child_type = children[0].type.get_canonical()
                        if is_cpp_file and op_str in (
                            "+",
                            "-",
                            "~",
                            "++",
                            "--",
                        ):
                            if child_type.kind == TypeKind.BOOL:
                                violations.append(
                                    Violation(
                                        "Rule 4-5-1",
                                        "Expressions with type bool shall not be used as operands to built-in arithmetic/bitwise operators.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            if child_type.kind == TypeKind.ENUM:
                                violations.append(
                                    Violation(
                                        "Rule 4-5-2",
                                        "Expressions with type enum shall not be used as operands to built-in operators other than array subscript.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            if child_type.kind in (
                                TypeKind.CHAR_S,
                                TypeKind.SCHAR,
                                TypeKind.UCHAR,
                                TypeKind.WCHAR,
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 4-5-3",
                                        "Expressions with type plain char/wchar_t shall not be used as operands to built-in operators.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                        if (
                            is_cpp_file
                            and op_str == "-"
                            and child_type.kind
                            in (
                                TypeKind.UINT,
                                TypeKind.ULONG,
                                TypeKind.ULONGLONG,
                                TypeKind.UCHAR,
                                TypeKind.USHORT,
                            )
                        ):
                            violations.append(
                                Violation(
                                    "Rule 5-3-2",
                                    "The unary minus operator shall not be applied to an expression whose underlying type is unsigned.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        # Bitwise NOT (~) should only apply to unsigned
                        if op_str == "~" and child_type.kind not in (
                            TypeKind.UINT,
                            TypeKind.ULONG,
                            TypeKind.ULONGLONG,
                            TypeKind.UCHAR,
                            TypeKind.USHORT,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 10.1",
                                    "Bitwise NOT (~) operator applied to an inappropriate essential type (should be unsigned).",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        # Rule 18.4
                        if (
                            op_str in ("++", "--")
                            and child_type.kind == TypeKind.POINTER
                        ):
                            violations.append(
                                Violation(
                                    "Rule 18.4",
                                    "The +, -, += and -= operators should not be applied to an expression of pointer type",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        # Rule 22.5
                        if op_str == "*" and (
                            child_type.spelling
                            in ("struct _IO_FILE *", "FILE *")
                            or "FILE" in children[0].type.spelling
                        ):
                            violations.append(
                                Violation(
                                    "Rule 22.5",
                                    "A pointer to a FILE object shall not be dereferenced",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        # Logical NOT (!) should ideally apply to boolean
                        if (
                            is_cpp_file
                            and op_str == "!"
                            and not (
                                has_explicit_bool_type(children[0])
                                or is_essentially_boolean(children[0])
                            )
                        ):
                            violations.append(
                                Violation(
                                    "Rule 5-3-1",
                                    "Each operand of the ! operator, the logical &&, or || shall have type bool.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )

                    elif (
                        node.kind == CursorKind.BINARY_OPERATOR
                        and len(children) >= 2
                    ):
                        lhs = children[0]
                        rhs = children[1]

                        op_spelling = ""
                        for t in toks:
                            if (
                                t.extent.start.offset >= lhs.extent.end.offset
                                and t.extent.end.offset
                                <= rhs.extent.start.offset
                            ):
                                op_spelling = t.spelling
                                if op_spelling.strip():
                                    break
                        if not op_spelling:
                            for candidate in (
                                "<<",
                                ">>",
                                "<=",
                                ">=",
                                "==",
                                "!=",
                                "&&",
                                "||",
                                "+=",
                                "-=",
                                "*=",
                                "/=",
                                "%=",
                                "&=",
                                "|=",
                                "^=",
                                "+",
                                "-",
                                "*",
                                "/",
                                "%",
                                "&",
                                "|",
                                "^",
                                "<",
                                ">",
                                "=",
                            ):
                                if candidate in toks:
                                    op_spelling = candidate
                                    break
                        if is_cpp_file:
                            lhs_orig = _get_original_type(lhs) or lhs.type
                            rhs_orig = _get_original_type(rhs) or rhs.type
                            lhs_kind = (
                                lhs_orig.get_canonical().kind
                                if lhs_orig
                                else lhs.type.get_canonical().kind
                            )
                            rhs_kind = (
                                rhs_orig.get_canonical().kind
                                if rhs_orig
                                else rhs.type.get_canonical().kind
                            )
                            cpp_disallowed_ops = {
                                "+",
                                "-",
                                "*",
                                "/",
                                "%",
                                "<<",
                                ">>",
                                "&",
                                "|",
                                "^",
                                "<",
                                "<=",
                                ">",
                                ">=",
                            }
                            if op_spelling in cpp_disallowed_ops:
                                if (
                                    lhs_kind == TypeKind.BOOL
                                    or rhs_kind == TypeKind.BOOL
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 4-5-1",
                                            "Expressions with type bool shall not be used as operands to built-in arithmetic/bitwise operators.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                                if (
                                    lhs_kind == TypeKind.ENUM
                                    or rhs_kind == TypeKind.ENUM
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 4-5-2",
                                            "Expressions with type enum shall not be used as operands to built-in operators other than array subscript.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                                if lhs_kind in (
                                    TypeKind.CHAR_S,
                                    TypeKind.SCHAR,
                                    TypeKind.UCHAR,
                                    TypeKind.WCHAR,
                                ) or rhs_kind in (
                                    TypeKind.CHAR_S,
                                    TypeKind.SCHAR,
                                    TypeKind.UCHAR,
                                    TypeKind.WCHAR,
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 4-5-3",
                                            "Expressions with type plain char/wchar_t shall not be used as operands to built-in operators.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                            # Rule 7-2-1: enum values should correspond to enumerators.
                            if op_spelling == "=":
                                lhs_t = (
                                    lhs.type.get_canonical()
                                    if lhs.type
                                    else None
                                )
                                rhs_val = _get_integer_literal_value(rhs)
                                if (
                                    lhs_t
                                    and lhs_t.kind == TypeKind.ENUM
                                    and rhs_val is not None
                                ):
                                    allowed_vals = (
                                        _enum_allowed_values_from_type(lhs_t)
                                    )
                                    if (
                                        allowed_vals
                                        and rhs_val not in allowed_vals
                                    ):
                                        violations.append(
                                            Violation(
                                                "Rule 7-2-1",
                                                "An expression with enum underlying type shall only have values corresponding to the enumerators.",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(rhs),
                                            )
                                        )
                            if "NULL" in [
                                t.spelling for t in toks
                            ] and op_spelling in {
                                "+",
                                "-",
                                "*",
                                "/",
                                "%",
                                "<<",
                                ">>",
                                "&",
                                "|",
                                "^",
                            }:
                                violations.append(
                                    Violation(
                                        "Rule 4-10-1",
                                        "NULL shall not be used as an integer value.",
                                        file_path,
                                        node.location.line,
                                        trigger="NULL",
                                    )
                                )
                        if (
                            is_cpp_file
                            and op_spelling == "="
                            and lhs_orig
                            and rhs_orig
                        ):
                            lhs_k = lhs_orig.get_canonical().kind
                            rhs_k = rhs_orig.get_canonical().kind
                            if _is_integral_kind(lhs_k) and _is_integral_kind(
                                rhs_k
                            ):
                                if _is_unsigned_kind(
                                    lhs_k
                                ) != _is_unsigned_kind(rhs_k):
                                    trigger_text = _cursor_text(
                                        rhs
                                    ) or _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-4",
                                            "An implicit integral conversion shall not change the signedness of the underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-3",
                                            "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                            try:
                                if (
                                    rhs_orig.get_canonical().get_size()
                                    > lhs_orig.get_canonical().get_size()
                                ):
                                    trigger_text = _cursor_text(
                                        rhs
                                    ) or _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-6",
                                            "An implicit conversion to a narrower type shall not occur.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-3",
                                            "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                            except Exception:
                                pass
                            if (
                                _is_integral_kind(lhs_k)
                                and _is_floating_kind(rhs_k)
                            ) or (
                                _is_floating_kind(lhs_k)
                                and _is_integral_kind(rhs_k)
                            ):
                                trigger_text = _cursor_text(
                                    rhs
                                ) or _cursor_text(node)
                                violations.append(
                                    Violation(
                                        "Rule 5-0-5",
                                        "There shall be no implicit conversions between floating-point and integer types.",
                                        file_path,
                                        node.location.line,
                                        trigger=trigger_text,
                                    )
                                )
                                violations.append(
                                    Violation(
                                        "Rule 5-0-3",
                                        "A cvalue expression shall not be implicitly converted to a different underlying type.",
                                        file_path,
                                        node.location.line,
                                        trigger=trigger_text,
                                    )
                                )
                        if (
                            is_cpp_file
                            and op_spelling == "="
                            and _is_function_ref_without_address(rhs)
                        ):
                            violations.append(
                                Violation(
                                    "Rule 8-4-4",
                                    "A function identifier shall either be used to call the function or it shall be preceded by '&'.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(rhs),
                                )
                            )
                        if is_cpp_file and op_spelling == "<<":
                            lhs_unwrapped = unwrap_expr(lhs)
                            lhs_is_cast = (
                                lhs_unwrapped is not None
                                and lhs_unwrapped.kind
                                in (
                                    CursorKind.CSTYLE_CAST_EXPR,
                                    CursorKind.CXX_STATIC_CAST_EXPR,
                                    CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                                )
                            )
                            try:
                                if (
                                    lhs_orig
                                    and lhs_orig.get_canonical().get_size() < 4
                                    and not lhs_is_cast
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-10",
                                            "If bitwise operators ~ and << are applied to a smaller operand, it should be cast to its required underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                            except Exception:
                                pass
                        if is_cpp_file and op_spelling in ("/", "%"):
                            rhs_unwrapped = unwrap_expr(rhs)
                            if (
                                rhs_unwrapped
                                and rhs_unwrapped.kind
                                == CursorKind.INTEGER_LITERAL
                            ):
                                rhs_tokens = list(rhs_unwrapped.get_tokens())
                                if rhs_tokens:
                                    rhs_text = (
                                        rhs_tokens[0]
                                        .spelling.lower()
                                        .replace("u", "")
                                        .replace("l", "")
                                    )
                                    if rhs_text == "0":
                                        violations.append(
                                            Violation(
                                                "Rule 0-1-6",
                                                "A project shall not contain instances of undefined or critical unspecified behavior (division by zero).",
                                                file_path,
                                                node.location.line,
                                                detector="cpp-ch0-heuristic",
                                                trigger=_cursor_text(node),
                                            )
                                        )

                        # Rule 18.2, 18.3, 18.4, 18.6
                        lhs_t = lhs.type.get_canonical()
                        rhs_t = rhs.type.get_canonical()

                        is_ptr_lhs = (
                            lhs_t.kind == TypeKind.POINTER
                            or lhs_t.kind
                            in (
                                TypeKind.INCOMPLETEARRAY,
                                TypeKind.CONSTANTARRAY,
                            )
                        )
                        is_ptr_rhs = (
                            rhs_t.kind == TypeKind.POINTER
                            or rhs_t.kind
                            in (
                                TypeKind.INCOMPLETEARRAY,
                                TypeKind.CONSTANTARRAY,
                            )
                        )

                        def _pointer_base_decl(expr):
                            cur = expr
                            while cur and cur.kind in (
                                CursorKind.UNEXPOSED_EXPR,
                                CursorKind.PAREN_EXPR,
                                CursorKind.CSTYLE_CAST_EXPR,
                            ):
                                c = list(cur.get_children())
                                if not c:
                                    break
                                cur = c[-1]
                            if not cur:
                                return None
                            if (
                                cur.kind == CursorKind.DECL_REF_EXPR
                                and cur.referenced
                            ):
                                return cur.referenced
                            if cur.kind in (
                                CursorKind.ARRAY_SUBSCRIPT_EXPR,
                                CursorKind.MEMBER_REF_EXPR,
                            ):
                                c = list(cur.get_children())
                                return _pointer_base_decl(c[0]) if c else None
                            if cur.kind == CursorKind.UNARY_OPERATOR:
                                c = list(cur.get_children())
                                return _pointer_base_decl(c[0]) if c else None
                            if cur.kind == CursorKind.BINARY_OPERATOR:
                                c = list(cur.get_children())
                                if len(c) >= 2:
                                    b0 = _pointer_base_decl(c[0])
                                    b1 = _pointer_base_decl(c[1])
                                    return b0 or b1
                            return None

                        if op_spelling in ("+", "-", "+=", "-="):
                            if is_ptr_lhs or is_ptr_rhs:
                                violations.append(
                                    Violation(
                                        "Rule 18.4",
                                        "The +, -, += and -= operators should not be applied to an expression of pointer type",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                                if (
                                    op_spelling == "-"
                                    and is_ptr_lhs
                                    and is_ptr_rhs
                                ):
                                    lhs_base = _pointer_base_decl(lhs)
                                    rhs_base = _pointer_base_decl(rhs)
                                    lhs_is_array_obj = bool(
                                        lhs_base
                                        and lhs_base.kind
                                        == CursorKind.VAR_DECL
                                        and lhs_base.type.kind
                                        in (
                                            TypeKind.CONSTANTARRAY,
                                            TypeKind.INCOMPLETEARRAY,
                                            TypeKind.VARIABLEARRAY,
                                            TypeKind.DEPENDENTSIZEDARRAY,
                                        )
                                    )
                                    rhs_is_array_obj = bool(
                                        rhs_base
                                        and rhs_base.kind
                                        == CursorKind.VAR_DECL
                                        and rhs_base.type.kind
                                        in (
                                            TypeKind.CONSTANTARRAY,
                                            TypeKind.INCOMPLETEARRAY,
                                            TypeKind.VARIABLEARRAY,
                                            TypeKind.DEPENDENTSIZEDARRAY,
                                        )
                                    )
                                    if (
                                        lhs_is_array_obj
                                        and rhs_is_array_obj
                                        and lhs_base.hash != rhs_base.hash
                                    ):
                                        violations.append(
                                            Violation(
                                                "Rule 18.2",
                                                "Subtraction between pointers shall only be applied to pointers that address elements of the same array",
                                                file_path,
                                                node.location.line,
                                                trigger=_cursor_text(node),
                                            )
                                        )

                                # Rule 18.1: A pointer resulting from arithmetic on a pointer operand shall address an element of the same array
                                def check_bounds(ptr_expr, int_expr):
                                    # Very basic heuristic for a + 6 where a is size 5
                                    while ptr_expr and ptr_expr.kind in (
                                        CursorKind.UNEXPOSED_EXPR,
                                        CursorKind.PAREN_EXPR,
                                        CursorKind.CSTYLE_CAST_EXPR,
                                    ):
                                        c = list(ptr_expr.get_children())
                                        if c:
                                            ptr_expr = c[-1]
                                        else:
                                            break
                                    if (
                                        ptr_expr
                                        and ptr_expr.kind
                                        == CursorKind.DECL_REF_EXPR
                                        and ptr_expr.type.kind
                                        == TypeKind.CONSTANTARRAY
                                    ):
                                        sz = ptr_expr.type.element_count
                                        while int_expr and int_expr.kind in (
                                            CursorKind.UNEXPOSED_EXPR,
                                            CursorKind.PAREN_EXPR,
                                        ):
                                            c = list(int_expr.get_children())
                                            if c:
                                                int_expr = c[-1]
                                            else:
                                                break
                                        if (
                                            int_expr
                                            and int_expr.kind
                                            == CursorKind.INTEGER_LITERAL
                                        ):
                                            try:
                                                vs = (
                                                    list(
                                                        int_expr.get_tokens()
                                                    )[0]
                                                    .spelling.lower()
                                                    .replace("u", "")
                                                    .replace("l", "")
                                                )
                                                base = (
                                                    16
                                                    if vs.startswith("0x")
                                                    else (
                                                        8
                                                        if vs.startswith("0")
                                                        and len(vs) > 1
                                                        else 10
                                                    )
                                                )
                                                v = int(vs, base)
                                                if v > sz:
                                                    violations.append(
                                                        Violation(
                                                            "Rule 18.1",
                                                            "A pointer resulting from arithmetic on a pointer operand shall address an element of the same array",
                                                            file_path,
                                                            node.location.line,
                                                            trigger=_cursor_text(
                                                                node
                                                            ),
                                                        )
                                                    )
                                            except Exception:
                                                pass

                                if is_ptr_lhs and not is_ptr_rhs:
                                    check_bounds(lhs, rhs)
                                elif is_ptr_rhs and not is_ptr_lhs:
                                    check_bounds(rhs, lhs)

                        if op_spelling in (">", ">=", "<", "<="):
                            if is_ptr_lhs and is_ptr_rhs:
                                lhs_base = _pointer_base_decl(lhs)
                                rhs_base = _pointer_base_decl(rhs)
                                lhs_is_array_obj = bool(
                                    lhs_base
                                    and lhs_base.kind == CursorKind.VAR_DECL
                                    and lhs_base.type.kind
                                    in (
                                        TypeKind.CONSTANTARRAY,
                                        TypeKind.INCOMPLETEARRAY,
                                        TypeKind.VARIABLEARRAY,
                                        TypeKind.DEPENDENTSIZEDARRAY,
                                    )
                                )
                                rhs_is_array_obj = bool(
                                    rhs_base
                                    and rhs_base.kind == CursorKind.VAR_DECL
                                    and rhs_base.type.kind
                                    in (
                                        TypeKind.CONSTANTARRAY,
                                        TypeKind.INCOMPLETEARRAY,
                                        TypeKind.VARIABLEARRAY,
                                        TypeKind.DEPENDENTSIZEDARRAY,
                                    )
                                )
                                if (
                                    lhs_is_array_obj
                                    and rhs_is_array_obj
                                    and lhs_base.hash != rhs_base.hash
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 18.3",
                                            "The relational operators shall not be applied to objects of pointer type except where they point into the same object",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                        if op_spelling == "=":
                            # Chapter 22 resource tracking from assignments.
                            rhs_expr = unwrap_expr(rhs)
                            lhs_expr = unwrap_expr(lhs)
                            if (
                                rhs_expr
                                and rhs_expr.kind == CursorKind.CALL_EXPR
                            ):
                                called = get_call_name(rhs_expr)
                                lhs_hash = get_decl_ref_hash(lhs_expr)
                                if lhs_hash is not None:
                                    if called in (
                                        "malloc",
                                        "calloc",
                                        "realloc",
                                    ):
                                        alloc_resources[lhs_hash] = {
                                            "name": (
                                                lhs_expr.spelling
                                                if hasattr(
                                                    lhs_expr, "spelling"
                                                )
                                                else ""
                                            ),
                                            "line": node.location.line,
                                            "kind": "heap",
                                        }
                                    elif called == "fopen":
                                        call_args = list(
                                            rhs_expr.get_arguments()
                                        )
                                        mode = ""
                                        fname = ""
                                        if len(call_args) >= 2:
                                            mode = get_string_literal_text(
                                                call_args[1]
                                            )
                                        if len(call_args) >= 1:
                                            fname = get_string_literal_text(
                                                call_args[0]
                                            )
                                        alloc_resources[lhs_hash] = {
                                            "name": (
                                                lhs_expr.spelling
                                                if hasattr(
                                                    lhs_expr, "spelling"
                                                )
                                                else ""
                                            ),
                                            "line": node.location.line,
                                            "kind": "file",
                                        }
                                        file_modes[lhs_hash] = mode
                                        if fname:
                                            if fname not in file_opens:
                                                file_opens[fname] = []
                                            file_opens[fname].append(
                                                {
                                                    "hash": lhs_hash,
                                                    "mode": mode,
                                                    "line": node.location.line,
                                                }
                                            )

                            # Rule 19.1: An object shall not be assigned or copied to an overlapping object
                            def _get_base_decl(n):
                                while n:
                                    if (
                                        n.kind == CursorKind.DECL_REF_EXPR
                                        and n.referenced
                                    ):
                                        return n.referenced
                                    if n.kind in (
                                        CursorKind.UNEXPOSED_EXPR,
                                        CursorKind.PAREN_EXPR,
                                        CursorKind.CSTYLE_CAST_EXPR,
                                        CursorKind.ARRAY_SUBSCRIPT_EXPR,
                                        CursorKind.MEMBER_REF_EXPR,
                                    ):
                                        c = list(n.get_children())
                                        if not c:
                                            break
                                        n = c[0]
                                    else:
                                        break
                                return None

                            base_lhs = _get_base_decl(lhs)
                            base_rhs = _get_base_decl(rhs)
                            if (
                                base_lhs
                                and base_rhs
                                and base_lhs.hash == base_rhs.hash
                            ):
                                t = base_lhs.type.get_canonical()
                                if (
                                    t.kind == TypeKind.RECORD
                                    and t.get_declaration().kind
                                    == CursorKind.UNION_DECL
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 19.1",
                                            "An object shall not be assigned or copied to an overlapping object",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                            if rhs.kind == CursorKind.UNARY_OPERATOR:
                                r_toks = [
                                    t.spelling for t in tuple(rhs.get_tokens())
                                ]
                                if "&" in r_toks:
                                    c = list(rhs.get_children())
                                    if (
                                        c
                                        and c[0].kind
                                        == CursorKind.DECL_REF_EXPR
                                        and c[0].referenced
                                    ):
                                        target = c[0].referenced
                                        if (
                                            target.kind == CursorKind.VAR_DECL
                                            and target.lexical_parent
                                            and target.lexical_parent.kind
                                            != CursorKind.TRANSLATION_UNIT
                                        ):
                                            if (
                                                getattr(
                                                    target, "storage_class", 0
                                                )
                                                != clang.cindex.StorageClass.STATIC
                                            ):
                                                lhs_v = lhs
                                                while lhs_v and lhs_v.kind in (
                                                    CursorKind.UNEXPOSED_EXPR,
                                                    CursorKind.PAREN_EXPR,
                                                ):
                                                    lc = list(
                                                        lhs_v.get_children()
                                                    )
                                                    if lc:
                                                        lhs_v = lc[-1]
                                                    else:
                                                        break
                                                if (
                                                    lhs_v
                                                    and lhs_v.kind
                                                    == CursorKind.DECL_REF_EXPR
                                                    and lhs_v.referenced
                                                ):
                                                    ltarget = lhs_v.referenced
                                                    if (
                                                        getattr(
                                                            ltarget,
                                                            "linkage",
                                                            0,
                                                        )
                                                        in (
                                                            clang.cindex.LinkageKind.EXTERNAL,
                                                            clang.cindex.LinkageKind.INTERNAL,
                                                        )
                                                        or getattr(
                                                            ltarget,
                                                            "storage_class",
                                                            0,
                                                        )
                                                        == clang.cindex.StorageClass.STATIC
                                                    ):
                                                        violations.append(
                                                            Violation(
                                                                "Rule 18.6",
                                                                "The address of an object with automatic storage shall not be copied to another object that persists",
                                                                file_path,
                                                                node.location.line,
                                                                trigger=_cursor_text(
                                                                    rhs
                                                                ),
                                                            )
                                                        )
                                                        if is_cpp_file:
                                                            violations.append(
                                                                Violation(
                                                                    "Rule 7-5-2",
                                                                    "The address of an object with automatic storage shall not be assigned to another object that may persist after the first object ends.",
                                                                    file_path,
                                                                    node.location.line,
                                                                    trigger=_cursor_text(
                                                                        rhs
                                                                    ),
                                                                )
                                                            )

                        is_bitwise = op_spelling in (
                            "&",
                            "|",
                            "^",
                            "<<",
                            ">>",
                            "&=",
                            "|=",
                            "^=",
                            "<<=",
                            ">>=",
                        )
                        is_logical = op_spelling in ("&&", "||")

                        if is_bitwise:
                            lhs_k = lhs.type.get_canonical().kind
                            rhs_k = rhs.type.get_canonical().kind
                            if lhs_k not in (
                                TypeKind.UINT,
                                TypeKind.ULONG,
                                TypeKind.ULONGLONG,
                                TypeKind.UCHAR,
                                TypeKind.USHORT,
                                TypeKind.ENUM,
                            ) or rhs_k not in (
                                TypeKind.UINT,
                                TypeKind.ULONG,
                                TypeKind.ULONGLONG,
                                TypeKind.UCHAR,
                                TypeKind.USHORT,
                                TypeKind.ENUM,
                                TypeKind.INT,
                            ):  # Shift by int is allowed, but bitwise mostly unsigned
                                violations.append(
                                    Violation(
                                        "Rule 10.1",
                                        "Bitwise operator applied to an inappropriate essential type (usually requires unsigned).",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            if is_cpp_file:
                                lhs_u = unwrap_expr(lhs)
                                rhs_u = unwrap_expr(rhs)
                                lhs_is_const = (
                                    lhs_u is not None
                                    and lhs_u.kind
                                    == CursorKind.INTEGER_LITERAL
                                )
                                rhs_is_const = (
                                    rhs_u is not None
                                    and rhs_u.kind
                                    == CursorKind.INTEGER_LITERAL
                                )
                                if (
                                    not lhs_is_const
                                    and not rhs_is_const
                                    and lhs_k != rhs_k
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-20",
                                            "Non-constant operands to a binary bitwise operator shall have the same underlying type.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

                        if is_logical:
                            if not (
                                (
                                    has_explicit_bool_type(lhs)
                                    or is_essentially_boolean(lhs)
                                )
                                and (
                                    has_explicit_bool_type(rhs)
                                    or is_essentially_boolean(rhs)
                                )
                            ):
                                if is_cpp_file:
                                    violations.append(
                                        Violation(
                                            "Rule 5-3-1",
                                            "Each operand of the ! operator, the logical &&, or || shall have type bool.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

            cond_kind = getattr(CursorKind, "CONDITIONAL_OPERATOR", None)
            if (
                is_cpp_file
                and cond_kind is not None
                and node.kind == cond_kind
            ):
                c_children = list(node.get_children())
                if c_children:
                    cond_expr = c_children[0]
                    cond_type = _get_original_type(cond_expr) or cond_expr.type
                    if (
                        cond_type
                        and cond_type.get_canonical().kind != TypeKind.BOOL
                    ):
                        violations.append(
                            Violation(
                                "Rule 5-0-14",
                                "The first operand of a conditional operator shall have type bool.",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(cond_expr),
                            )
                        )

            def _get_underlying_expr(n):
                while n and n.kind in (
                    CursorKind.UNEXPOSED_EXPR,
                    CursorKind.PAREN_EXPR,
                ):
                    c = list(n.get_children())
                    if not c:
                        break
                    # libclang often wraps casts in UNEXPOSED_EXPR where the first child
                    # is TYPE_REF; pick the first expression-like child with a type.
                    preferred = None
                    for ch in c:
                        if ch.kind in (
                            CursorKind.TYPE_REF,
                            CursorKind.TEMPLATE_REF,
                            CursorKind.NAMESPACE_REF,
                            CursorKind.OVERLOADED_DECL_REF,
                        ):
                            continue
                        if getattr(ch, "type", None) is not None:
                            preferred = ch
                            break
                    n = preferred or c[0]
                return n

            def _get_essential_type(n):
                real_n = _get_underlying_expr(n)
                if not real_n:
                    return None
                if real_n.kind in (
                    CursorKind.BINARY_OPERATOR,
                    CursorKind.UNARY_OPERATOR,
                ):
                    c = list(real_n.get_children())
                    if len(c) >= 2:
                        t1 = _get_essential_type(c[0])
                        t2 = _get_essential_type(c[1])
                        if not t1:
                            return t2
                        if not t2:
                            return t1
                        # IMPORTANT: Do NOT call libclang Type.get_size() here.
                        # We hit a reproducible hard crash (SIGILL, worker exit -4/132)
                        # on yaml-cpp (src/null.cpp) inside clang.cindex.Type.get_size().
                        # This is a native libclang failure, not a recoverable Python
                        # exception, so the worker dies immediately. Keep this logic
                        # size-free and prefer conservative kind-based precedence.
                        k1 = t1.kind
                        k2 = t2.kind
                        if k1 == k2:
                            return t1
                        float_kinds = {
                            TypeKind.FLOAT,
                            TypeKind.DOUBLE,
                            TypeKind.LONGDOUBLE,
                        }
                        if k1 in float_kinds or k2 in float_kinds:
                            return t1 if k1 in float_kinds else t2
                        unsigned_kinds = {
                            TypeKind.UCHAR,
                            TypeKind.USHORT,
                            TypeKind.UINT,
                            TypeKind.ULONG,
                            TypeKind.ULONGLONG,
                        }
                        if k1 in unsigned_kinds or k2 in unsigned_kinds:
                            return t1 if k1 in unsigned_kinds else t2
                        return t1
                    elif len(c) == 1:
                        return _get_essential_type(c[0])
                if real_n.type:
                    return real_n.type.get_canonical()
                return None

            # Helper to classify type category
            def _get_type_category(t):
                if not t:
                    return "other"
                t_kind = t.kind
                if t_kind in (
                    TypeKind.FLOAT,
                    TypeKind.DOUBLE,
                    TypeKind.LONGDOUBLE,
                ):
                    return "float"
                if t_kind == TypeKind.BOOL:
                    return "bool"
                if t_kind == TypeKind.ENUM:
                    return "enum"
                if t_kind in (
                    TypeKind.UINT,
                    TypeKind.ULONG,
                    TypeKind.ULONGLONG,
                    TypeKind.UCHAR,
                    TypeKind.USHORT,
                    TypeKind.ENUM,
                ):
                    return "unsigned"
                if t_kind in (
                    TypeKind.INT,
                    TypeKind.LONG,
                    TypeKind.LONGLONG,
                    TypeKind.SCHAR,
                    TypeKind.SHORT,
                    TypeKind.CHAR_S,
                ):
                    return "signed"
                return "other"

            def _is_integer_zero_literal(expr):
                e = _get_underlying_expr(expr)
                if not e:
                    return False
                if e.kind != CursorKind.INTEGER_LITERAL:
                    return False
                toks = [t.spelling for t in tuple(e.get_tokens())]
                if not toks:
                    return False
                lit = toks[0].lower()
                lit = re.sub(r"[uUlL]+$", "", lit)
                if not lit:
                    return False
                try:
                    if lit.startswith("0x"):
                        return int(lit, 16) == 0
                    if lit.startswith("0b"):
                        return int(lit, 2) == 0
                    if len(lit) > 1 and lit.startswith("0") and lit.isdigit():
                        return int(lit, 8) == 0
                    return int(lit, 10) == 0
                except ValueError:
                    return False

            def _extract_integer_literal_value(expr):
                e = _get_underlying_expr(expr)
                if not e or e.kind != CursorKind.INTEGER_LITERAL:
                    return None
                toks = [t.spelling for t in tuple(e.get_tokens())]
                if not toks:
                    return None
                lit = toks[0].lower()
                lit = re.sub(r"[uUlL]+$", "", lit)
                if not lit:
                    return None
                try:
                    if lit.startswith("0x"):
                        return int(lit, 16)
                    if lit.startswith("0b"):
                        return int(lit, 2)
                    if len(lit) > 1 and lit.startswith("0") and lit.isdigit():
                        return int(lit, 8)
                    return int(lit, 10)
                except ValueError:
                    return None

            def _extract_character_literal_value(expr):
                e = _get_underlying_expr(expr)
                if not e or e.kind != CursorKind.CHARACTER_LITERAL:
                    return None
                toks = [t.spelling for t in tuple(e.get_tokens())]
                if not toks:
                    return None
                tok = toks[0]
                # Handle common C character literal spellings conservatively.
                if len(tok) >= 3 and tok[0] == "'" and tok[-1] == "'":
                    inner = tok[1:-1]
                    if len(inner) == 1:
                        return ord(inner)
                    if inner == r"\0":
                        return 0
                    if inner == r"\n":
                        return 10
                    if inner == r"\r":
                        return 13
                    if inner == r"\t":
                        return 9
                    if inner == r"\b":
                        return 8
                    if inner == r"\f":
                        return 12
                    if inner == r"\\":
                        return ord("\\")
                    if inner == r"\"":
                        return ord('"')
                    if inner == r"\'":
                        return ord("'")
                return None

            def _fits_integral_type(value, dst_t):
                if value is None or not dst_t:
                    return False
                dtk = dst_t.kind
                unsigned_kinds = {
                    TypeKind.UINT,
                    TypeKind.ULONG,
                    TypeKind.ULONGLONG,
                    TypeKind.UCHAR,
                    TypeKind.USHORT,
                }
                signed_kinds = {
                    TypeKind.INT,
                    TypeKind.LONG,
                    TypeKind.LONGLONG,
                    TypeKind.SCHAR,
                    TypeKind.SHORT,
                    TypeKind.CHAR_S,
                }
                if dtk not in unsigned_kinds and dtk not in signed_kinds:
                    return False
                try:
                    sz = dst_t.get_size()
                except Exception:
                    return False
                if not sz or sz < 1:
                    return False
                bits = sz * 8
                if dtk in unsigned_kinds:
                    return 0 <= value <= (2**bits - 1)
                # signed integral
                lo = -(2 ** (bits - 1))
                hi = (2 ** (bits - 1)) - 1
                return lo <= value <= hi

            def _is_matching_enum_constant(expr, dst_t):
                if not dst_t or dst_t.kind != TypeKind.ENUM:
                    return False
                e = _get_underlying_expr(expr)
                if not e:
                    return False
                if e.kind != CursorKind.DECL_REF_EXPR or not e.referenced:
                    return False
                if e.referenced.kind != CursorKind.ENUM_CONSTANT_DECL:
                    return False
                try:
                    enum_decl = dst_t.get_declaration()
                    return bool(
                        enum_decl
                        and e.referenced.semantic_parent
                        and e.referenced.semantic_parent.hash == enum_decl.hash
                    )
                except Exception:
                    return False

            # Helper to approximate wider type check
            def _is_wider_type(type1, type2):
                if not type1 or not type2:
                    return False
                try:
                    s1 = type1.get_size()
                    s2 = type2.get_size()
                    if s1 > 0 and s2 > 0 and s1 > s2:
                        return True
                except Exception:
                    pass
                return False

            # Rule 10.3: Implicit assignment/cast to narrower or different essential type category
            if node.kind in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL):
                for child in node.get_children():
                    if child.kind == CursorKind.UNEXPOSED_EXPR:
                        # Could be implicit cast
                        pass

            # Rule 9.3, 9.4, 9.5: Initialization checks
            if node.kind == CursorKind.INIT_LIST_EXPR:
                parent_type = node.type
                is_array = parent_type.kind in (
                    TypeKind.CONSTANTARRAY,
                    TypeKind.INCOMPLETEARRAY,
                )

                # Check for designated initializers
                has_designators = False
                initialized_indices = set()
                initialized_fields = set()

                # Clang AST Python bindings might not perfectly expose DesignatedInitExpr natively without traversal,
                # but we can check children.
                for child in node.get_children():
                    if (
                        getattr(child.kind, "name", "")
                        == "DESIGNATED_INIT_EXPR"
                    ):
                        has_designators = True
                    # Let's just catch overlapping explicit initialization from compiler diagnostics if AST isn't giving us raw designated nodes.
                    # Or we can just flag them if we see them.
                if not has_designators:
                    # Fallback: detect designated initializer tokens like [idx] = value.
                    itoks = [t.spelling for t in tuple(node.get_tokens())]
                    if "[" in itoks and "]" in itoks and "=" in itoks:
                        has_designators = True

                # Rule 9.5: Where designated initializers are used to initialize an array object the size of the array shall be specified explicitly
                if (
                    is_array
                    and parent_type.kind == TypeKind.INCOMPLETEARRAY
                    and has_designators
                ):
                    violations.append(
                        Violation(
                            "Rule 9.5",
                            "Array initialized with designated initializers must have explicit size",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(node),
                        )
                    )

                # Rule 9.3: Arrays shall not be partially initialized.
                if is_array and parent_type.kind == TypeKind.CONSTANTARRAY:
                    expected_size = parent_type.element_count
                    actual_elements = len(list(node.get_children()))
                    if (
                        actual_elements > 0
                        and actual_elements < expected_size
                        and not has_designators
                    ):
                        violations.append(
                            Violation(
                                "Rule 9.3",
                                f"Array partially initialized ({actual_elements} of {expected_size} elements)",
                                file_path,
                                node.location.line,
                                trigger=_cursor_text(node),
                            )
                        )

            if node.kind in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL):
                # Additional Rule 9.5 fallback on declaration text.
                try:
                    decl_type = node.type.get_canonical()
                    if decl_type.kind == TypeKind.INCOMPLETEARRAY:
                        dtoks = [t.spelling for t in tuple(node.get_tokens())]
                        if "[" in dtoks and "]" in dtoks and "=" in dtoks:
                            violations.append(
                                Violation(
                                    "Rule 9.5",
                                    "Array initialized with designated initializers must have explicit size",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                except Exception:
                    pass

            # Rule 10.3: implicit assignment/cast to narrower or different essential type category
            if node.kind in (
                CursorKind.VAR_DECL,
                CursorKind.FIELD_DECL,
                CursorKind.BINARY_OPERATOR,
            ):
                children = list(node.get_children())
                is_assignment = False
                if (
                    node.kind == CursorKind.BINARY_OPERATOR
                    and len(children) >= 2
                ):
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break
                    if op_spelling == "=":
                        is_assignment = True
                if children and (
                    node.kind != CursorKind.BINARY_OPERATOR or is_assignment
                ):
                    init_expr = None
                    dst_type = None
                    if node.kind in (
                        CursorKind.VAR_DECL,
                        CursorKind.FIELD_DECL,
                    ):
                        # For declarations, ignore TYPE_REF child and inspect initializer.
                        for c in children:
                            if c.kind != CursorKind.TYPE_REF:
                                init_expr = c
                                break
                        dst_type = node.type.get_canonical()
                    elif node.kind == CursorKind.BINARY_OPERATOR:
                        init_expr = children[1]
                        dst_type = children[0].type.get_canonical()
                    if init_expr and dst_type and _is_implicit_cast(init_expr):
                        src_type = _get_original_type(init_expr)
                        if src_type:
                            src_cat = _get_type_category(
                                src_type.get_canonical()
                            )
                            dst_cat = _get_type_category(dst_type)
                            if src_cat != "other" and dst_cat != "other":
                                if src_cat != dst_cat:
                                    trigger_text = _cursor_text(
                                        init_expr
                                    ) or _cursor_text(node)
                                    if re.fullmatch(
                                        r"(0|[1-9][0-9]*|'[^']+')",
                                        (trigger_text or "").strip(),
                                    ):
                                        trigger_text = _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 10.3",
                                            "Implicit cast to a different essential type category",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )
                                elif _is_wider_type(
                                    src_type.get_canonical(), dst_type
                                ):
                                    trigger_text = _cursor_text(
                                        init_expr
                                    ) or _cursor_text(node)
                                    if re.fullmatch(
                                        r"(0|[1-9][0-9]*|'[^']+')",
                                        (trigger_text or "").strip(),
                                    ):
                                        trigger_text = _cursor_text(node)
                                    violations.append(
                                        Violation(
                                            "Rule 10.3",
                                            "Implicit cast to a narrower essential type",
                                            file_path,
                                            node.location.line,
                                            trigger=trigger_text,
                                        )
                                    )

            # Rule 10.4, 10.6, 10.7, 10.8: Composite expressions
            if node.kind in (
                CursorKind.BINARY_OPERATOR,
                CursorKind.UNARY_OPERATOR,
            ):
                children = list(node.get_children())
                if (
                    node.kind == CursorKind.BINARY_OPERATOR
                    and len(children) >= 2
                ):
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break
                    if not op_spelling:
                        for candidate in (
                            "<<",
                            ">>",
                            "+",
                            "-",
                            "*",
                            "/",
                            "%",
                            "&",
                            "|",
                            "^",
                        ):
                            if candidate in [
                                tok.spelling
                                for tok in tuple(node.get_tokens())
                            ]:
                                op_spelling = candidate
                                break

                    real_lhs = _get_underlying_expr(lhs)
                    real_rhs = _get_underlying_expr(rhs)

                    is_lhs_composite = real_lhs.kind in (
                        CursorKind.BINARY_OPERATOR,
                        CursorKind.UNARY_OPERATOR,
                    )
                    is_rhs_composite = real_rhs.kind in (
                        CursorKind.BINARY_OPERATOR,
                        CursorKind.UNARY_OPERATOR,
                    )

                    # Rule 10.7: If a composite expression is used as one operand of an operator in which the usual arithmetic conversions are performed then the other operand shall not have wider essential type.
                    # We approximate "wider" by checking size
                    if is_lhs_composite or is_rhs_composite:
                        if op_spelling in {
                            "+",
                            "-",
                            "*",
                            "/",
                            "%",
                            "&",
                            "|",
                            "^",
                            "<<",
                            ">>",
                        }:
                            lhs_et = _get_essential_type(real_lhs)
                            rhs_et = _get_essential_type(real_rhs)
                            lhs_cat = _get_type_category(lhs_et)
                            rhs_cat = _get_type_category(rhs_et)
                            valid_cats = {
                                "signed",
                                "unsigned",
                                "float",
                                "enum",
                            }
                            if lhs_cat in valid_cats and rhs_cat in valid_cats:
                                if (
                                    is_lhs_composite
                                    and not is_rhs_composite
                                    and _is_wider_type(rhs_et, lhs_et)
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 10.7",
                                            "Composite expression used as operand with wider essential type operand.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                                elif (
                                    is_rhs_composite
                                    and not is_lhs_composite
                                    and _is_wider_type(lhs_et, rhs_et)
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 10.7",
                                            "Composite expression used as operand with wider essential type operand.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )

            # Rule 10.6 & 10.8: Assigning or casting composite expressions to wider type
            if node.kind in (
                CursorKind.VAR_DECL,
                CursorKind.FIELD_DECL,
                CursorKind.CSTYLE_CAST_EXPR,
                CursorKind.CXX_STATIC_CAST_EXPR,
                CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                CursorKind.BINARY_OPERATOR,
            ):
                children = list(node.get_children())

                is_assignment = False
                if (
                    node.kind == CursorKind.BINARY_OPERATOR
                    and len(children) >= 2
                ):
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break
                    if op_spelling == "=":
                        is_assignment = True

                if children and (
                    node.kind != CursorKind.BINARY_OPERATOR or is_assignment
                ):
                    init_expr = None
                    if node.kind in (
                        CursorKind.VAR_DECL,
                        CursorKind.FIELD_DECL,
                    ):
                        init_expr = children[0] if len(children) > 0 else None
                    elif node.kind == CursorKind.BINARY_OPERATOR:
                        init_expr = children[1] if len(children) > 1 else None
                    elif node.kind in (
                        CursorKind.CSTYLE_CAST_EXPR,
                        CursorKind.CXX_STATIC_CAST_EXPR,
                        CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                    ):
                        # skip type_ref
                        for c in children:
                            if c.kind != CursorKind.TYPE_REF:
                                init_expr = c
                                break

                    if init_expr:
                        real_init_expr = _get_underlying_expr(init_expr)
                        if (
                            real_init_expr
                            and real_init_expr.kind
                            == CursorKind.BINARY_OPERATOR
                        ):
                            real_et = _get_essential_type(real_init_expr)
                            if real_et and real_et.kind != TypeKind.BOOL:
                                if _is_wider_type(
                                    node.type.get_canonical(), real_et
                                ):
                                    rule = (
                                        "10.8"
                                        if node.kind
                                        in (
                                            CursorKind.CSTYLE_CAST_EXPR,
                                            CursorKind.CXX_STATIC_CAST_EXPR,
                                        )
                                        else "10.6"
                                    )
                                    msg = (
                                        "Composite expression cast to wider essential type."
                                        if rule == "10.8"
                                        else "Composite expression assigned to wider essential type."
                                    )
                                    violations.append(
                                        Violation(
                                            f"Rule {rule}",
                                            msg,
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(
                                                real_init_expr
                                            ),
                                        )
                                    )

            # Rule 10.5: The value of an expression should not be cast to an inappropriate essential type
            if node.kind in (
                CursorKind.CSTYLE_CAST_EXPR,
                CursorKind.CXX_STATIC_CAST_EXPR,
                CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                CursorKind.CXX_REINTERPRET_CAST_EXPR,
            ):
                children = list(node.get_children())
                if children:
                    cast_source = None
                    for c in children:
                        if c.kind != CursorKind.TYPE_REF:
                            cast_source = c
                            break
                    src_et = _get_essential_type(cast_source or children[0])
                    dst_et = node.type.get_canonical()

                    src_cat = _get_type_category(src_et)
                    dst_cat = _get_type_category(dst_et)

                    if src_cat != "other" and dst_cat != "other":
                        # Inappropriate casts: float <-> bool is definitely restricted.
                        # Boolean cannot be cast to float, Float cannot be cast to boolean.
                        if (src_cat == "float" and dst_cat == "bool") or (
                            src_cat == "bool" and dst_cat == "float"
                        ):
                            violations.append(
                                Violation(
                                    "Rule 10.5",
                                    "Expression cast to an inappropriate essential type.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        if is_cpp_file and (
                            (
                                src_cat == "float"
                                and dst_cat
                                in {"signed", "unsigned", "pointer", "enum"}
                            )
                            or (
                                dst_cat == "float"
                                and src_cat
                                in {"signed", "unsigned", "pointer", "enum"}
                            )
                        ):
                            violations.append(
                                Violation(
                                    "Rule 3-9-3",
                                    "The underlying bit representations of floating-point values shall not be used.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                    if is_cpp_file and src_et and dst_et:
                        src_k = src_et.get_canonical().kind
                        dst_k = dst_et.get_canonical().kind
                        if dst_k == TypeKind.POINTER:
                            src_is_int_or_enum = (
                                _is_integral_kind(src_k)
                                or src_k == TypeKind.ENUM
                            )
                            src_is_void_ptr = (
                                src_k == TypeKind.POINTER
                                and src_et.get_pointee().get_canonical().kind
                                == TypeKind.VOID
                            )
                            if src_is_int_or_enum or src_is_void_ptr:
                                violations.append(
                                    Violation(
                                        "Rule 5-2-8",
                                        "An object with integral, enumerated, or pointer to void type shall not be cast to a pointer type.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                        if _is_floating_kind(src_k) and _is_integral_kind(
                            dst_k
                        ):
                            violations.append(
                                Violation(
                                    "Rule 5-0-7",
                                    "There shall be no explicit floating point to integral conversions.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )
                        if _is_integral_kind(src_k) and _is_integral_kind(
                            dst_k
                        ):
                            if _is_unsigned_kind(src_k) != _is_unsigned_kind(
                                dst_k
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 5-0-8",
                                        "An explicit integral conversion shall not change the signedness of the underlying type.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            try:
                                if src_et.get_size() > dst_et.get_size():
                                    violations.append(
                                        Violation(
                                            "Rule 5-0-9",
                                            "An explicit integral conversion shall not convert to a narrower type.",
                                            file_path,
                                            node.location.line,
                                            trigger=_cursor_text(node),
                                        )
                                    )
                            except Exception:
                                pass
                    if is_cpp_file and cast_source:
                        src_value_expr = (
                            unwrap_expr(cast_source) or cast_source
                        )
                        src_decl = _get_record_decl_from_indirect_type(
                            src_value_expr.type
                        )
                        if not src_decl:
                            for sub in cast_source.walk_preorder():
                                if (
                                    sub.kind == CursorKind.DECL_REF_EXPR
                                    and sub.referenced
                                ):
                                    src_decl = (
                                        _get_record_decl_from_indirect_type(
                                            sub.referenced.type
                                        )
                                    )
                                    if src_decl:
                                        break
                        dst_decl = _get_record_decl_from_indirect_type(
                            node.type
                        )
                        if (
                            src_decl
                            and dst_decl
                            and src_decl.hash != dst_decl.hash
                            and _is_derived_from(dst_decl, src_decl)
                        ):
                            if _is_virtual_base_of(
                                src_decl, dst_decl
                            ) or _has_virtual_base_in_hierarchy(dst_decl):
                                violations.append(
                                    Violation(
                                        "Rule 5-2-2",
                                        "A pointer to a virtual base class shall only be cast to a pointer to a derived class by means of dynamic_cast.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )
                            if _class_is_polymorphic(src_decl):
                                violations.append(
                                    Violation(
                                        "Rule 5-2-3",
                                        "Casts from a base class to a derived class should not be performed on polymorphic types.",
                                        file_path,
                                        node.location.line,
                                        trigger=_cursor_text(node),
                                    )
                                )

            # C++ Rule 5-2-4: C-style and functional notation casts shall not be used.
            if file_path.suffix in (".cpp", ".cc", ".cxx"):
                if node.kind in (
                    CursorKind.CSTYLE_CAST_EXPR,
                    CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                ):
                    violations.append(
                        Violation(
                            "Rule 5-2-4",
                            "C-style casts and functional notation casts shall not be used.",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(node),
                        )
                    )

            # Rule 10.4: Both operands of an operator in which the usual arithmetic conversions are performed shall have the same essential type category
            if node.kind == CursorKind.BINARY_OPERATOR:
                children = list(node.get_children())
                if len(children) >= 2:
                    lhs = children[0]
                    rhs = children[1]
                    lhs_et = _get_essential_type(lhs)
                    rhs_et = _get_essential_type(rhs)
                    # Check if they are basically the same category (e.g. both Signed, both Unsigned, both Float)
                    cat_lhs = _get_type_category(lhs_et)
                    cat_rhs = _get_type_category(rhs_et)

                    def _is_enum_constant_expr(expr):
                        e = _get_underlying_expr(expr)
                        if not e:
                            return False
                        if e.kind == CursorKind.DECL_REF_EXPR and e.referenced:
                            return (
                                e.referenced.kind
                                == CursorKind.ENUM_CONSTANT_DECL
                            )
                        return False

                    def _has_explicit_cast_to_category(expr, expected_cat):
                        e = _get_underlying_expr(expr)
                        if not e:
                            return False
                        if e.kind in (
                            CursorKind.CSTYLE_CAST_EXPR,
                            CursorKind.CXX_STATIC_CAST_EXPR,
                            CursorKind.CXX_FUNCTIONAL_CAST_EXPR,
                            CursorKind.CXX_REINTERPRET_CAST_EXPR,
                            CursorKind.CXX_CONST_CAST_EXPR,
                        ):
                            return (
                                _get_type_category(
                                    e.type.get_canonical() if e.type else None
                                )
                                == expected_cat
                            )
                        return False

                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break

                    is_arith = op_spelling in (
                        "+",
                        "-",
                        "*",
                        "/",
                        "%",
                        "<",
                        ">",
                        "<=",
                        ">=",
                        "==",
                        "!=",
                    )
                    # Pragmatic FP reduction: libclang can type enum constants as signed ints
                    # in comparisons, which creates noisy "enum vs signed" diagnostics for
                    # otherwise natural enum-constant checks (e.g. opcode == INVALID).
                    if op_spelling in ("==", "!=", "<", "<=", ">", ">="):
                        if (
                            cat_lhs == "enum"
                            and cat_rhs == "signed"
                            and _is_enum_constant_expr(rhs)
                        ):
                            cat_rhs = "enum"
                        elif (
                            cat_rhs == "enum"
                            and cat_lhs == "signed"
                            and _is_enum_constant_expr(lhs)
                        ):
                            cat_lhs = "enum"
                    if (
                        is_arith
                        and cat_lhs != "other"
                        and cat_rhs != "other"
                        and cat_lhs != cat_rhs
                    ):
                        lhs_casted_to_rhs = _has_explicit_cast_to_category(
                            lhs, cat_rhs
                        )
                        rhs_casted_to_lhs = _has_explicit_cast_to_category(
                            rhs, cat_lhs
                        )
                        if not (lhs_casted_to_rhs or rhs_casted_to_lhs):
                            violations.append(
                                Violation(
                                    "Rule 10.4",
                                    f"Operands of arithmetic operator have different essential type categories ({cat_lhs} vs {cat_rhs}).",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )

                    # C++ Rule 6-2-2: floating-point expressions should not be tested for equality/inequality.
                    if is_cpp_file and op_spelling in ("==", "!="):
                        lhs_k = (
                            (_get_original_type(lhs) or lhs.type)
                            .get_canonical()
                            .kind
                        )
                        rhs_k = (
                            (_get_original_type(rhs) or rhs.type)
                            .get_canonical()
                            .kind
                        )
                        if _is_floating_kind(lhs_k) or _is_floating_kind(
                            rhs_k
                        ):
                            violations.append(
                                Violation(
                                    "Rule 6-2-2",
                                    "Floating-point expressions shall not be tested for equality or inequality.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )

            # Rule 10.2: Expressions of essentially character type shall not be used inappropriately in addition and subtraction
            if node.kind == CursorKind.BINARY_OPERATOR:
                children = list(node.get_children())
                if len(children) >= 2:
                    lhs = children[0]
                    rhs = children[1]
                    op_spelling = ""
                    for t in node.get_tokens():
                        if (
                            t.extent.start.offset >= lhs.extent.end.offset
                            and t.extent.end.offset <= rhs.extent.start.offset
                        ):
                            op_spelling = t.spelling
                            if op_spelling.strip():
                                break

                    if not op_spelling:
                        toks = [t.spelling for t in node.get_tokens()]
                        if "+" in toks:
                            op_spelling = "+"
                        elif "-" in toks:
                            op_spelling = "-"
                    if op_spelling in ("+", "-"):
                        lhs_t = _get_original_type(lhs) or lhs.type
                        rhs_t = _get_original_type(rhs) or rhs.type
                        lhs_k = lhs_t.get_canonical().kind
                        rhs_k = rhs_t.get_canonical().kind
                        is_char_lhs = lhs_k in (
                            TypeKind.CHAR_S,
                            TypeKind.CHAR_U,
                            TypeKind.SCHAR,
                            TypeKind.UCHAR,
                        )
                        is_char_rhs = rhs_k in (
                            TypeKind.CHAR_S,
                            TypeKind.CHAR_U,
                            TypeKind.SCHAR,
                            TypeKind.UCHAR,
                        )
                        if is_char_lhs and is_char_rhs and op_spelling == "+":
                            violations.append(
                                Violation(
                                    "Rule 10.2",
                                    "Addition of two characters is not allowed.",
                                    file_path,
                                    node.location.line,
                                    trigger=_cursor_text(node),
                                )
                            )

            # Rule 2.2 / 2.7 heuristics natively missing from clang diagnostics might be found via unused params
        if is_cpp_file and node.kind == CursorKind.NULL_STMT:
            # Rule 6-2-3: null statement shall only occur on a line by itself.
            try:
                same_file = bool(
                    node.location.file
                    and Path(node.location.file.name).resolve()
                    == file_path.resolve()
                )
                if same_file:
                    start_line = int(node.extent.start.line)
                    end_line = int(node.extent.end.line)
                    if (
                        start_line > 0
                        and end_line > 0
                        and start_line <= len(source_lines)
                    ):
                        segment = "\n".join(
                            source_lines[
                                start_line
                                - 1 : min(end_line, len(source_lines))
                            ]
                        )
                        if segment.strip() != ";":
                            violations.append(
                                Violation(
                                    "Rule 6-2-3",
                                    "A null statement shall only occur on a line by itself.",
                                    file_path,
                                    start_line,
                                    trigger=segment.strip(),
                                )
                            )
            except Exception:
                pass
        if is_cpp_file and node.kind in (
            CursorKind.IF_STMT,
            CursorKind.WHILE_STMT,
            CursorKind.FOR_STMT,
            CursorKind.DO_STMT,
        ):
            # Rule 6-2-3: also flag empty compound bodies used inline
            # (e.g. `if (x) {}`), which are semantically null statements.
            try:
                for child in node.get_children():
                    if child.kind != CursorKind.COMPOUND_STMT:
                        continue
                    if any(True for _ in child.get_children()):
                        continue
                    line = int(
                        child.extent.start.line or node.location.line or 0
                    )
                    snippet = _cursor_text(node)
                    if line > 0:
                        violations.append(
                            Violation(
                                "Rule 6-2-3",
                                "A null statement shall only occur on a line by itself.",
                                file_path,
                                line,
                                trigger=snippet or "{}",
                            )
                        )
            except Exception:
                pass

        # Rule 2.2 / 2.7 heuristics natively missing from clang diagnostics might be found via unused params
        if node.kind == CursorKind.PARM_DECL and node.spelling:
            if (
                node.location.file
                and Path(node.location.file.name).resolve()
                == file_path.resolve()
            ):
                # Check if this parameter is ever referenced in the function body
                func = node.lexical_parent
                if (
                    func
                    and func.kind
                    in (CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD)
                    and func.is_definition()
                ):
                    # We do a basic search for DECL_REF_EXPR referencing this parm
                    is_used = False
                    # Fast path: if the parameter identifier appears more than once in the
                    # function token stream, it is referenced beyond the declaration list.
                    try:
                        occ = 0
                        for tok in func.get_tokens():
                            if tok.spelling == node.spelling:
                                occ += 1
                                if occ > 1:
                                    is_used = True
                                    break
                    except Exception:
                        pass
                    param_usr = ""
                    try:
                        param_usr = node.get_usr() or ""
                    except Exception:
                        param_usr = ""
                    param_hash = node.hash

                    def find_usage(n):
                        nonlocal is_used
                        if is_used:
                            return
                        if n.kind == CursorKind.DECL_REF_EXPR and n.referenced:
                            ref = n.referenced
                            try:
                                ref_usr = ref.get_usr() or ""
                            except Exception:
                                ref_usr = ""
                            if (param_usr and ref_usr == param_usr) or (
                                ref.hash == param_hash
                            ):
                                is_used = True
                        for c in n.get_children():
                            find_usage(c)

                    find_usage(func)
                    if not is_used and node.spelling:
                        key = (
                            str(file_path.resolve()),
                            node.location.line,
                            node.spelling,
                        )
                        has_nearby_diag = any(
                            f == key[0]
                            and n == key[2]
                            and abs(int(l) - int(key[1])) <= 3
                            for (f, l, n) in unused_param_diag_keys
                        )
                        if (
                            key not in unused_param_diag_keys
                            and not has_nearby_diag
                        ):
                            violations.append(
                                Violation(
                                    "Rule 2.7",
                                    f"There should be no unused parameters in functions: '{node.spelling}'",
                                    file_path,
                                    node.location.line,
                                    trigger=node.spelling,
                                )
                            )

        # Rule 5.3: Identifier hiding (shadowing)
        # Detailed shadowing detection requires building a scope stack, but we can detect basic ones
        # using the AST context. (Omitted for brevity, requires scope tracking)

        # Rule 8.4: A compatible declaration shall be visible when an obj/fn with external linkage is defined
        if node.kind == CursorKind.FUNCTION_DECL and node.is_definition():
            # Check if it has external linkage and no forward declaration exists
            if (
                node.linkage == clang.cindex.LinkageKind.EXTERNAL
                and node.lexical_parent
                and node.lexical_parent.kind == CursorKind.TRANSLATION_UNIT
            ):
                decl_key = (node.spelling, node.type.spelling)
                # main is exempt; otherwise require a prior visible declaration.
                if (
                    node.spelling != "main"
                    and decl_key not in visible_external_func_decls
                    and node.spelling not in visible_header_func_names
                ):
                    violations.append(
                        Violation(
                            "Rule 8.4",
                            f"A compatible declaration shall be visible when function '{node.spelling}' is defined.",
                            file_path,
                            node.location.line,
                            trigger=node.spelling,
                        )
                    )

        for child in node.get_children():
            if child:
                visit(child, next_func)

    if tu.cursor:
        visit(tu.cursor)

    apply_resource_postprocess_rules(
        file_path=file_path,
        violations=violations,
        alloc_resources=alloc_resources,
        freed_heap=freed_heap,
        closed_files=closed_files,
        file_opens=file_opens,
        is_write_mode=is_write_mode,
    )

    # Rule 5.5: Identifiers vs macros
    for name, node in ordinary.items():
        if name in macros:
            violations.append(
                Violation(
                    "Rule 5.5",
                    f"Identifiers shall be distinct from macro names: '{name}'",
                    file_path,
                    node.location.line,
                    trigger=name,
                )
            )
    for name, node in tags.items():
        if name in macros:
            violations.append(
                Violation(
                    "Rule 5.5",
                    f"Identifiers shall be distinct from macro names: tag '{name}'",
                    file_path,
                    node.location.line,
                    trigger=name,
                )
            )
    for name, node in typedefs.items():
        if name in macros:
            violations.append(
                Violation(
                    "Rule 5.5",
                    f"Identifiers shall be distinct from macro names: typedef '{name}'",
                    file_path,
                    node.location.line,
                    trigger=name,
                )
            )

    # Rule 5.6: Typedef unique
    for name, node in typedefs.items():
        if name in ordinary or name in tags:
            violations.append(
                Violation(
                    "Rule 5.6",
                    f"A typedef name shall be a unique identifier: '{name}'",
                    file_path,
                    node.location.line,
                    trigger=name,
                )
            )

    # Rule 5.7: Tag unique
    for name, node in tags.items():
        if name in ordinary:
            violations.append(
                Violation(
                    "Rule 5.7",
                    f"A tag name shall be a unique identifier: '{name}'",
                    file_path,
                    node.location.line,
                    trigger=name,
                )
            )

    for tag_hash, tag_node in declared_tags.items():
        spelling = getattr(tag_node, "spelling", "") or ""
        # Clang synthesizes pseudo names like "union (unnamed at file:line:col)".
        # These are not real tag identifiers and should not trigger Rule 2.4.
        if "(unnamed at " in spelling:
            continue
        if tag_hash not in used_tags:
            if tag_node.kind == CursorKind.TYPEDEF_DECL:
                violations.append(
                    Violation(
                        "Rule 2.3",
                        f"Unused typedef declaration: '{tag_node.spelling}'",
                        file_path,
                        tag_node.location.line,
                        trigger=tag_node.spelling,
                    )
                )
            else:
                violations.append(
                    Violation(
                        "Rule 2.4",
                        f"Unused tag declaration: '{tag_node.spelling}'",
                        file_path,
                        tag_node.location.line,
                        trigger=tag_node.spelling,
                    )
                )

    for vhash, n_decl in file_vars.items():
        users = file_vars_users.get(vhash, set())
        if len(users) == 1:
            violations.append(
                Violation(
                    "Rule 8.9",
                    f"An object '{n_decl.spelling}' should be defined at block scope if its identifier only appears in a single function.",
                    file_path,
                    n_decl.location.line,
                    trigger=n_decl.spelling,
                )
            )

    for f_hash, ptr_params in func_ptr_params.items():
        mutated_set = func_ptr_params_mutated.get(f_hash, set())
        mutated_name_set = func_ptr_params_mutated_names.get(f_hash, set())
        fn_node = function_nodes.get(f_hash)
        fn_tok_text = ""
        if fn_node is not None:
            try:
                fn_tok_text = " ".join(
                    t.spelling for t in tuple(fn_node.get_tokens())
                )
            except Exception:
                fn_tok_text = ""

        def _is_pointer_param_written_by_tokens(param_name: str) -> bool:
            if not fn_tok_text or not param_name:
                return False
            # Heuristic write patterns:
            #   *param = ...
            #   param[index] = ...
            #   param->field = ...
            if re.search(rf"\*\s*{re.escape(param_name)}\s*=", fn_tok_text):
                return True
            if re.search(
                rf"{re.escape(param_name)}\s*\[[^\]]*\]\s*=", fn_tok_text
            ):
                return True
            if re.search(rf"{re.escape(param_name)}\s*->[^;]*=", fn_tok_text):
                return True
            return False

        def _is_pointer_param_forwarded_to_call(param_name: str) -> bool:
            if not fn_tok_text or not param_name:
                return False
            # If a pointer parameter is forwarded as a call argument, we cannot
            # reliably infer const-correctness without interprocedural analysis.
            # Treat this as "potentially mutable" to avoid false positives.
            call_arg_pat = (
                rf"\b[A-Za-z_]\w*\s*\([^)]*\b{re.escape(param_name)}\b[^)]*\)"
            )
            return bool(re.search(call_arg_pat, fn_tok_text))

        for p_hash, p_spelling, p_line in ptr_params:
            if (
                p_hash not in mutated_set
                and p_spelling not in mutated_name_set
                and not _is_pointer_param_written_by_tokens(p_spelling)
                and not _is_pointer_param_forwarded_to_call(p_spelling)
            ):
                violations.append(
                    Violation(
                        "Rule 8.13",
                        f"A pointer should point to a const-qualified type whenever possible: '{p_spelling}'",
                        file_path,
                        p_line,
                        trigger=p_spelling,
                    )
                )

    # Post-process Chapter 15 rules per function
    for func in chapter_15_funcs:
        # Rule 15.2: The goto statement shall jump to a label declared later in the same function
        # Rule 15.3: Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement

        labels = {}  # name -> (node, scope_path)
        gotos = []  # (node, scope_path)

        # We need a custom walker to track scope paths
        def walk_scopes(n, current_path):
            if n.kind == CursorKind.COMPOUND_STMT:
                current_path = current_path + (n.hash,)

            if n.kind == CursorKind.LABEL_STMT:
                labels[n.spelling] = (n, current_path)
            elif n.kind == CursorKind.GOTO_STMT:
                gotos.append((n, current_path))

            for c in n.get_children():
                walk_scopes(c, current_path)

        walk_scopes(func, ())

        for goto_node, goto_path in gotos:
            target_name = ""
            for c in goto_node.get_children():
                if c.kind == CursorKind.LABEL_REF:
                    target_name = c.spelling
                    break

            if target_name in labels:
                target_node, target_path = labels[target_name]

                # Check 15.2 (backward jump)
                if target_node.location.line <= goto_node.location.line:
                    violations.append(
                        Violation(
                            "Rule 15.2",
                            "The goto statement shall jump to a label declared later in the same function (jumping back)",
                            file_path,
                            goto_node.location.line,
                            trigger=target_name,
                        )
                    )

                # Check 15.3 (scope visibility)
                # target_path must be a prefix of goto_path (meaning target is in the same block or an enclosing block)
                if (
                    len(target_path) > len(goto_path)
                    or goto_path[: len(target_path)] != target_path
                ):
                    # Exception: if they are in the exact same block, target_path == goto_path. Wait, if target is DEEPER, length is greater.
                    # If target is in a sibling block, lengths might be same but elements differ.
                    violations.append(
                        Violation(
                            "Rule 15.3",
                            "Any label referenced by a goto statement shall be declared in the same block, or in any block enclosing the goto statement",
                            file_path,
                            goto_node.location.line,
                            trigger=target_name,
                        )
                    )

        # Rule 15.4: There should be no more than one break or goto statement used to terminate any iteration statement
        def walk_loops(n):
            if n.kind in (
                CursorKind.FOR_STMT,
                CursorKind.WHILE_STMT,
                CursorKind.DO_STMT,
            ):
                # Count breaks and gotos directly inside this loop's body, stopping at nested loops/switches
                terminators = []

                def count_terms(inner_n):
                    if inner_n.kind in (
                        CursorKind.FOR_STMT,
                        CursorKind.WHILE_STMT,
                        CursorKind.DO_STMT,
                        CursorKind.SWITCH_STMT,
                    ):
                        return  # inner construct handles its own breaks
                    if inner_n.kind in (
                        CursorKind.BREAK_STMT,
                        CursorKind.GOTO_STMT,
                    ):
                        terminators.append(inner_n)
                    for c in inner_n.get_children():
                        count_terms(c)

                # We only want to search the body of the loop.
                # Usually the body is a COMPOUND_STMT.
                for c in n.get_children():
                    if c.kind == CursorKind.COMPOUND_STMT:
                        count_terms(c)

                if len(terminators) > 1:
                    # Flag the loop itself or the second terminator
                    violations.append(
                        Violation(
                            "Rule 15.4",
                            f"There should be no more than one break or goto statement used to terminate any iteration statement (found {len(terminators)})",
                            file_path,
                            terminators[-1].location.line,
                            trigger=_cursor_text(terminators[-1]),
                        )
                    )

                if is_cpp_file and n.kind == CursorKind.FOR_STMT:
                    # Rule 6-5-5 / 6-5-6: loop-control vars other than loop-counter.
                    toks = [t.spelling for t in n.get_tokens()]
                    loop_counter = None
                    other_ctrl_refs = {}
                    body_node = next(
                        (
                            c
                            for c in n.get_children()
                            if c.kind == CursorKind.COMPOUND_STMT
                        ),
                        None,
                    )
                    try:
                        if toks and toks[0] == "for":
                            start_paren = toks.index("(")
                            paren_count = 1
                            end_paren = -1
                            for i in range(start_paren + 1, len(toks)):
                                if toks[i] == "(":
                                    paren_count += 1
                                elif toks[i] == ")":
                                    paren_count -= 1
                                    if paren_count == 0:
                                        end_paren = i
                                        break
                            if end_paren != -1:
                                inside = toks[start_paren + 1 : end_paren]
                                semis = [
                                    i for i, t in enumerate(inside) if t == ";"
                                ]
                                if len(semis) == 2:
                                    clause1 = inside[: semis[0]]
                                    clause2 = inside[semis[0] + 1 : semis[1]]
                                    keywords = {
                                        "int",
                                        "long",
                                        "short",
                                        "signed",
                                        "unsigned",
                                        "char",
                                        "float",
                                        "double",
                                        "bool",
                                        "auto",
                                        "const",
                                        "volatile",
                                        "static",
                                        "register",
                                        "extern",
                                        "mutable",
                                        "typename",
                                        "struct",
                                        "class",
                                        "enum",
                                        "union",
                                    }
                                    init_ids = [
                                        tk
                                        for tk in clause1
                                        if re.match(r"^[A-Za-z_]\w*$", tk)
                                        and tk not in keywords
                                    ]
                                    if init_ids:
                                        loop_counter = init_ids[0]
                                    cond_ids = {
                                        tk
                                        for tk in clause2
                                        if re.match(r"^[A-Za-z_]\w*$", tk)
                                        and tk not in keywords
                                    }
                                    for ref in cond_ids:
                                        if ref != loop_counter:
                                            other_ctrl_refs[ref] = {
                                                "modified_in_cond": False,
                                                "modified_in_body": False,
                                                "is_bool": False,
                                            }
                    except Exception:
                        pass

                    def mark_mods(mnode):
                        if mnode.kind == CursorKind.BINARY_OPERATOR:
                            mtoks = [
                                t.spelling for t in tuple(mnode.get_tokens())
                            ]
                            assign_ops = (
                                "=",
                                "+=",
                                "-=",
                                "*=",
                                "/=",
                                "%=",
                                "&=",
                                "|=",
                                "^=",
                                "<<=",
                                ">>=",
                            )
                            if any(op in mtoks for op in assign_ops):
                                kids = list(mnode.get_children())
                                if kids:
                                    lhs = kids[0]
                                    lhs_u = unwrap_expr(lhs)
                                    if (
                                        lhs_u
                                        and lhs_u.kind
                                        == CursorKind.DECL_REF_EXPR
                                        and lhs_u.spelling in other_ctrl_refs
                                    ):
                                        other_ctrl_refs[lhs_u.spelling][
                                            "modified_in_body"
                                        ] = True
                                        try:
                                            other_ctrl_refs[lhs_u.spelling][
                                                "is_bool"
                                            ] = (
                                                lhs_u.type.get_canonical().kind
                                                == TypeKind.BOOL
                                            )
                                        except Exception:
                                            pass
                        if mnode.kind == CursorKind.UNARY_OPERATOR:
                            utoks = [
                                t.spelling for t in tuple(mnode.get_tokens())
                            ]
                            if "++" in utoks or "--" in utoks:
                                kids = list(mnode.get_children())
                                if kids:
                                    target = unwrap_expr(kids[0])
                                    if (
                                        target
                                        and target.kind
                                        == CursorKind.DECL_REF_EXPR
                                        and target.spelling in other_ctrl_refs
                                    ):
                                        other_ctrl_refs[target.spelling][
                                            "modified_in_body"
                                        ] = True
                                        try:
                                            other_ctrl_refs[target.spelling][
                                                "is_bool"
                                            ] = (
                                                target.type.get_canonical().kind
                                                == TypeKind.BOOL
                                            )
                                        except Exception:
                                            pass
                        for cc in mnode.get_children():
                            if cc.kind in (
                                CursorKind.FOR_STMT,
                                CursorKind.WHILE_STMT,
                                CursorKind.DO_STMT,
                                CursorKind.SWITCH_STMT,
                            ):
                                continue
                            mark_mods(cc)

                    if body_node and other_ctrl_refs:
                        mark_mods(body_node)
                        for name, meta in other_ctrl_refs.items():
                            if meta["modified_in_body"]:
                                violations.append(
                                    Violation(
                                        "Rule 6-5-5",
                                        f"Loop-control-variable '{name}' other than the loop-counter shall not be modified within statement.",
                                        file_path,
                                        n.location.line,
                                        trigger=name,
                                    )
                                )
                                if not meta["is_bool"]:
                                    violations.append(
                                        Violation(
                                            "Rule 6-5-6",
                                            f"Loop-control-variable '{name}' modified in statement shall have bool type.",
                                            file_path,
                                            n.location.line,
                                            trigger=name,
                                        )
                                    )

            for c in n.get_children():
                walk_loops(c)

        walk_loops(func)

        if is_cpp_file:
            # Rule 6-6-3: continue shall only be used within a well-formed for loop.
            def for_is_well_formed(for_node):
                toks = [t.spelling for t in for_node.get_tokens()]
                if not toks or toks[0] != "for":
                    return False
                try:
                    start_paren = toks.index("(")
                    paren_count = 1
                    end_paren = -1
                    for i in range(start_paren + 1, len(toks)):
                        if toks[i] == "(":
                            paren_count += 1
                        elif toks[i] == ")":
                            paren_count -= 1
                            if paren_count == 0:
                                end_paren = i
                                break
                    if end_paren == -1:
                        return False
                    inside = toks[start_paren + 1 : end_paren]
                    semis = [i for i, t in enumerate(inside) if t == ";"]
                    if len(semis) != 2:
                        return False
                    c1 = inside[: semis[0]]
                    c2 = inside[semis[0] + 1 : semis[1]]
                    c3 = inside[semis[1] + 1 :]
                    return bool(c1 and c2 and c3)
                except Exception:
                    return False

            def walk_continue(node, loop_stack):
                if node.kind in (
                    CursorKind.FOR_STMT,
                    CursorKind.WHILE_STMT,
                    CursorKind.DO_STMT,
                ):
                    if node.kind == CursorKind.FOR_STMT:
                        loop_stack.append(("for", for_is_well_formed(node)))
                    elif node.kind == CursorKind.WHILE_STMT:
                        loop_stack.append(("while", False))
                    else:
                        loop_stack.append(("do", False))

                if node.kind == CursorKind.CONTINUE_STMT:
                    if not loop_stack:
                        violations.append(
                            Violation(
                                "Rule 6-6-3",
                                "The continue statement shall only be used within a well-formed for loop.",
                                file_path,
                                node.location.line,
                                trigger="continue",
                            )
                        )
                    else:
                        top_kind, top_well_formed = loop_stack[-1]
                        if top_kind != "for" or not top_well_formed:
                            violations.append(
                                Violation(
                                    "Rule 6-6-3",
                                    "The continue statement shall only be used within a well-formed for loop.",
                                    file_path,
                                    node.location.line,
                                    trigger="continue",
                                )
                            )

                for c in node.get_children():
                    walk_continue(c, loop_stack)

                if node.kind in (
                    CursorKind.FOR_STMT,
                    CursorKind.WHILE_STMT,
                    CursorKind.DO_STMT,
                ):
                    loop_stack.pop()

            walk_continue(func, [])

    apply_common_postprocess_rules(
        file_path=file_path,
        violations=violations,
        chapter_15_funcs=chapter_15_funcs,
        is_cpp_file=is_cpp_file,
        is_essentially_boolean=is_essentially_boolean,
        unwrap_expr=unwrap_expr,
    )

    if is_cpp_file:
        apply_cpp_ch11_12_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
            iter_base_specs=_iter_base_specs,
            is_fundamental_kind=_is_fundamental_kind,
        )

        apply_cpp_ch15_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
            unwrap_expr=unwrap_expr,
            record_decl_from_type=_record_decl_from_type,
            is_derived_from=_is_derived_from,
        )

        apply_cpp_ch9_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
            returns_non_const_handle=_returns_non_const_handle,
            get_returned_decl=get_returned_decl,
        )

        apply_cpp_ch10_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
            iter_base_specs=_iter_base_specs,
            has_virtual_base_in_hierarchy=_has_virtual_base_in_hierarchy,
            is_derived_from=_is_derived_from,
            method_sig_key=_method_sig_key,
            method_has_virtual_keyword=_method_has_virtual_keyword,
            collect_base_member_names=_collect_base_member_names,
        )
        apply_cpp_ch14_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
        )

        apply_cpp_ch7_8_rules(
            tu=tu,
            file_path=file_path,
            violations=violations,
            iter_base_specs=_iter_base_specs,
            method_has_default_argument=_method_has_default_argument,
            cpp_scope_decl_lines=cpp_scope_decl_lines,
            cpp_scope_using_lines=cpp_scope_using_lines,
            chapter_15_funcs=chapter_15_funcs,
            cpp_func_has_asm=cpp_func_has_asm,
            cpp_func_asm_lines=cpp_func_asm_lines,
        )

        apply_cpp_postprocess_rules(
            file_path=file_path,
            violations=violations,
            chapter_15_funcs=chapter_15_funcs,
            unwrap_expr=unwrap_expr,
            is_pointer_or_reference_kind=_is_pointer_or_reference_kind,
            get_returned_decl=get_returned_decl,
            cpp_entity_decl_lines=cpp_entity_decl_lines,
            rule_2_10_1_enabled=rule_2_10_1_enabled,
            cpp_typo_scope_names=cpp_typo_scope_names,
            cpp_static_duration_names=cpp_static_duration_names,
            cpp_defined_functions=cpp_defined_functions,
            cpp_function_linkage=cpp_function_linkage,
            cpp_called_functions=cpp_called_functions,
            cpp_void_func_has_side_effect=cpp_void_func_has_side_effect,
            cpp_var_decls=cpp_var_decls,
            cpp_var_ref_counts=cpp_var_ref_counts,
            is_pod_like_type=is_pod_like_type,
            cpp_known_error_calls_ignored=cpp_known_error_calls_ignored,
            logger=logger,
        )

    raw_profile = getattr(project_config, "misra_profile", None)
    if isinstance(raw_profile, str):
        profile_key = raw_profile
    else:
        profile_key = cast(Optional[str], getattr(raw_profile, "key", None))
    violations.extend(
        run_fallback_source_scans(
            file_path, is_cpp_file, profile_key=profile_key
        )
    )

    return violations


def _is_implicit_cast(node: clang.cindex.Cursor) -> bool:
    return bool(node and node.kind == CursorKind.UNEXPOSED_EXPR)


def _get_original_type(
    node: clang.cindex.Cursor,
) -> Optional[clang.cindex.Type]:
    """Traverses down through UNEXPOSED_EXPR to find the concrete type before implicit casts."""
    if not node:
        return None
    children = list(node.get_children())
    if not children:
        return node.type
    child = children[0]
    if child and child.kind == CursorKind.UNEXPOSED_EXPR:
        return _get_original_type(child)
    else:
        return child.type if child else node.type
