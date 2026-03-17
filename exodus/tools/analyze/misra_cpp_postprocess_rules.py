from pathlib import Path
import logging
from typing import Any, Callable

import clang.cindex
from clang.cindex import CursorKind, TypeKind

from exodus.tools.analyze.misra_rules import Violation


def _has_executable_statement(func_cursor: clang.cindex.Cursor) -> bool:
    for c in func_cursor.get_children():
        if c.kind != CursorKind.COMPOUND_STMT:
            continue
        for stmt in c.get_children():
            if stmt.kind not in (CursorKind.DECL_STMT,):
                return True
    return False


def apply_cpp_postprocess_rules(
    *,
    file_path: Path,
    violations: list[Violation],
    chapter_15_funcs: list[clang.cindex.Cursor],
    unwrap_expr: Callable[[clang.cindex.Cursor], clang.cindex.Cursor | None],
    is_pointer_or_reference_kind: Callable[[Any], bool],
    get_returned_decl: Callable[
        [clang.cindex.Cursor], clang.cindex.Cursor | None
    ],
    cpp_entity_decl_lines: dict[tuple[Any, Any], list[tuple[int, str]]],
    rule_2_10_1_enabled: bool,
    cpp_typo_scope_names: dict[Any, dict[Any, dict[Any, tuple[str, int]]]],
    cpp_static_duration_names: dict[
        str, list[tuple[clang.cindex.Cursor, Any]]
    ],
    cpp_defined_functions: dict[Any, clang.cindex.Cursor],
    cpp_function_linkage: dict[Any, Any],
    cpp_called_functions: set[str],
    cpp_void_func_has_side_effect: dict[Any, bool],
    cpp_var_decls: dict[Any, clang.cindex.Cursor],
    cpp_var_ref_counts: dict[Any, int],
    is_pod_like_type: Callable[[clang.cindex.Type], bool],
    cpp_known_error_calls_ignored: list[Any],
    logger: logging.Logger,
) -> None:
    # Rule 7-1-1: suggest const for never-modified locals.
    for func in chapter_15_funcs:
        if (
            not func.location.file
            or Path(func.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        local_candidates: dict[int, tuple[str, int]] = {}
        local_modified: set[int] = set()

        def collect_locals(n: clang.cindex.Cursor) -> None:
            if n.kind == CursorKind.VAR_DECL:
                parent = n.semantic_parent or n.lexical_parent
                if parent and parent.kind in (
                    CursorKind.FUNCTION_DECL,
                    CursorKind.CXX_METHOD,
                    CursorKind.CONSTRUCTOR,
                    CursorKind.DESTRUCTOR,
                    CursorKind.COMPOUND_STMT,
                ):
                    t = n.type.get_canonical() if n.type else None
                    if (
                        t
                        and not t.is_const_qualified()
                        and not t.is_volatile_qualified()
                    ):
                        if t.kind not in (
                            TypeKind.POINTER,
                            TypeKind.LVALUEREFERENCE,
                            TypeKind.RVALUEREFERENCE,
                        ):
                            has_initializer = any(
                                c.kind != CursorKind.TYPE_REF
                                for c in n.get_children()
                            )
                            if has_initializer:
                                local_candidates[n.hash] = (
                                    n.spelling,
                                    n.location.line,
                                )
            for c in n.get_children():
                collect_locals(c)

        def collect_modifications(n: clang.cindex.Cursor) -> None:
            if n.kind == CursorKind.BINARY_OPERATOR:
                toks = [t.spelling for t in tuple(n.get_tokens())]
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
                if any(tok in assign_ops for tok in toks):
                    children = list(n.get_children())
                    if children:
                        lhs = unwrap_expr(children[0])
                        if (
                            lhs
                            and lhs.kind == CursorKind.DECL_REF_EXPR
                            and lhs.referenced
                        ):
                            local_modified.add(lhs.referenced.hash)
            elif n.kind == CursorKind.UNARY_OPERATOR:
                toks = [t.spelling for t in tuple(n.get_tokens())]
                if "++" in toks or "--" in toks:
                    children = list(n.get_children())
                    if children:
                        target = unwrap_expr(children[0])
                        if (
                            target
                            and target.kind == CursorKind.DECL_REF_EXPR
                            and target.referenced
                        ):
                            local_modified.add(target.referenced.hash)
            for c in n.get_children():
                collect_modifications(c)

        collect_locals(func)
        for c in func.get_children():
            if c.kind == CursorKind.COMPOUND_STMT:
                collect_modifications(c)

        for var_hash, (var_name, line) in local_candidates.items():
            if var_hash not in local_modified:
                violations.append(
                    Violation(
                        "Rule 7-1-1",
                        f"Variable '{var_name}' is not modified and should be const-qualified.",
                        file_path,
                        line,
                        trigger=var_name,
                    )
                )

    # Rule 7-5-1 / 7-5-3: unsafe return of local/parameter addresses or references.
    for func in chapter_15_funcs:
        ret_type = (
            func.result_type.get_canonical() if func.result_type else None
        )
        if not ret_type or not is_pointer_or_reference_kind(ret_type.kind):
            continue

        for c in func.get_children():
            if c.kind != CursorKind.COMPOUND_STMT:
                continue
            for n in c.walk_preorder():
                if n.kind != CursorKind.RETURN_STMT:
                    continue
                returned_decl = get_returned_decl(n)
                if not returned_decl:
                    continue
                if returned_decl.kind == CursorKind.PARM_DECL:
                    p_t = (
                        returned_decl.type.get_canonical()
                        if returned_decl.type
                        else None
                    )
                    if p_t and is_pointer_or_reference_kind(p_t.kind):
                        violations.append(
                            Violation(
                                "Rule 7-5-3",
                                f"Function returns a pointer/reference derived from parameter '{returned_decl.spelling}'.",
                                file_path,
                                n.location.line,
                                trigger=returned_decl.spelling,
                            )
                        )
                elif returned_decl.kind == CursorKind.VAR_DECL:
                    parent = (
                        returned_decl.semantic_parent
                        or returned_decl.lexical_parent
                    )
                    if parent and parent.kind != CursorKind.TRANSLATION_UNIT:
                        storage = getattr(returned_decl, "storage_class", None)
                        if storage not in (
                            clang.cindex.StorageClass.STATIC,
                            clang.cindex.StorageClass.EXTERN,
                        ):
                            violations.append(
                                Violation(
                                    "Rule 7-5-1",
                                    f"Function returns a pointer/reference to automatic variable '{returned_decl.spelling}'.",
                                    file_path,
                                    n.location.line,
                                    trigger=returned_decl.spelling,
                                )
                            )

    # Rule 3-2-3: A type, object or function shall only be declared once in one translation unit.
    for (_, _), entries in cpp_entity_decl_lines.items():
        if len(entries) > 1:
            first_line, name = entries[0]
            violations.append(
                Violation(
                    "Rule 3-2-3",
                    (
                        f"Entity '{name}' is declared multiple times in this translation unit "
                        f"(first at line {first_line})."
                    ),
                    file_path,
                    entries[1][0],
                    trigger=name,
                )
            )

    # Rule 2-10-1: typographic ambiguity in same scope (configurable heuristic).
    if rule_2_10_1_enabled:
        for _, norm_map in cpp_typo_scope_names.items():
            for _, usr_map in norm_map.items():
                unique_names = sorted({entry[0] for entry in usr_map.values()})
                if len(unique_names) <= 1:
                    continue
                for _, (name, line) in usr_map.items():
                    others = [n for n in unique_names if n != name]
                    if not others:
                        continue
                    violations.append(
                        Violation(
                            "Rule 2-10-1",
                            (
                                "Different identifiers shall be typographically unambiguous: "
                                f"'{name}' vs '{others[0]}'."
                            ),
                            file_path,
                            line,
                            trigger=name,
                        )
                    )

    # 2-10-5: Identifier name reuse for non-member static-storage object/function.
    for name, static_entries in cpp_static_duration_names.items():
        unique_usrs = {usr for _, usr in static_entries}
        if len(unique_usrs) > 1:
            for node, _ in static_entries:
                violations.append(
                    Violation(
                        "Rule 2-10-5",
                        f"The identifier name '{name}' of a non-member object/function with static storage duration should not be reused.",
                        file_path,
                        node.location.line,
                        trigger=name,
                    )
                )

    # 0-1-10: Every defined function should be called at least once (heuristic, TU-local).
    for defined_func in cpp_defined_functions.values():
        name = defined_func.spelling or ""
        if not name or name == "main":
            continue
        if name.startswith("operator") or name.startswith("~"):
            continue
        # Accept both internal and external linkage for project examples;
        # this keeps rule coverage aligned with MISRA sample suites.
        if name not in cpp_called_functions:
            violations.append(
                Violation(
                    "Rule 0-1-10",
                    f"Every defined function should be called at least once: '{name}'.",
                    file_path,
                    defined_func.location.line,
                    detector="cpp-ch0-heuristic",
                    trigger=name,
                )
            )

    # 0-1-8: Void functions should have external side effects (heuristic).
    for func_hash, has_side_effect in cpp_void_func_has_side_effect.items():
        maybe_func = cpp_defined_functions.get(func_hash)
        if not maybe_func or (maybe_func.spelling or "") == "main":
            continue
        # Accept both internal and external linkage for project examples.
        if not _has_executable_statement(maybe_func):
            continue
        if not has_side_effect:
            violations.append(
                Violation(
                    "Rule 0-1-8",
                    f"Function '{maybe_func.spelling}' has void return type and appears to have no external side effects.",
                    file_path,
                    maybe_func.location.line,
                    detector="cpp-ch0-heuristic",
                    trigger=maybe_func.spelling,
                )
            )

    # 0-1-3 / 0-1-12 / 0-1-4: Variable-use checks.
    for var_hash, var_decl in cpp_var_decls.items():
        if not var_decl or var_decl.kind != CursorKind.VAR_DECL:
            continue
        if (
            not var_decl.location.file
            or Path(var_decl.location.file.name).resolve()
            != file_path.resolve()
        ):
            continue
        refs = cpp_var_ref_counts.get(var_hash, 0)
        parent = var_decl.semantic_parent or var_decl.lexical_parent
        parent_kind = parent.kind if parent else None
        is_local = parent_kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.DESTRUCTOR,
            CursorKind.COMPOUND_STMT,
        )
        is_global = parent_kind == CursorKind.TRANSLATION_UNIT

        if refs == 0:
            if is_local:
                violations.append(
                    Violation(
                        "Rule 0-1-9",
                        f"A project shall not contain unused variables: '{var_decl.spelling}'.",
                        file_path,
                        var_decl.location.line,
                        detector="cpp-ch0-heuristic",
                        trigger=var_decl.spelling,
                    )
                )
                violations.append(
                    Violation(
                        "Rule 0-1-12",
                        f"There shall be no unused variables in functions: '{var_decl.spelling}'.",
                        file_path,
                        var_decl.location.line,
                        detector="cpp-ch0-heuristic",
                        trigger=var_decl.spelling,
                    )
                )
            elif is_global:
                violations.append(
                    Violation(
                        "Rule 0-1-3",
                        f"A project shall not contain unused variables: '{var_decl.spelling}'.",
                        file_path,
                        var_decl.location.line,
                        detector="cpp-ch0-heuristic",
                        trigger=var_decl.spelling,
                    )
                )

        if (
            is_local
            and refs == 1
            and is_pod_like_type(var_decl.type)
            and not var_decl.type.is_volatile_qualified()
            and var_decl.type.get_canonical().kind != TypeKind.POINTER
        ):
            violations.append(
                Violation(
                    "Rule 0-1-4",
                    f"Non-volatile POD variable '{var_decl.spelling}' has only one use.",
                    file_path,
                    var_decl.location.line,
                    detector="cpp-ch0-heuristic",
                    trigger=var_decl.spelling,
                )
            )

    # 0-3-2: Ignored return values from known error-reporting APIs (heuristic).
    for line, call_name in cpp_known_error_calls_ignored:
        violations.append(
            Violation(
                "Rule 0-3-2",
                f"Error information from '{call_name}' appears to be ignored.",
                file_path,
                line,
                detector="cpp-ch0-heuristic",
                trigger=call_name,
            )
        )

    # 0-3-1 is process-oriented; this tool itself is a static analysis step.
    logger.debug(
        "Rule 0-3-1 is treated as process-compliance and not emitted as a source-level violation."
    )
    # 17-0-4 is also process/integration-oriented and not a direct source-level diagnostic.
    logger.debug(
        "Rule 17-0-4 is treated as process-compliance and not emitted as a source-level violation."
    )
    # 15-3-1 is lifecycle/process-oriented (startup/termination boundaries), kept as process compliance.
    logger.debug(
        "Rule 15-3-1 is treated as process-compliance and not emitted as a source-level violation."
    )
