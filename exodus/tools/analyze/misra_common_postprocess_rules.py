from pathlib import Path
from typing import Any, Callable

import clang.cindex
from clang.cindex import CursorKind, TypeKind

from exodus.tools.analyze.misra_rules import Violation


def apply_common_postprocess_rules(
    *,
    file_path: Path,
    violations: list[Violation],
    chapter_15_funcs: list[clang.cindex.Cursor],
    is_cpp_file: bool,
    is_essentially_boolean: Callable[[clang.cindex.Cursor], bool],
    unwrap_expr: (
        Callable[[clang.cindex.Cursor], clang.cindex.Cursor | None] | None
    ),
) -> None:
    def _cursor_text(cur: clang.cindex.Cursor, max_len: int = 160) -> str:
        try:
            toks = [t.spelling for t in tuple(cur.get_tokens())]
        except Exception:
            toks = []
        text = " ".join(toks).strip()
        if len(text) > max_len:
            text = text[: max_len - 3] + "..."
        return text

    # Post-process Chapter 16 rules per function.
    for func in chapter_15_funcs:

        def walk_switches(n: clang.cindex.Cursor) -> None:
            if n.kind == CursorKind.SWITCH_STMT:
                children = list(n.get_children())
                if children:
                    switch_not_well_formed = False
                    # Rule 16.7: A switch-expression shall not have essentially Boolean type.
                    cond = children[0]
                    if is_essentially_boolean(cond):
                        violations.append(
                            Violation(
                                "Rule 16.7",
                                "A switch-expression shall not have essentially Boolean type",
                                file_path,
                                cond.location.line,
                                trigger=_cursor_text(cond),
                            )
                        )

                    # Rule 16.1: no code before first case/default.
                    if len(children) > 1:
                        body = children[1]
                        if body.kind == CursorKind.COMPOUND_STMT:
                            body_children = list(body.get_children())
                            if body_children:
                                first_stmt = body_children[0]
                                if first_stmt.kind not in (
                                    CursorKind.CASE_STMT,
                                    CursorKind.DEFAULT_STMT,
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 16.1",
                                            "All switch statements shall be well-formed (code before first case/default)",
                                            file_path,
                                            first_stmt.location.line,
                                            trigger=_cursor_text(first_stmt),
                                        )
                                    )
                                    switch_not_well_formed = True

                        # Rule 16.2: nested labels only in switch body.
                        def check_nested_labels(
                            stmt: clang.cindex.Cursor, allowed: bool
                        ) -> bool:
                            if stmt.kind in (
                                CursorKind.CASE_STMT,
                                CursorKind.DEFAULT_STMT,
                            ):
                                if not allowed:
                                    violations.append(
                                        Violation(
                                            "Rule 16.2",
                                            "A switch label shall only be used when the most closely-enclosing compound statement is the body of a switch statement",
                                            file_path,
                                            stmt.location.line,
                                            trigger=_cursor_text(stmt),
                                        )
                                    )
                                    return True
                                for c in stmt.get_children():
                                    if check_nested_labels(c, allowed):
                                        return True
                                return False
                            if stmt.kind == CursorKind.SWITCH_STMT:
                                return False
                            if stmt.kind == CursorKind.COMPOUND_STMT:
                                for c in stmt.get_children():
                                    if check_nested_labels(c, False):
                                        return True
                                return False
                            for c in stmt.get_children():
                                if check_nested_labels(c, allowed):
                                    return True
                            return False

                        if body.kind == CursorKind.COMPOUND_STMT:
                            for c in body.get_children():
                                if check_nested_labels(c, True):
                                    switch_not_well_formed = True

                        # Rule 16.5: default first or last.
                        if body.kind == CursorKind.COMPOUND_STMT:
                            labels = [
                                c
                                for c in body.get_children()
                                if c.kind
                                in (
                                    CursorKind.CASE_STMT,
                                    CursorKind.DEFAULT_STMT,
                                )
                            ]
                            if labels:
                                default_positions = [
                                    i
                                    for i, c in enumerate(labels)
                                    if c.kind == CursorKind.DEFAULT_STMT
                                ]
                                if default_positions and not (
                                    0 in default_positions
                                    or (len(labels) - 1) in default_positions
                                ):
                                    violations.append(
                                        Violation(
                                            "Rule 16.5",
                                            "A default label shall appear as either the first or the last switch label of a switch statement.",
                                            file_path,
                                            labels[
                                                default_positions[0]
                                            ].location.line,
                                            trigger=_cursor_text(
                                                labels[default_positions[0]]
                                            ),
                                        )
                                    )
                                    switch_not_well_formed = True

                    if is_cpp_file and switch_not_well_formed:
                        violations.append(
                            Violation(
                                "Rule 6-4-2",
                                "All switch statements shall be well-formed.",
                                file_path,
                                n.location.line,
                                trigger=_cursor_text(n),
                            )
                        )

            for c in n.get_children():
                walk_switches(c)

        walk_switches(func)

    # Post-process Chapter 17 rules per function.
    for func in chapter_15_funcs:

        def walk_func_stmts(n: clang.cindex.Cursor) -> None:
            if n.kind == CursorKind.COMPOUND_STMT:
                # Rule 17.7: discarded non-void return value.
                for stmt in n.get_children():
                    if stmt.kind == CursorKind.CALL_EXPR:
                        # Rule 17.3: implicit function declaration / unresolved direct call target.
                        # We only flag direct identifier calls where no declaration can be resolved.
                        # (Function-pointer calls are intentionally excluded.)
                        call_children = list(stmt.get_children())
                        if call_children:
                            callee = (
                                unwrap_expr(call_children[0])
                                if unwrap_expr
                                else call_children[0]
                            )
                            if (
                                callee is not None
                                and callee.kind == CursorKind.DECL_REF_EXPR
                                and not callee.referenced
                                and callee.spelling
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 17.3",
                                        f"A function shall not be declared implicitly: '{callee.spelling}'",
                                        file_path,
                                        stmt.location.line,
                                        trigger=_cursor_text(stmt),
                                    )
                                )

                        if stmt.type and stmt.type.kind != TypeKind.VOID:
                            toks = [t.spelling for t in stmt.get_tokens()]
                            if (
                                toks
                                and toks[0] == "("
                                and len(toks) > 2
                                and toks[1] == "void"
                                and toks[2] == ")"
                            ):
                                pass
                            else:
                                violations.append(
                                    Violation(
                                        "Rule 17.7",
                                        "The value returned by a function having non-void return type shall be used",
                                        file_path,
                                        stmt.location.line,
                                        trigger=_cursor_text(stmt),
                                    )
                                )

            # Rule 17.8: parameter should not be modified.
            if n.kind == CursorKind.BINARY_OPERATOR:
                toks = [t.spelling for t in n.get_tokens()]
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
                    if assign_op in toks:
                        is_assign = True
                        break
                if is_assign:
                    children = list(n.get_children())
                    if children:
                        lhs = children[0]
                        if (
                            lhs.kind == CursorKind.DECL_REF_EXPR
                            and lhs.referenced
                            and lhs.referenced.kind == CursorKind.PARM_DECL
                        ):
                            violations.append(
                                Violation(
                                    "Rule 17.8",
                                    f"A function parameter should not be modified: '{lhs.referenced.spelling}'",
                                    file_path,
                                    n.location.line,
                                    trigger=_cursor_text(n),
                                )
                            )
            elif n.kind == CursorKind.UNARY_OPERATOR:
                toks = [t.spelling for t in n.get_tokens()]
                if "++" in toks or "--" in toks:
                    children = list(n.get_children())
                    if children:
                        lhs = children[0]
                        if (
                            lhs.kind == CursorKind.DECL_REF_EXPR
                            and lhs.referenced
                            and lhs.referenced.kind == CursorKind.PARM_DECL
                        ):
                            violations.append(
                                Violation(
                                    "Rule 17.8",
                                    f"A function parameter should not be modified: '{lhs.referenced.spelling}'",
                                    file_path,
                                    n.location.line,
                                    trigger=_cursor_text(n),
                                )
                            )

            for c in n.get_children():
                walk_func_stmts(c)

        for c in func.get_children():
            if c.kind == CursorKind.COMPOUND_STMT:
                walk_func_stmts(c)

    # Rule 9.1 (heuristic) intentionally disabled here.
    # The previous local read-before-init scan had a high false-positive rate
    # without proper control/data-flow analysis. Rule 9.1 is still reported via
    # compiler diagnostics when available.
