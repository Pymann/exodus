from pathlib import Path
from typing import Any, Callable

import clang.cindex
from clang.cindex import CursorKind

from exodus.tools.analyze.misra_rules import Violation


def apply_cpp_ch7_8_rules(
    *,
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
    iter_base_specs: Callable[[clang.cindex.Cursor], Any],
    method_has_default_argument: Callable[[clang.cindex.Cursor], bool],
    cpp_scope_decl_lines: dict[Any, dict[str, list[int]]],
    cpp_scope_using_lines: dict[Any, dict[str, list[int]]],
    chapter_15_funcs: list[clang.cindex.Cursor],
    cpp_func_has_asm: dict[int, bool],
    cpp_func_asm_lines: dict[int, list[int]],
) -> None:
    # Rule 8-3-1: overriding virtual functions should not introduce default args
    # unless they are kept compatible with base declarations.
    for node in tu.cursor.walk_preorder():
        if node.kind != CursorKind.CXX_METHOD:
            continue
        if (
            not node.location.file
            or Path(node.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        if not method_has_default_argument(node):
            continue
        parent = node.semantic_parent or node.lexical_parent
        if not parent or parent.kind not in (
            CursorKind.CLASS_DECL,
            CursorKind.STRUCT_DECL,
        ):
            continue
        try:
            arg_count = len(list(node.get_arguments() or ()))
        except Exception:
            arg_count = 0
        overrides = False
        for base_decl, _ in iter_base_specs(parent):
            for member in base_decl.get_children():
                if member.kind != CursorKind.CXX_METHOD:
                    continue
                if member.spelling != node.spelling:
                    continue
                try:
                    base_arg_count = len(list(member.get_arguments() or ()))
                except Exception:
                    base_arg_count = -1
                if base_arg_count == arg_count:
                    overrides = True
                    break
            if overrides:
                break
        if overrides:
            violations.append(
                Violation(
                    "Rule 8-3-1",
                    "An overriding virtual function should not introduce default arguments unless they are identical to the overridden declaration.",
                    file_path,
                    node.location.line,
                    trigger=node.spelling,
                )
            )

    # Rule 7-3-5: declarations in a namespace scope shall not straddle a using-declaration.
    for scope_hash, name_to_decl_lines in cpp_scope_decl_lines.items():
        using_map = cpp_scope_using_lines.get(scope_hash, {})
        if not using_map:
            continue
        for name, decl_lines in name_to_decl_lines.items():
            if len(decl_lines) < 2:
                continue
            using_lines = using_map.get(name, [])
            if not using_lines:
                continue
            low = min(decl_lines)
            high = max(decl_lines)
            for uline in using_lines:
                if low < uline < high:
                    violations.append(
                        Violation(
                            "Rule 7-3-5",
                            f"Multiple declarations for '{name}' in the same namespace straddle a using-declaration.",
                            file_path,
                            uline,
                            trigger=name,
                        )
                    )

    # Rule 7-4-3: assembly language should be encapsulated and isolated.
    for func in chapter_15_funcs:
        if not cpp_func_has_asm.get(func.hash):
            continue
        compound = None
        for c in func.get_children():
            if c.kind == CursorKind.COMPOUND_STMT:
                compound = c
                break
        if not compound:
            continue
        stmts = list(compound.get_children())
        if len(stmts) > 1:
            asm_line = cpp_func_asm_lines.get(func.hash, [func.location.line])[
                0
            ]
            violations.append(
                Violation(
                    "Rule 7-4-3",
                    "Assembly language shall be encapsulated and isolated.",
                    file_path,
                    asm_line,
                    trigger=func.spelling,
                )
            )
