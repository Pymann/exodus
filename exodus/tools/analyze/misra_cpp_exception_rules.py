import re
from pathlib import Path
from typing import Any

import clang.cindex
from clang.cindex import CursorKind, TypeKind

from exodus.tools.analyze.misra_rules import Violation


def apply_cpp_ch15_rules(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
    unwrap_expr: Any,
    record_decl_from_type: Any,
    is_derived_from: Any,
) -> None:
    def _cursor_text(cur: clang.cindex.Cursor, max_len: int = 240) -> str:
        try:
            toks = [t.spelling for t in tuple(cur.get_tokens())]
        except Exception:
            toks = []
        text = " ".join(toks).strip()
        if len(text) > max_len:
            text = text[: max_len - 3] + "..."
        return text

    def _normalize_type_name(txt: str) -> str:
        s = (txt or "").strip()
        if not s:
            return ""
        s = s.replace("const ", "").replace("volatile ", "")
        s = s.replace("struct ", "").replace("class ", "").replace("enum ", "")
        s = s.replace("::", "")
        s = re.sub(r"\s+", "", s)
        return s

    def _function_key(cur: clang.cindex.Cursor) -> tuple[str, str, int]:
        parent = cur.semantic_parent or cur.lexical_parent
        parent_name = (
            parent.spelling
            if parent
            and parent.kind in (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL)
            else ""
        )
        try:
            argc = len(list(cur.get_arguments() or ()))
        except Exception:
            argc = -1
        return (parent_name, cur.spelling or "", argc)

    def _extract_decl_exception_spec(
        cur: clang.cindex.Cursor,
    ) -> tuple[bool, tuple[str, ...]]:
        try:
            toks = [t.spelling for t in tuple(cur.get_tokens())]
        except Exception:
            toks = []
        if not toks:
            return (False, ())

        # Only inspect declaration/signature prefix.
        sig = []
        for tok in toks:
            if tok in ("{", ";"):
                break
            sig.append(tok)
        if not sig:
            return (False, ())

        i = 0
        while i < len(sig):
            if sig[i] != "throw":
                i += 1
                continue
            j = i + 1
            if j >= len(sig) or sig[j] != "(":
                i += 1
                continue
            j += 1
            depth = 1
            spec_tokens = []
            while j < len(sig):
                tok = sig[j]
                if tok == "(":
                    depth += 1
                elif tok == ")":
                    depth -= 1
                    if depth == 0:
                        break
                spec_tokens.append(tok)
                j += 1

            # Split by commas at top-level.
            items = []
            cur_item: list[str] = []
            inner_depth = 0
            for tok in spec_tokens:
                if tok == "(":
                    inner_depth += 1
                elif tok == ")":
                    if inner_depth > 0:
                        inner_depth -= 1
                if tok == "," and inner_depth == 0:
                    item = "".join(cur_item).strip()
                    if item:
                        items.append(item)
                    cur_item = []
                    continue
                cur_item.append(tok)
            tail = "".join(cur_item).strip()
            if tail:
                items.append(tail)
            return (True, tuple(sorted(items)))
        return (False, ())

    def _line_in_any_range(
        line_no: int, ranges: list[tuple[int, int]]
    ) -> bool:
        for lo, hi in ranges:
            if lo <= line_no <= hi:
                return True
        return False

    try_catch_ranges = []
    label_lines = {}
    gotos = []  # list[(line, target_label)]
    function_decl_specs: dict[
        tuple[str, str, int], list[tuple[int, bool, tuple[str, ...]]]
    ] = {}
    function_def_specs = []  # list[(cursor, has_spec, spec_tuple)]

    # Rule 15-*: exception handling checks.
    for node in tu.cursor.walk_preorder():
        if (
            not node.location.file
            or Path(node.location.file.name).resolve() != file_path.resolve()
        ):
            continue

        if node.kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.DESTRUCTOR,
        ):
            key = _function_key(node)
            has_spec, spec = _extract_decl_exception_spec(node)
            function_decl_specs.setdefault(key, []).append(
                (node.location.line, has_spec, spec)
            )
            try:
                is_defn = bool(node.is_definition())
            except Exception:
                is_defn = False
            if is_defn:
                function_def_specs.append((node, has_spec, spec))

        if node.kind in (CursorKind.CXX_TRY_STMT, CursorKind.CXX_CATCH_STMT):
            try:
                lo = int(node.extent.start.line)
                hi = int(node.extent.end.line)
            except Exception:
                lo = hi = node.location.line
            if lo > 0 and hi >= lo:
                try_catch_ranges.append((lo, hi))

        if node.kind == CursorKind.LABEL_STMT and node.spelling:
            label_lines[node.spelling] = node.location.line

        if node.kind == CursorKind.GOTO_STMT:
            toks = [t.spelling for t in tuple(node.get_tokens())]
            target = toks[1] if len(toks) >= 2 else ""
            if target:
                gotos.append((node.location.line, target))

        if node.kind == CursorKind.CXX_THROW_EXPR:
            throw_children = list(node.get_children())
            if not throw_children:
                # Rule 15-1-3: empty throw only inside catch body.
                anc = node.lexical_parent or node.semantic_parent
                inside_catch = False
                while anc:
                    if anc.kind == CursorKind.CXX_CATCH_STMT:
                        inside_catch = True
                        break
                    anc = anc.lexical_parent or anc.semantic_parent
                if not inside_catch:
                    violations.append(
                        Violation(
                            "Rule 15-1-3",
                            "An empty throw (re-throw) shall only be used in the compound-statement of a catch handler.",
                            file_path,
                            node.location.line,
                            trigger="throw;",
                        )
                    )
            else:
                expr = unwrap_expr(throw_children[-1])
                et = expr.type.get_canonical() if expr and expr.type else None
                # Rule 15-0-2: exception object should not have pointer type.
                if et and et.kind == TypeKind.POINTER:
                    violations.append(
                        Violation(
                            "Rule 15-0-2",
                            "An exception object should not have pointer type.",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(expr) or et.spelling,
                        )
                    )
                # Rule 15-0-1 (heuristic): primitive/pointer throws are likely non-domain error signaling.
                if et and et.kind in (
                    TypeKind.POINTER,
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
                ):
                    violations.append(
                        Violation(
                            "Rule 15-0-1",
                            "Exceptions should be used for error handling; throwing primitive/pointer types is not considered robust error-domain signaling.",
                            file_path,
                            node.location.line,
                            trigger=et.spelling,
                        )
                    )
                # Rule 15-1-2: NULL shall not be thrown explicitly.
                toks = [t.spelling for t in tuple(node.get_tokens())]
                null_like = any(
                    tok in {"NULL", "nullptr", "__null"} for tok in toks
                )
                if not null_like and expr:
                    ktxt = str(expr.kind)
                    if (
                        "GNU_NULL_EXPR" in ktxt
                        or expr.kind == CursorKind.CXX_NULL_PTR_LITERAL_EXPR
                    ):
                        null_like = True
                if null_like:
                    violations.append(
                        Violation(
                            "Rule 15-1-2",
                            "NULL shall not be thrown explicitly.",
                            file_path,
                            node.location.line,
                            trigger=_cursor_text(expr) or "NULL",
                        )
                    )
                # Rule 15-1-1: throw expression should not itself cause exception.
                if expr and any(
                    ch.kind == CursorKind.CALL_EXPR
                    for ch in expr.walk_preorder()
                ):
                    trigger_text = _cursor_text(expr) or _cursor_text(node)
                    violations.append(
                        Violation(
                            "Rule 15-1-1",
                            "The assignment expression of a throw statement shall not itself cause an exception to be thrown.",
                            file_path,
                            node.location.line,
                            trigger=trigger_text,
                        )
                    )
                # Rule 15-5-1 handled robustly in destructor body scan.

        elif node.kind == CursorKind.CXX_TRY_STMT:
            catches = [
                c
                for c in node.get_children()
                if c.kind == CursorKind.CXX_CATCH_STMT
            ]
            if not catches:
                continue

            # Rule 15-3-2: should have a catch-all handler.
            has_catch_all = False
            catch_types = []  # list[(idx, record_decl)]
            for idx, c in enumerate(catches):
                var_decl = None
                for ch in c.get_children():
                    if ch.kind == CursorKind.VAR_DECL:
                        var_decl = ch
                        break
                if var_decl is None:
                    has_catch_all = True
                    continue

                ctype = (
                    var_decl.type.get_canonical() if var_decl.type else None
                )
                if ctype and ctype.kind not in (
                    TypeKind.LVALUEREFERENCE,
                    TypeKind.RVALUEREFERENCE,
                ):
                    violations.append(
                        Violation(
                            "Rule 15-3-4",
                            "Each exception handler shall catch by reference.",
                            file_path,
                            c.location.line,
                            trigger=var_decl.spelling,
                        )
                    )
                rec = record_decl_from_type(ctype)
                if rec:
                    catch_types.append((idx, rec, c.location.line, ctype))
                    # Rule 15-3-5: class type should be caught by reference or pointer.
                    if ctype and ctype.kind not in (
                        TypeKind.LVALUEREFERENCE,
                        TypeKind.RVALUEREFERENCE,
                        TypeKind.POINTER,
                    ):
                        violations.append(
                            Violation(
                                "Rule 15-3-5",
                                "A class type exception shall always be caught by reference or pointer.",
                                file_path,
                                c.location.line,
                                trigger=var_decl.spelling,
                            )
                        )

            if not has_catch_all:
                violations.append(
                    Violation(
                        "Rule 15-3-2",
                        "There should be at least one exception handler to catch all otherwise unhandled exceptions.",
                        file_path,
                        node.location.line,
                        trigger="try",
                    )
                )

            # Rule 15-3-6 / 15-3-7: handler order should be derived -> base.
            for i in range(len(catch_types)):
                for j in range(i + 1, len(catch_types)):
                    _, rec_i, line_i, _ = catch_types[i]
                    _, rec_j, line_j, _ = catch_types[j]
                    if is_derived_from(rec_j, rec_i):
                        # Base before derived.
                        violations.append(
                            Violation(
                                "Rule 15-3-6",
                                "Exception handlers shall appear in order from most derived exception to least derived.",
                                file_path,
                                line_i,
                                trigger=rec_i.spelling,
                            )
                        )
                        violations.append(
                            Violation(
                                "Rule 15-3-7",
                                "A handler for a base class shall not be followed by a handler for a derived class.",
                                file_path,
                                line_j,
                                trigger=rec_j.spelling,
                            )
                        )

        # Rule 15-3-3: ctor/dtor function-try-block handlers shall not reference non-static members.
        if node.kind in (CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR):
            try_stmts = [
                c
                for c in node.get_children()
                if c.kind == CursorKind.CXX_TRY_STMT
            ]
            if not try_stmts:
                continue
            for ts in try_stmts:
                for c in ts.get_children():
                    if c.kind != CursorKind.CXX_CATCH_STMT:
                        continue
                    bad_ref_line = None
                    for inner in c.walk_preorder():
                        if (
                            inner.kind == CursorKind.MEMBER_REF_EXPR
                            and inner.referenced
                        ):
                            if inner.referenced.kind == CursorKind.FIELD_DECL:
                                bad_ref_line = inner.location.line
                                break
                    if bad_ref_line:
                        violations.append(
                            Violation(
                                "Rule 15-3-3",
                                "Handlers of a function-try-block implementation of a class constructor or destructor shall not reference non-static members.",
                                file_path,
                                bad_ref_line,
                                trigger=node.spelling,
                            )
                        )

    # Rule 15-0-3: no transfer into try/catch via goto/switch.
    for goto_line, target_label in gotos:
        label_line = label_lines.get(target_label)
        if not label_line:
            continue
        if _line_in_any_range(
            label_line, try_catch_ranges
        ) and not _line_in_any_range(goto_line, try_catch_ranges):
            violations.append(
                Violation(
                    "Rule 15-0-3",
                    "Control shall not be transferred into a try or catch block using a goto statement.",
                    file_path,
                    goto_line,
                    trigger=target_label,
                )
            )

    # Rule 15-4-1: exception-specification consistency across declarations.
    for _, entries in function_decl_specs.items():
        has_any_spec = any(has_spec for _, has_spec, _ in entries)
        if not has_any_spec:
            continue
        baseline = None
        for _, has_spec, spec in entries:
            if has_spec:
                baseline = spec
                break
        if baseline is None:
            continue
        for line, has_spec, spec in entries:
            if (not has_spec) or spec != baseline:
                violations.append(
                    Violation(
                        "Rule 15-4-1",
                        "If a function declaration includes an exception-specification, all declarations of that function shall use the same set of type-ids.",
                        file_path,
                        line,
                        trigger=str(spec),
                    )
                )

    # Rule 15-5-2 / 15-5-3: throw types must satisfy declared exception-specification.
    for fn, has_spec, spec in function_def_specs:
        if not has_spec:
            continue
        normalized_allowed = tuple(_normalize_type_name(x) for x in spec if x)
        allow_any = any(x == "..." for x in normalized_allowed)
        if allow_any:
            continue

        for n in fn.walk_preorder():
            if n.kind != CursorKind.CXX_THROW_EXPR:
                continue
            throw_children = list(n.get_children())
            if not throw_children:
                continue
            expr = unwrap_expr(throw_children[-1])
            expr_type = (
                expr.type.get_canonical().spelling
                if expr and expr.type
                else ""
            )
            thrown_norm = _normalize_type_name(expr_type)
            if not thrown_norm:
                continue
            if thrown_norm in normalized_allowed:
                continue

            violations.append(
                Violation(
                    "Rule 15-5-2",
                    "A function with an exception-specification shall only throw exceptions of the indicated type(s).",
                    file_path,
                    n.location.line,
                    trigger=thrown_norm,
                )
            )
            violations.append(
                Violation(
                    "Rule 15-5-3",
                    "The terminate() function shall not be called implicitly (exception-specification mismatch).",
                    file_path,
                    n.location.line,
                    trigger=thrown_norm,
                )
            )
