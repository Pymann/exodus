import re
from pathlib import Path
from typing import Any, Callable

import clang.cindex
from clang.cindex import CursorKind, TypeKind

from exodus.tools.analyze.misra_rules import Violation


def _extract_ctor_initializer_targets(
    ctor_cursor: clang.cindex.Cursor,
) -> list[str]:
    """Best-effort extraction of constructor initializer target names."""
    try:
        toks = [t.spelling for t in tuple(ctor_cursor.get_tokens())]
    except Exception:
        return []
    if not toks:
        return []

    paren_depth = 0
    seen_param_list = False
    param_end = -1
    for i, tok in enumerate(toks):
        if tok == "(":
            paren_depth += 1
            seen_param_list = True
        elif tok == ")" and seen_param_list:
            paren_depth -= 1
            if paren_depth == 0:
                param_end = i
                break
    if param_end < 0:
        return []

    colon_idx = -1
    for i in range(param_end + 1, len(toks)):
        if toks[i] == ":":
            colon_idx = i
            break
        if toks[i] in ("{", ";"):
            return []
    if colon_idx < 0:
        return []

    segment = []
    for i in range(colon_idx + 1, len(toks)):
        if toks[i] in ("{", "try", ";"):
            break
        segment.append(toks[i])

    names = []
    i = 0
    n = len(segment)
    while i < n:
        while i < n and segment[i] == ",":
            i += 1
        if i >= n:
            break

        target_tokens = []
        while i < n and segment[i] not in ("(", "{", ","):
            target_tokens.append(segment[i])
            i += 1
        if target_tokens:
            for tok in reversed(target_tokens):
                if tok and (tok[0].isalpha() or tok[0] == "_"):
                    names.append(tok)
                    break

        depth_par = 0
        depth_brace = 0
        while i < n:
            tok = segment[i]
            if tok == "(":
                depth_par += 1
            elif tok == ")":
                if depth_par > 0:
                    depth_par -= 1
            elif tok == "{":
                depth_brace += 1
            elif tok == "}":
                if depth_brace > 0:
                    depth_brace -= 1
            elif tok == "," and depth_par == 0 and depth_brace == 0:
                i += 1
                break
            i += 1

    return names


def apply_cpp_ch11_12_rules(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
    iter_base_specs: Callable[
        [clang.cindex.Cursor], list[tuple[clang.cindex.Cursor, bool]]
    ],
    is_fundamental_kind: Callable[[Any], bool],
) -> None:
    # Rule 11-0-1 / 12-* class and special-member checks.
    for cls in tu.cursor.walk_preorder():
        if cls.kind not in (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL):
            continue
        if (
            not cls.location.file
            or Path(cls.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        try:
            if not cls.is_definition():
                continue
        except Exception:
            pass

        # Rule 11-0-1: member data in non-POD class types shall be private.
        has_non_pod_feature = False
        try:
            has_non_pod_feature = len(iter_base_specs(cls)) > 0
        except Exception:
            has_non_pod_feature = False
        for m in cls.get_children():
            if m.kind in (
                CursorKind.CXX_METHOD,
                CursorKind.CONSTRUCTOR,
                CursorKind.DESTRUCTOR,
            ):
                has_non_pod_feature = True
                break
        if has_non_pod_feature:
            for m in cls.get_children():
                if m.kind != CursorKind.FIELD_DECL:
                    continue
                access = getattr(
                    m, "access_specifier", clang.cindex.AccessSpecifier.INVALID
                )
                if access != clang.cindex.AccessSpecifier.PRIVATE:
                    violations.append(
                        Violation(
                            "Rule 11-0-1",
                            "Member data in non-POD class types shall be private.",
                            file_path,
                            m.location.line,
                            trigger=m.spelling,
                        )
                    )

        # Rule 12-8-2: copy assignment in abstract class shall be protected/private.
        is_abstract = False
        try:
            is_abstract = bool(cls.is_abstract_record())
        except Exception:
            is_abstract = False
        if is_abstract:
            for m in cls.get_children():
                if m.kind != CursorKind.CXX_METHOD:
                    continue
                if m.spelling != "operator=":
                    continue
                access = getattr(
                    m, "access_specifier", clang.cindex.AccessSpecifier.INVALID
                )
                if access == clang.cindex.AccessSpecifier.PUBLIC:
                    violations.append(
                        Violation(
                            "Rule 12-8-2",
                            "The copy assignment operator shall be declared protected or private in an abstract class.",
                            file_path,
                            m.location.line,
                            trigger=m.spelling,
                        )
                    )

    # Rule 12-1-1 / 12-1-3: constructor/destructor checks.
    for fn in tu.cursor.walk_preorder():
        if fn.kind not in (CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR):
            continue
        if (
            not fn.location.file
            or Path(fn.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        if not fn.is_definition():
            continue

        if fn.kind == CursorKind.CONSTRUCTOR:
            parent = fn.semantic_parent or fn.lexical_parent
            parent_name = parent.spelling if parent else ""
            base_names = set()
            if parent:
                try:
                    for base_decl, _ in iter_base_specs(parent):
                        if base_decl and base_decl.spelling:
                            base_names.add(base_decl.spelling)
                except Exception:
                    pass
            member_names = set()
            if parent:
                for m in parent.get_children():
                    if m.kind == CursorKind.FIELD_DECL and m.spelling:
                        member_names.add(m.spelling)

            init_targets = set(_extract_ctor_initializer_targets(fn))

            # Rule 12-1-2: constructors should explicitly call all direct/virtual base ctors.
            missing_bases = sorted(
                name
                for name in base_names
                if name and name not in init_targets
            )
            if missing_bases:
                violations.append(
                    Violation(
                        "Rule 12-1-2",
                        (
                            "All constructors of a class should explicitly call a constructor for all "
                            f"immediate/virtual base classes (missing: {', '.join(missing_bases)})."
                        ),
                        file_path,
                        fn.location.line,
                        trigger=missing_bases[0],
                    )
                )

            # Rule 12-8-1: copy ctor shall initialize only bases and non-static members.
            try:
                args = list(fn.get_arguments() or ())
            except Exception:
                args = []
            is_copy_ctor = False
            if len(args) == 1 and parent:
                p = args[0]
                pt = p.type.get_canonical() if p.type else None
                if pt and pt.kind in (
                    TypeKind.LVALUEREFERENCE,
                    TypeKind.RVALUEREFERENCE,
                ):
                    try:
                        pointee = pt.get_pointee().get_canonical()
                    except Exception:
                        pointee = None
                    if pointee:
                        try:
                            p_decl = pointee.get_declaration()
                        except Exception:
                            p_decl = None
                        if p_decl and p_decl.hash == parent.hash:
                            is_copy_ctor = True
                        elif pointee.spelling == parent_name:
                            is_copy_ctor = True
            if is_copy_ctor and init_targets:
                allowed = base_names | member_names | {parent_name}
                invalid = sorted(
                    name for name in init_targets if name not in allowed
                )
                if invalid:
                    violations.append(
                        Violation(
                            "Rule 12-8-1",
                            (
                                "A copy constructor shall only initialize its base classes and non-static members "
                                f"(invalid: {', '.join(invalid)})."
                            ),
                            file_path,
                            fn.location.line,
                            trigger=invalid[0],
                        )
                    )

            # Rule 12-1-3: single fundamental-argument constructors should be explicit.
            if len(args) == 1:
                arg_kind = (
                    args[0].type.get_canonical().kind if args[0].type else None
                )
                if is_fundamental_kind(arg_kind):
                    toks = [t.spelling for t in tuple(fn.get_tokens())]
                    if "explicit" not in toks:
                        violations.append(
                            Violation(
                                "Rule 12-1-3",
                                "Constructors callable with a single fundamental argument shall be declared explicit.",
                                file_path,
                                fn.location.line,
                                trigger=fn.spelling,
                            )
                        )
        elif fn.kind == CursorKind.DESTRUCTOR:
            for c in fn.get_children():
                if c.kind != CursorKind.COMPOUND_STMT:
                    continue
                for n in c.walk_preorder():
                    if n.kind == CursorKind.CXX_THROW_EXPR:
                        violations.append(
                            Violation(
                                "Rule 15-5-1",
                                "A class destructor shall not exit with an exception.",
                                file_path,
                                n.location.line,
                                trigger=fn.spelling,
                            )
                        )

        # Rule 12-1-1: dynamic type shall not be used in ctor/dtor body.
        for c in fn.get_children():
            if c.kind != CursorKind.COMPOUND_STMT:
                continue
            for n in c.walk_preorder():
                if n.kind == CursorKind.CALL_EXPR:
                    target = n.referenced
                    if target and target.kind == CursorKind.CXX_METHOD:
                        try:
                            if target.is_virtual_method():
                                violations.append(
                                    Violation(
                                        "Rule 12-1-1",
                                        "An object's dynamic type shall not be used from the body of its constructor or destructor.",
                                        file_path,
                                        n.location.line,
                                        trigger=target.spelling,
                                    )
                                )
                        except Exception:
                            pass
                elif n.kind in (
                    CursorKind.CXX_DYNAMIC_CAST_EXPR,
                    CursorKind.CXX_TYPEID_EXPR,
                ):
                    violations.append(
                        Violation(
                            "Rule 12-1-1",
                            "An object's dynamic type shall not be used from the body of its constructor or destructor.",
                            file_path,
                            n.location.line,
                            trigger=str(n.kind),
                        )
                    )


def apply_cpp_ch9_rules(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
    returns_non_const_handle: Callable[[clang.cindex.Type | None], bool],
    get_returned_decl: Callable[
        [clang.cindex.Cursor], clang.cindex.Cursor | None
    ],
) -> None:
    # Rule 9-3-1 / 9-3-2 / 9-3-3: member function constness/handle-to-data checks.
    for method in tu.cursor.walk_preorder():
        if method.kind != CursorKind.CXX_METHOD:
            continue
        if (
            not method.location.file
            or Path(method.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        if not method.is_definition():
            continue

        ret_type = (
            method.result_type.get_canonical() if method.result_type else None
        )
        returns_non_const = returns_non_const_handle(ret_type)

        modifies_member = False
        returns_member_handle = False
        class_decl = method.semantic_parent or method.lexical_parent

        def _unwrap_expr(n: clang.cindex.Cursor) -> clang.cindex.Cursor | None:
            cur = n
            while cur and cur.kind in (
                CursorKind.UNEXPOSED_EXPR,
                CursorKind.PAREN_EXPR,
                CursorKind.CSTYLE_CAST_EXPR,
                CursorKind.CXX_STATIC_CAST_EXPR,
                CursorKind.CXX_REINTERPRET_CAST_EXPR,
            ):
                children = [
                    c
                    for c in cur.get_children()
                    if c.kind != CursorKind.TYPE_REF
                ]
                if not children:
                    break
                cur = children[-1]
            return cur

        for c in method.get_children():
            if c.kind != CursorKind.COMPOUND_STMT:
                continue
            for n in c.walk_preorder():
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
                            lhs = _unwrap_expr(children[0])
                            if (
                                lhs
                                and lhs.kind == CursorKind.MEMBER_REF_EXPR
                                and lhs.referenced
                                and lhs.referenced.kind
                                == CursorKind.FIELD_DECL
                            ):
                                modifies_member = True
                elif n.kind == CursorKind.UNARY_OPERATOR:
                    toks = [t.spelling for t in tuple(n.get_tokens())]
                    if "++" in toks or "--" in toks:
                        children = list(n.get_children())
                        if children:
                            target = _unwrap_expr(children[0])
                            if (
                                target
                                and target.kind == CursorKind.MEMBER_REF_EXPR
                                and target.referenced
                                and target.referenced.kind
                                == CursorKind.FIELD_DECL
                            ):
                                modifies_member = True
                elif n.kind == CursorKind.CALL_EXPR:
                    target = n.referenced
                    if target and target.kind == CursorKind.CXX_METHOD:
                        t_parent = (
                            target.semantic_parent or target.lexical_parent
                        )
                        if (
                            class_decl
                            and t_parent
                            and t_parent.hash == class_decl.hash
                        ):
                            try:
                                if not target.is_const_method():
                                    modifies_member = True
                            except Exception:
                                pass
                elif n.kind == CursorKind.RETURN_STMT and returns_non_const:
                    returned = get_returned_decl(n)
                    if returned and returned.kind == CursorKind.FIELD_DECL:
                        returns_member_handle = True

        if returns_non_const and returns_member_handle:
            violations.append(
                Violation(
                    "Rule 9-3-2",
                    "Member functions shall not return non-const handles to class-data.",
                    file_path,
                    method.location.line,
                    trigger=method.spelling,
                )
            )
            try:
                if method.is_const_method():
                    violations.append(
                        Violation(
                            "Rule 9-3-1",
                            "const member functions shall not return non-const pointers or references to class-data.",
                            file_path,
                            method.location.line,
                            trigger=method.spelling,
                        )
                    )
            except Exception:
                pass

        # Conservative heuristic: method has body, does not modify class data,
        # and is not already const => it can likely be const.
        try:
            is_const_method = method.is_const_method()
        except Exception:
            is_const_method = False
        if not is_const_method and not modifies_member:
            violations.append(
                Violation(
                    "Rule 9-3-3",
                    "If a member function can be made const, it shall be made const.",
                    file_path,
                    method.location.line,
                    trigger=method.spelling,
                )
            )


def apply_cpp_ch10_rules(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
    iter_base_specs: Callable[
        [clang.cindex.Cursor], list[tuple[clang.cindex.Cursor, bool]]
    ],
    has_virtual_base_in_hierarchy: Callable[[clang.cindex.Cursor], bool],
    is_derived_from: Callable[
        [clang.cindex.Cursor, clang.cindex.Cursor], bool
    ],
    method_sig_key: Callable[[clang.cindex.Cursor], Any],
    method_has_virtual_keyword: Callable[[clang.cindex.Cursor], bool],
    collect_base_member_names: Callable[[clang.cindex.Cursor], set[str]],
) -> None:
    # Rule 10-1-* / 10-2-1 / 10-3-*: class hierarchy checks.
    for cls in tu.cursor.walk_preorder():
        if cls.kind not in (CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL):
            continue
        if (
            not cls.location.file
            or Path(cls.location.file.name).resolve() != file_path.resolve()
        ):
            continue
        try:
            if not cls.is_definition():
                continue
        except Exception:
            pass

        direct_bases = iter_base_specs(cls)
        if not direct_bases:
            continue

        # Rule 10-1-1: classes should not be derived from virtual bases.
        if has_virtual_base_in_hierarchy(cls):
            violations.append(
                Violation(
                    "Rule 10-1-1",
                    "Classes should not be derived from virtual bases.",
                    file_path,
                    cls.location.line,
                    trigger=cls.spelling,
                )
            )
        # Rule 10-1-2: virtual base only in multiple inheritance hierarchies.
        if len(direct_bases) < 2 and any(
            is_virtual for _, is_virtual in direct_bases
        ):
            violations.append(
                Violation(
                    "Rule 10-1-2",
                    "A base class shall only be declared virtual if it is used in a multiple inheritance hierarchy.",
                    file_path,
                    cls.location.line,
                    trigger=cls.spelling,
                )
            )

        # Rule 10-1-3: same base must not be both virtual and non-virtual in one hierarchy.
        base_path_flags: dict[str, set[bool]] = {}

        def walk_base_paths(
            cur: clang.cindex.Cursor,
            has_virtual_edge: bool,
            path_seen: set[str],
        ) -> None:
            for base_decl, is_virtual in iter_base_specs(cur):
                usr = (
                    base_decl.get_usr()
                    or f"{base_decl.spelling}:{base_decl.hash}"
                )
                via_virtual = bool(has_virtual_edge or is_virtual)
                base_path_flags.setdefault(usr, set()).add(via_virtual)
                if usr in path_seen:
                    continue
                walk_base_paths(base_decl, via_virtual, path_seen | {usr})

        walk_base_paths(cls, False, set())
        for _, flags in base_path_flags.items():
            if True in flags and False in flags:
                violations.append(
                    Violation(
                        "Rule 10-1-3",
                        "An accessible base class shall not be both virtual and non-virtual in the same hierarchy.",
                        file_path,
                        cls.location.line,
                        trigger=cls.spelling,
                    )
                )
                break

        # Rule 10-2-1: base member names should be unambiguous.
        if len(direct_bases) >= 2:
            name_sources: dict[str, set[str]] = {}
            for base_decl, _ in direct_bases:
                base_usr = (
                    base_decl.get_usr()
                    or f"{base_decl.spelling}:{base_decl.hash}"
                )
                for nm in collect_base_member_names(base_decl):
                    if nm.startswith("operator") or nm.startswith("~"):
                        continue
                    name_sources.setdefault(nm, set()).add(base_usr)
            if any(len(srcs) > 1 for srcs in name_sources.values()):
                violations.append(
                    Violation(
                        "Rule 10-2-1",
                        "All accessible entity names from a base class object shall be unambiguous.",
                        file_path,
                        cls.location.line,
                        trigger=cls.spelling,
                    )
                )

        # Collect class methods for 10-3-* checks.
        class_methods = [
            m for m in cls.get_children() if m.kind == CursorKind.CXX_METHOD
        ]
        class_method_keys = {method_sig_key(m) for m in class_methods}

        # Gather ancestor methods.
        ancestor_methods = []
        stack = [b for b, _ in direct_bases]
        seen_anc = set()
        while stack:
            anc = stack.pop()
            anc_usr = anc.get_usr() or f"{anc.spelling}:{anc.hash}"
            if anc_usr in seen_anc:
                continue
            seen_anc.add(anc_usr)
            for m in anc.get_children():
                if m.kind == CursorKind.CXX_METHOD:
                    ancestor_methods.append(m)
            for next_base, _ in iter_base_specs(anc):
                stack.append(next_base)

        # Rule 10-3-1: no more than one virtual function definition per path (heuristic).
        if len(direct_bases) >= 2:
            virtual_sig_sources: dict[Any, set[str]] = {}
            for base_decl, _ in direct_bases:
                base_usr = (
                    base_decl.get_usr()
                    or f"{base_decl.spelling}:{base_decl.hash}"
                )
                for m in base_decl.get_children():
                    if m.kind != CursorKind.CXX_METHOD:
                        continue
                    try:
                        is_virtual = m.is_virtual_method()
                    except Exception:
                        is_virtual = False
                    if not is_virtual:
                        continue
                    virtual_sig_sources.setdefault(
                        method_sig_key(m), set()
                    ).add(base_usr)
            for sig, srcs in virtual_sig_sources.items():
                if len(srcs) > 1 and sig not in class_method_keys:
                    violations.append(
                        Violation(
                            "Rule 10-3-1",
                            "There shall be no more than one definition of each virtual function on each path through the inheritance hierarchy.",
                            file_path,
                            cls.location.line,
                            trigger=cls.spelling,
                        )
                    )
                    break

        # Rule 10-3-2 and 10-3-3: overriding virtual functions.
        for m in class_methods:
            sig = method_sig_key(m)
            matching_virtual_anc = []
            for anc_m in ancestor_methods:
                if method_sig_key(anc_m) != sig:
                    continue
                try:
                    anc_is_virtual = anc_m.is_virtual_method()
                except Exception:
                    anc_is_virtual = False
                if anc_is_virtual:
                    matching_virtual_anc.append(anc_m)
            if not matching_virtual_anc:
                continue

            if not method_has_virtual_keyword(m):
                violations.append(
                    Violation(
                        "Rule 10-3-2",
                        "Each overriding virtual function shall be declared with the virtual keyword.",
                        file_path,
                        m.location.line,
                        trigger=m.spelling,
                    )
                )

            try:
                is_pure = m.is_pure_virtual_method()
            except Exception:
                is_pure = False
            if is_pure:
                base_has_non_pure = False
                for anc_m in matching_virtual_anc:
                    try:
                        anc_is_pure = anc_m.is_pure_virtual_method()
                    except Exception:
                        anc_is_pure = False
                    if not anc_is_pure:
                        base_has_non_pure = True
                        break
                if base_has_non_pure:
                    violations.append(
                        Violation(
                            "Rule 10-3-3",
                            "A virtual function shall only be overridden by a pure virtual function if it is itself declared as pure virtual.",
                            file_path,
                            m.location.line,
                            trigger=m.spelling,
                        )
                    )


def apply_cpp_ch14_rules(
    tu: clang.cindex.TranslationUnit,
    file_path: Path,
    violations: list[Violation],
) -> None:
    # Rule 14-5-2 / 14-5-3: template ctor/assignment in class templates.
    for cls in tu.cursor.walk_preorder():
        if cls.kind != CursorKind.CLASS_TEMPLATE:
            continue
        if (
            not cls.location.file
            or Path(cls.location.file.name).resolve() != file_path.resolve()
        ):
            continue

        class_name = cls.spelling or ""
        template_param_names = set()
        for c in cls.get_children():
            if c.kind in (
                CursorKind.TEMPLATE_TYPE_PARAMETER,
                CursorKind.TEMPLATE_NON_TYPE_PARAMETER,
            ):
                if c.spelling:
                    template_param_names.add(c.spelling)

        has_declared_copy_ctor = False
        has_declared_copy_assign = False
        template_ctor_lines = []
        template_assign_lines = []

        def _is_ref_to_same_class(param_cursor: clang.cindex.Cursor) -> bool:
            pt = (
                param_cursor.type.get_canonical()
                if param_cursor and param_cursor.type
                else None
            )
            if not pt or pt.kind not in (
                TypeKind.LVALUEREFERENCE,
                TypeKind.RVALUEREFERENCE,
            ):
                return False
            try:
                pointee = pt.get_pointee().get_canonical()
            except Exception:
                return False
            if not pointee:
                return False
            if class_name and pointee.spelling == class_name:
                return True
            try:
                decl = pointee.get_declaration()
            except Exception:
                decl = None
            return bool(decl and decl.spelling == class_name)

        def _param_uses_template_name(
            param_cursor: clang.cindex.Cursor, candidate_names: set[str]
        ) -> bool:
            if not candidate_names:
                return False
            spelling = (
                param_cursor.type.spelling
                if param_cursor and param_cursor.type
                else ""
            ) or ""
            for tname in candidate_names:
                if re.search(rf"\b{re.escape(tname)}\b", spelling):
                    return True
            return False

        members = list(cls.get_children())
        for m in members:
            if m.kind == CursorKind.CONSTRUCTOR:
                try:
                    args = list(m.get_arguments() or ())
                except Exception:
                    args = []
                if len(args) == 1 and _is_ref_to_same_class(args[0]):
                    has_declared_copy_ctor = True
            elif m.kind == CursorKind.CXX_METHOD and m.spelling == "operator=":
                try:
                    args = list(m.get_arguments() or ())
                except Exception:
                    args = []
                if len(args) == 1 and _is_ref_to_same_class(args[0]):
                    has_declared_copy_assign = True

        for m in members:
            if m.kind != CursorKind.FUNCTION_TEMPLATE:
                continue
            fn_template_param_names = set()
            for ch in m.get_children():
                if ch.kind in (
                    CursorKind.TEMPLATE_TYPE_PARAMETER,
                    CursorKind.TEMPLATE_NON_TYPE_PARAMETER,
                ):
                    if ch.spelling:
                        fn_template_param_names.add(ch.spelling)
            combined_param_names = (
                template_param_names | fn_template_param_names
            )
            templated_children = list(m.get_children())
            for tc in templated_children:
                if tc.kind == CursorKind.CONSTRUCTOR:
                    try:
                        args = list(tc.get_arguments() or ())
                    except Exception:
                        args = []
                    if len(args) == 1 and _param_uses_template_name(
                        args[0], combined_param_names
                    ):
                        template_ctor_lines.append(
                            tc.location.line or m.location.line
                        )
                elif (
                    tc.kind == CursorKind.CXX_METHOD
                    and tc.spelling == "operator="
                ):
                    try:
                        args = list(tc.get_arguments() or ())
                    except Exception:
                        args = []
                    if len(args) == 1 and _param_uses_template_name(
                        args[0], combined_param_names
                    ):
                        template_assign_lines.append(
                            tc.location.line or m.location.line
                        )

        if template_ctor_lines and not has_declared_copy_ctor:
            violations.append(
                Violation(
                    "Rule 14-5-2",
                    "A copy constructor shall be declared when there is a template constructor with a single generic parameter.",
                    file_path,
                    template_ctor_lines[0],
                    trigger=class_name,
                )
            )
        if template_assign_lines and not has_declared_copy_assign:
            violations.append(
                Violation(
                    "Rule 14-5-3",
                    "A copy assignment operator shall be declared when there is a template assignment operator with a generic parameter.",
                    file_path,
                    template_assign_lines[0],
                    trigger=class_name,
                )
            )
