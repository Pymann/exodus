import logging
from typing import List, Dict, Any, Tuple, Iterable, Optional, cast
from pathlib import Path
import re
import tree_sitter

logger = logging.getLogger(__name__)

C_TO_CPP_MAP = {
    "Rule 1.2": "Rule 1-0-1",
    "Rule 2.1": "Rule 0-1-1",
    "Rule 2.2": "Rule 0-1-9",
    "Rule 2.3": "Rule 0-1-5",
    "Rule 2.7": "Rule 0-1-11",
    "Rule 3.1": "Rule 2-7-1",
    "Rule 4.2": "Rule 2-3-1",
    "Rule 5.3": "Rule 2-10-2",
    "Rule 5.6": "Rule 2-10-3",
    "Rule 5.7": "Rule 2-10-4",
    "Rule 7.1": "Rule 2-13-2",
    "Rule 8.3": "Rule 8-4-2",
    "Rule 8.5": "Rule 8-0-1",
    "Rule 8.6": "Rule 3-2-4",
    "Rule 8.11": "Rule 3-1-3",
    "Rule 8.8": "Rule 3-3-2",
    "Rule 8.9": "Rule 3-4-1",
    "Rule 8.13": "Rule 7-1-2",
    "Rule 9.1": "Rule 8-5-1",
    "Rule 9.2": "Rule 8-5-2",
    "Rule 10.1": "Rule 5-0-21",
    "Rule 11.1": "Rule 5-2-6",
    "Rule 11.3": "Rule 5-2-7",
    "Rule 11.4": "Rule 5-2-9",
    "Rule 11.8": "Rule 5-2-5",
    "Rule 11.9": "Rule 4-10-2",
    "Rule 12.2": "Rule 5-8-1",
    "Rule 12.3": "Rule 5-18-1",
    "Rule 12.4": "Rule 5-19-1",
    "Rule 13.2": "Rule 5-0-1",
    "Rule 13.4": "Rule 6-2-1",
    "Rule 13.5": "Rule 5-14-1",
    "Rule 13.6": "Rule 5-3-4",
    "Rule 14.4": "Rule 5-0-13",
    "Rule 15.2": "Rule 6-6-2",
    "Rule 15.3": "Rule 6-6-1",
    "Rule 15.4": "Rule 6-6-4",
    "Rule 15.5": "Rule 6-6-5",
    "Rule 15.6": "Rule 6-3-1",
    "Rule 15.7": "Rule 6-4-1",
    "Rule 16.1": "Rule 6-4-3",
    "Rule 16.2": "Rule 6-4-4",
    "Rule 16.3": "Rule 6-4-5",
    "Rule 16.4": "Rule 6-4-6",
    "Rule 16.5": "Rule 6-4-6",
    "Rule 16.6": "Rule 6-4-8",
    "Rule 16.7": "Rule 6-4-7",
    "Rule 17.1": "Rule 8-4-1",
    "Rule 17.2": "Rule 7-5-4",
    "Rule 17.4": "Rule 8-4-3",
    "Rule 18.4": "Rule 5-0-15",
    "Rule 18.1": "Rule 5-0-16",
    "Rule 18.2": "Rule 5-0-17",
    "Rule 18.3": "Rule 5-0-18",
    "Rule 18.5": "Rule 5-0-19",
    "Rule 19.1": "Rule 0-2-1",
    "Rule 19.2": "Rule 9-5-1",
    "Rule 20.1": "Rule 16-0-1",
    "Rule 20.2": "Rule 16-2-4",
    "Rule 20.5": "Rule 16-0-3",
    "Rule 20.6": "Rule 16-0-5",
    "Rule 20.7": "Rule 16-0-6",
    "Rule 20.9": "Rule 16-0-7",
    "Rule 20.10": "Rule 16-3-2",
    "Rule 20.13": "Rule 16-0-8",
    "Rule 20.14": "Rule 16-1-2",
    "Rule 21.3": "Rule 18-4-1",
    "Rule 21.4": "Rule 17-0-5",
    "Rule 21.5": "Rule 18-7-1",
    "Rule 21.6": "Rule 27-0-1",
    "Rule 21.7": "Rule 18-0-2",
    "Rule 21.8": "Rule 18-0-3",
    "Rule 21.10": "Rule 18-0-4",
}


class Violation:
    _file_line_cache: Dict[str, List[str]] = {}

    def __init__(
        self,
        rule: str,
        message: str,
        file: Optional[Path],
        line: int = 0,
        detector: str = "",
        trigger: str = "",
    ) -> None:
        # Auto-map MISRA C:2012 to MISRA C++:2008 if evaluating a C++ file
        if (
            file
            and hasattr(file, "suffix")
            and file.suffix in [".cpp", ".cc", ".cxx"]
            and rule in C_TO_CPP_MAP
        ):
            rule = C_TO_CPP_MAP[rule]

        self.rule = rule
        self.message = message
        self.file = file
        self.line = line
        self.detector = detector
        self.trigger = trigger

    @staticmethod
    def _extract_trigger_from_message(message: str) -> str:
        if not message:
            return ""
        quoted = re.search(r"'([^']+)'", message)
        if quoted:
            return quoted.group(1).strip()
        # Config-style detail in message, e.g.
        # "... (compiler.integer_division_documented=false)"
        kv = re.search(r"\(([A-Za-z_][\w.]*)\s*=", message)
        if kv:
            return kv.group(1).strip()
        # fallback: grab token after a trailing colon pattern
        # Example: "... functions: foo"
        colon = re.search(r":\s*([A-Za-z_]\w*)\s*$", message)
        if colon:
            return colon.group(1).strip()
        return ""

    @classmethod
    def _line_text(cls, file: Path, line: int) -> str:
        if not file or line <= 0:
            return ""
        key = str(file)
        lines = cls._file_line_cache.get(key)
        if lines is None:
            try:
                lines = file.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
            except Exception:
                lines = []
            cls._file_line_cache[key] = lines
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""

    @classmethod
    def _extract_trigger_from_source(cls, file: Path, line: int) -> str:
        def _last_func_like_symbol(s: str) -> str:
            matches = list(re.finditer(r"\b([A-Za-z_]\w*)\s*\(", s))
            if not matches:
                return ""
            banned = {"if", "for", "while", "switch", "return", "sizeof"}
            for m in reversed(matches):
                name = m.group(1)
                if name not in banned:
                    return name
            return ""

        def _enclosing_function_name(lines: List[str], line_idx: int) -> str:
            start = max(0, line_idx - 200)
            for i in range(line_idx, start - 1, -1):
                s = lines[i].strip()
                if not s or s.startswith("#"):
                    continue
                # likely function declaration/definition line
                if "(" in s and ")" in s and ";" not in s:
                    name = _last_func_like_symbol(s)
                    if name:
                        return name
            return ""

        text = cls._line_text(file, line)
        if not text:
            return ""
        # Macro definitions: use macro symbol name.
        macro = re.match(r"^\s*#\s*define\s+([A-Za-z_]\w*)\b", text)
        if macro:
            return macro.group(1)
        # Goto statements: use destination label.
        goto = re.search(r"\bgoto\s+([A-Za-z_]\w*)\s*;", text)
        if goto:
            return goto.group(1)
        # Prefer function-like calls when present.
        call_name = _last_func_like_symbol(text)
        if call_name:
            return call_name
        # Prefer assignment/comparison expression chunks.
        expr = re.search(
            r"([A-Za-z_][^;{}]*?(==|!=|<=|>=|=|\+=|-=|\*=|/=|%=|<<=|>>=|&&|\|\|)[^;{}]*)",
            text,
        )
        if expr:
            return " ".join(expr.group(1).split())[:120]
        # For function-scope violations (e.g. Rule 15.5), use enclosing function name.
        key = str(file)
        lines = cls._file_line_cache.get(key) or []
        if lines and line > 0:
            fn = _enclosing_function_name(lines, min(len(lines) - 1, line - 1))
            if fn:
                return fn
        # Fallback: trimmed source snippet.
        return " ".join(text.split())[:120]

    def _derived_trigger(self) -> str:
        if self.trigger:
            return self.trigger
        # Rule-specific preference: for single-exit guideline we want the function symbol.
        if self.rule == "Rule 15.5" and self.file and self.line:
            key = str(self.file)
            lines = self._file_line_cache.get(key)
            if lines is None:
                try:
                    lines = self.file.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                except Exception:
                    lines = []
                self._file_line_cache[key] = lines
            if lines:
                start = min(len(lines) - 1, max(0, self.line - 1))
                for i in range(start, max(-1, start - 200), -1):
                    s = lines[i].strip()
                    if (
                        "(" in s
                        and ")" in s
                        and ";" not in s
                        and not s.startswith("#")
                    ):
                        matches = list(
                            re.finditer(r"\b([A-Za-z_]\w*)\s*\(", s)
                        )
                        for m in reversed(matches):
                            name = m.group(1)
                            if name not in {
                                "if",
                                "for",
                                "while",
                                "switch",
                                "return",
                                "sizeof",
                            }:
                                return name
        from_msg = self._extract_trigger_from_message(self.message or "")
        if from_msg:
            return from_msg
        if self.file and self.line:
            return self._extract_trigger_from_source(self.file, self.line)
        return ""

    def __str__(self) -> str:
        location = f"{self.file}:{self.line}" if self.file else "Global:0"
        detector = self.detector if self.detector else "unknown-detector"
        trigger = self._derived_trigger()
        if trigger:
            return f"{location} [{self.rule}] {self.message} [trigger='{trigger}'] [{detector}]"
        return f"{location} [{self.rule}] {self.message} [{detector}]"


class MisraRule:
    def __init__(self, name: str, description: str, query: str | None = None):
        self.name = name
        self.description = description
        self.query = query


# Predefine queries for C and C++ (some might be slightly different depending on grammar)
RULES = [
    MisraRule(
        name="Rule 3-1-2",
        description="Functions shall not be declared at block scope.",
        query="""(compound_statement (declaration declarator: (function_declarator) @block_func_decl))""",
    ),
    MisraRule(
        name="Rule 2-5-1",
        description="Digraphs should not be used.",
        query="""(translation_unit) @tu_digraph""",
    ),
    MisraRule(
        name="Rule 15.1",
        description="The goto statement should not be used.",
        query="""(goto_statement) @goto""",
    ),
    MisraRule(
        name="Rule 7.1",
        description="Octal constants shall not be used.",
        # Matches numbers starting with 0 followed by 1-7, optionally with type suffixes.
        # Tree-sitter might classify this just as `number_literal`. We will need to check the exact text content in code, but we can query all number literals first.
        query="""(number_literal) @number""",
    ),
    MisraRule(
        name="Rule 7.2 / 7.3",
        description="Suffixes 'U' and 'u' are required for unsigned, 'l' is forbidden.",
        query="""(number_literal) @number_suffix""",
    ),
    MisraRule(
        name="Rule 6.1 / 6.2",
        description="Bit-field types and signedness rules.",
        query="""(field_declaration (bitfield_clause)) @bitfield""",
    ),
    MisraRule(
        name="Rule 8.10",
        description="An inline function shall be declared with the static storage class.",
        query="""(function_definition) @inline_func""",
    ),
    MisraRule(
        name="Rule 13.6",
        description="The operand of the sizeof operator shall not contain any expression which has potential side effects.",
        query="""(sizeof_expression value: [(update_expression) (assignment_expression) (call_expression)]) @sizeof""",
    ),
    MisraRule(
        name="Rule 17.2",
        description="Functions shall not call themselves, either directly or indirectly.",
        query="""(function_definition declarator: (function_declarator declarator: (identifier) @func_name)) @recursion""",
    ),
    MisraRule(
        name="Rule 16.4",
        description="Every switch statement shall have a default label.",
        query="""(switch_statement body: (compound_statement) @body)""",
    ),
    MisraRule(
        name="Rule 21.3",
        description="The memory allocation and deallocation functions of <stdlib.h> shall not be used.",
        query="""(call_expression function: (identifier) @func_name (#match? @func_name "^(malloc|calloc|realloc|free)$"))""",
    ),
    MisraRule(
        name="Rule 18.4.1",  # C++ Specific
        description="Dynamic heap memory allocation shall not be used.",
        query="""[
            (new_expression) @new
            (delete_expression) @delete
        ]""",
    ),
    MisraRule(
        name="Rule 17.1",
        description="The features of <stdarg.h> shall not be used.",
        query="""[
            (preproc_include path: (system_lib_string) @lib (#eq? @lib "<stdarg.h>"))
            (preproc_include path: (system_lib_string) @lib (#eq? @lib "<cstdarg>"))
        ]""",
    ),
    MisraRule(
        name="Rule 2.1",
        description="A project shall not contain unreachable code.",
        query="""[
            (compound_statement (return_statement) . (_) @unreachable)
            (compound_statement (break_statement) . (_) @unreachable)
            (compound_statement (continue_statement) . (_) @unreachable)
            (compound_statement (goto_statement) . (_) @unreachable)
        ]""",
    ),
    MisraRule(
        name="Rule 15.6",
        description="The body of an iteration-statement or a selection-statement shall be a compound-statement.",
        query="""[
            (if_statement consequence: [(expression_statement) (return_statement) (break_statement) (continue_statement) (goto_statement)] @no_brace)
            (while_statement body: [(expression_statement) (return_statement) (break_statement) (continue_statement) (goto_statement)] @no_brace)
            (for_statement body: [(expression_statement) (return_statement) (break_statement) (continue_statement) (goto_statement)] @no_brace)
        ]""",
    ),
    MisraRule(
        name="Rule 20.5",
        description="#undef should not be used.",
        query="""(preproc_call directive: (preproc_directive) @dir (#eq? @dir "#undef"))""",
    ),
    MisraRule(
        name="Rule 20.4",
        description="A macro shall not be defined with the same name as a keyword.",
        query="""(preproc_def name: (identifier) @macro_name)""",
    ),
    # removed Rule 21.6 as it is handled by 21.X
    MisraRule(
        name="Rule 8.14",
        description="The restrict type qualifier shall not be used.",
        query="""(type_qualifier) @qualifier (#eq? @qualifier "restrict")""",
    ),
    MisraRule(
        name="Rule 3.1 / 3.2",
        description="Nested comments and line-splicing in comments are not allowed.",
        query="""(comment) @comment""",
    ),
    MisraRule(
        name="Rule 4.1 / 4.2",
        description="Trigraphs and malformed escape sequences.",
        query="""[
            (string_literal) @string
            (char_literal) @char
            (escape_sequence) @escape
        ]""",
    ),
    MisraRule(
        name="Rule 19.2",
        description="The union keyword should not be used.",
        query="""(union_specifier) @union""",
    ),
    MisraRule(
        name="Rule 21.X / 27.X",
        description="Restricted standard headers (setjmp, signal, time, tgmath, fenv, stdio) shall not be used.",
        query="""(preproc_include path: (system_lib_string) @lib)""",
    ),
    MisraRule(
        name="Rule 16.3 / 16.5 / 16.6",
        description="Switch statement well-formedness (clause count, default placement, break termination).",
        query="""(switch_statement body: (compound_statement) @switch_body_advanced)""",
    ),
    MisraRule(
        name="Rule 18.8",
        description="Variable-length array types shall not be used.",
        query="""(vla_declarator) @vla""",
    ),
    MisraRule(
        name="Rule 20.1",
        description="#include directives should only be preceded by preprocessor directives or comments.",
        query="""(translation_unit) @tu_includes""",
    ),
    MisraRule(
        name="Rule 20.2",
        description="Invalid characters in header file names.",
        query="""[
            (preproc_include path: (system_lib_string) @header_name)
            (preproc_include path: (string_literal) @header_name)
        ]""",
    ),
    MisraRule(
        name="Rule 15.5",
        description="A function should have a single point of exit at the end.",
        query="""(function_definition body: (compound_statement) @func_body)""",
    ),
    MisraRule(
        name="Rule 15.7",
        description="All if ... else if constructs shall be terminated with an else statement.",
        query="""(if_statement alternative: (else_clause (if_statement))) @else_if_chain""",
    ),
    MisraRule(
        name="Rule 8.2",
        description="Function types shall be in prototype form with named parameters.",
        query="""(parameter_declaration) @param""",
    ),
    MisraRule(
        name="Rule 20.3",
        description="The \\ character shall not be used to splice a macro definition across more than one line.",
        query="""(preproc_def) @macro_def""",
    ),
    MisraRule(
        name="Rule 20.8",
        description="The controlling expression of a #if or #elif preprocessing directive shall evaluate to 0 or 1.",
        query="""(translation_unit) @tu_preproc_checks""",
    ),
    MisraRule(
        name="Rule 20.9",
        description="All identifiers used in the controlling expression of #if or #elif preprocessing directives shall be #define'd before evaluation.",
        query="""(translation_unit) @tu_preproc_checks""",
    ),
    MisraRule(
        name="Rule 20.13",
        description="A line whose first token is # shall be a valid preprocessing directive.",
        # Same query as 20.14 to perform file-level string analysis
        query="""(translation_unit) @tu_preproc_checks""",
    ),
    MisraRule(
        name="Rule 20.14",
        description="All #else, #elif and #endif preprocessor directives shall reside in the same file as the #if, #ifdef or #ifndef directive to which they are related.",
        query="""(translation_unit) @tu_preproc_checks""",
    ),
]


def analyze_tree(
    tree: tree_sitter.Tree,
    file_path: Path,
    language: tree_sitter.Language,
    source_code: bytes,
    project_config: Any = None,
) -> List[Violation]:
    violations: List[Violation] = []
    rule_20_9_cfg = (
        getattr(
            getattr(project_config, "misra_heuristics", None),
            "rule_20_9",
            None,
        )
        if project_config
        else None
    )
    rule_20_9_enabled = bool(getattr(rule_20_9_cfg, "enabled", True))
    rule_20_9_allowed = set(
        getattr(rule_20_9_cfg, "allowed_undefined_macros", [])
    )
    is_cpp_file = file_path.suffix in (".cpp", ".cc", ".cxx")
    source_text = source_code.decode("utf8", errors="ignore")

    def _node_snippet(n: tree_sitter.Node, max_len: int = 140) -> str:
        try:
            text = source_code[n.start_byte : n.end_byte].decode(
                "utf8", errors="ignore"
            )
        except Exception:
            return ""
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_len:
            return text[: max_len - 3] + "..."
        return text

    if is_cpp_file:
        # Rule 1-0-1 heuristic: detect GNU statement-expression extension pattern.
        ext_match = re.search(r"\(\{", source_text)
        if ext_match:
            line = source_text.count("\n", 0, ext_match.start()) + 1
            violations.append(
                Violation(
                    "Rule 1.2",
                    "Language extensions should not be used (GNU statement-expression detected).",
                    file_path,
                    line,
                    trigger="({",
                )
            )
        # Rule 4-10-1 heuristic: NULL used as integer value in simple declarations.
        null_int_decl = re.compile(
            r"^\s*(?:const\s+)?(?:signed\s+|unsigned\s+)?(?:short|int|long|wchar_t|char)\s+\w+\s*=\s*NULL\b"
        )
        for line_no, line_text in enumerate(source_text.splitlines(), start=1):
            if null_int_decl.search(line_text):
                violations.append(
                    Violation(
                        "Rule 4-10-1",
                        "NULL shall not be used as an integer value.",
                        file_path,
                        line_no,
                        trigger=line_text.strip(),
                    )
                )

    def _looks_like_commented_out_code(comment_text: str) -> bool:
        stripped = comment_text.strip()
        if not stripped:
            return False
        # Conservative "commented-out code" heuristic: require at least one structural token
        # and one typical code keyword/operator pattern.
        has_structure = any(
            token in stripped
            for token in (";", "{", "}", "(", ")", "=", "->", "::")
        )
        has_code_word = re.search(
            r"\b(if|else|for|while|switch|case|return|class|struct|typedef|namespace|template|#include)\b",
            stripped,
        )
        return bool(has_structure and has_code_word)

    def _has_invalid_cpp_escape(literal_text: str) -> bool:
        # Raw string literals do not interpret backslash escapes.
        if re.match(r'^[uUL]*R"', literal_text) or literal_text.startswith(
            'u8R"'
        ):
            return False

        i = 0
        n = len(literal_text)
        while i < n:
            if literal_text[i] != "\\":
                i += 1
                continue

            i += 1
            if i >= n:
                return True
            c = literal_text[i]
            i += 1

            if c in "'\"?\\abfnrtv":
                continue
            if c in "01234567":
                # Octal escape: up to 3 octal digits total (we already consumed first).
                consumed = 1
                while i < n and consumed < 3 and literal_text[i] in "01234567":
                    i += 1
                    consumed += 1
                continue
            if c == "x":
                # Hex escape must include at least one hex digit.
                if i >= n or literal_text[i] not in "0123456789abcdefABCDEF":
                    return True
                while i < n and literal_text[i] in "0123456789abcdefABCDEF":
                    i += 1
                continue
            if c == "u":
                # Universal character name: exactly 4 hex digits.
                if i + 4 > n or not re.fullmatch(
                    r"[0-9a-fA-F]{4}", literal_text[i : i + 4]
                ):
                    return True
                i += 4
                continue
            if c == "U":
                # Universal character name: exactly 8 hex digits.
                if i + 8 > n or not re.fullmatch(
                    r"[0-9a-fA-F]{8}", literal_text[i : i + 8]
                ):
                    return True
                i += 8
                continue

            # Unknown escape sequence.
            return True
        return False

    def _literal_suffix(text: str) -> str:
        # Lightweight suffix extractor for integer/floating literals.
        m = re.match(
            r"^(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]+|[0-9]+(?:\.[0-9]*)?(?:[eEpP][+\-]?[0-9]+)?)([a-zA-Z]+)$",
            text,
        )
        return m.group(1) if m else ""

    for rule in RULES:
        if rule.query:
            try:
                if hasattr(tree_sitter, "Query"):
                    query = tree_sitter.Query(language, rule.query)
                    cursor = tree_sitter.QueryCursor(query)
                    captures: Any = cursor.captures(tree.root_node)
                else:
                    query = language.query(rule.query)
                    captures = cast(Any, query).captures(tree.root_node)

                # In tree-sitter >= 0.22, captures is a dict mapping capture_name -> list of nodes
                # In tree-sitter < 0.22, captures is a list of tuples: (node, capture_name)
                iterable_captures: list[tuple[tree_sitter.Node, str]] = []
                if isinstance(captures, dict):
                    for capture_name, nodes in captures.items():
                        # sometimes it's a single node, sometimes a list
                        node_list = (
                            nodes if isinstance(nodes, list) else [nodes]
                        )
                        for node in cast(
                            Iterable[tree_sitter.Node], node_list
                        ):
                            iterable_captures.append((node, capture_name))
                else:
                    iterable_captures = list(
                        cast(Iterable[tuple[tree_sitter.Node, str]], captures)
                    )

                for node, capture_name in iterable_captures:
                    if (
                        rule.name == "Rule 3-1-2"
                        and capture_name == "block_func_decl"
                    ):
                        if is_cpp_file:
                            violations.append(
                                Violation(
                                    "Rule 3-1-2",
                                    "Functions shall not be declared at block scope.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    if rule.name == "Rule 7.1" and capture_name == "number":
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        if (
                            text.startswith("0")
                            and len(text) > 1
                            and not text.lower().startswith(("0x", "0b"))
                            and not "." in text
                        ):
                            if any(c in "1234567" for c in text[1:]):
                                violations.append(
                                    Violation(
                                        rule.name,
                                        rule.description,
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=text,
                                    )
                                )
                        continue
                    elif (
                        rule.name == "Rule 2-5-1"
                        and capture_name == "tu_digraph"
                    ):
                        if not is_cpp_file:
                            continue
                        code_text = source_code.decode("utf8", errors="ignore")
                        digraph_tokens = ("<%", "%>", "<:", ":>", "%:", "%:%:")
                        for line_no, line_text in enumerate(
                            code_text.splitlines(), start=1
                        ):
                            if any(
                                token in line_text for token in digraph_tokens
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 2-5-1",
                                        "Digraphs should not be used.",
                                        file_path,
                                        line_no,
                                        trigger=line_text.strip(),
                                    )
                                )
                        continue
                    elif rule.name == "Rule 16.4" and capture_name == "body":
                        has_default = False

                        def find_default(n: tree_sitter.Node) -> None:
                            nonlocal has_default
                            if n.type == "case_statement" and any(
                                child.type == "default" for child in n.children
                            ):
                                has_default = True
                                return
                            if n.type in (
                                "default_statement",
                                "labeled_statement",
                            ) and any(
                                child.type == "default" for child in n.children
                            ):
                                has_default = True
                                return
                            if n.type == "default":
                                has_default = True
                                return
                            for c in n.children:
                                find_default(c)

                        find_default(node)
                        if not has_default:
                            violations.append(
                                Violation(
                                    rule.name,
                                    rule.description,
                                    file_path,
                                    (
                                        (node.parent.start_point[0] + 1)
                                        if node.parent
                                        else (node.start_point[0] + 1)
                                    ),
                                    trigger=_node_snippet(
                                        node.parent if node.parent else node
                                    ),
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 15.6" and capture_name == "no_brace"
                    ):
                        ctrl = node.parent
                        if ctrl and ctrl.type in (
                            "if_statement",
                            "while_statement",
                            "for_statement",
                        ):
                            trigger = _node_snippet(ctrl)
                            violations.append(
                                Violation(
                                    rule.name,
                                    rule.description,
                                    file_path,
                                    ctrl.start_point[0] + 1,
                                    trigger=trigger,
                                )
                            )
                        else:
                            violations.append(
                                Violation(
                                    rule.name,
                                    rule.description,
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 3.1 / 3.2"
                        and capture_name == "comment"
                    ):
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        if text.startswith("/*") and "/*" in text[2:]:
                            violations.append(
                                Violation(
                                    "Rule 3.1",
                                    "The character sequence /* shall not be used within a C-style comment.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        if text.startswith("//") and (
                            "\\\n" in text or "\\\r\n" in text
                        ):
                            violations.append(
                                Violation(
                                    "Rule 3.2",
                                    "Line-splicing shall not be used in // comments.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        if (
                            is_cpp_file
                            and text.startswith("/*")
                            and _looks_like_commented_out_code(text[2:-2])
                        ):
                            violations.append(
                                Violation(
                                    "Rule 2-7-2",
                                    "Sections of code shall not be commented out using C-style comments.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        if (
                            is_cpp_file
                            and text.startswith("//")
                            and _looks_like_commented_out_code(text[2:])
                        ):
                            violations.append(
                                Violation(
                                    "Rule 2-7-3",
                                    "Sections of code should not be commented out using C++ comments.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    elif rule.name == "Rule 4.1 / 4.2":
                        if capture_name in ("string", "char"):
                            text = source_code[
                                node.start_byte : node.end_byte
                            ].decode("utf8", errors="ignore")
                            if (
                                "??=" in text
                                or "??(" in text
                                or "??/" in text
                                or "??)" in text
                                or "??'" in text
                                or "??<" in text
                                or "??!" in text
                                or "??>" in text
                                or "??-" in text
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 4.2",
                                        "Trigraphs shall not be used.",
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                            if is_cpp_file and _has_invalid_cpp_escape(text):
                                violations.append(
                                    Violation(
                                        "Rule 2-13-1",
                                        "Only those escape sequences defined in ISO C++ shall be used.",
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                        elif capture_name == "escape":
                            text = source_code[
                                node.start_byte : node.end_byte
                            ].decode("utf8", errors="ignore")
                            is_hex = text.startswith("\\x") or text.startswith(
                                "\\X"
                            )
                            is_oct = len(text) > 1 and text[1] in "01234567"
                            if is_hex or is_oct:
                                next_char = source_code[
                                    node.end_byte : node.end_byte + 1
                                ]
                                if next_char not in (b'"', b"'", b"\\"):
                                    violations.append(
                                        Violation(
                                            "Rule 4.1",
                                            "Octal and hexadecimal escape sequences shall be terminated.",
                                            file_path,
                                            node.start_point[0] + 1,
                                            trigger=_node_snippet(node),
                                        )
                                    )
                        continue
                    elif (
                        rule.name == "Rule 7.2 / 7.3"
                        and capture_name == "number_suffix"
                    ):
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        if text.endswith(
                            ("l", "ul", "lu", "ll", "ull", "llu")
                        ) and not text.lower().startswith(("0x", "0b")):
                            violations.append(
                                Violation(
                                    "Rule 7.3",
                                    "The lowercase character 'l' shall not be used in a literal suffix.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        if is_cpp_file:
                            suffix = _literal_suffix(text)
                            if suffix and suffix != suffix.upper():
                                violations.append(
                                    Violation(
                                        "Rule 2-13-4",
                                        "Literal suffixes shall be upper case.",
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                        continue
                    elif (
                        rule.name == "Rule 6.1 / 6.2"
                        and capture_name == "bitfield"
                    ):
                        type_node = next(
                            (
                                c
                                for c in node.children
                                if c.type
                                in (
                                    "primitive_type",
                                    "type_identifier",
                                    "sized_type_specifier",
                                )
                            ),
                            None,
                        )
                        if type_node:
                            type_text = source_code[
                                type_node.start_byte : type_node.end_byte
                            ].decode("utf8", errors="ignore")
                            if type_text == "int":
                                violations.append(
                                    Violation(
                                        "Rule 6.1",
                                        "Bit-fields shall only be declared with an appropriate type (explicit signed/unsigned).",
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                            elif (
                                type_text == "signed int"
                                or type_text == "signed"
                            ):
                                clause = next(
                                    (
                                        c
                                        for c in node.children
                                        if c.type == "bitfield_clause"
                                    ),
                                    None,
                                )
                                if clause:
                                    num = next(
                                        (
                                            c
                                            for c in clause.children
                                            if c.type == "number_literal"
                                        ),
                                        None,
                                    )
                                    if num:
                                        num_text = source_code[
                                            num.start_byte : num.end_byte
                                        ].decode("utf8", errors="ignore")
                                        if num_text == "1":
                                            violations.append(
                                                Violation(
                                                    "Rule 6.2",
                                                    "Single-bit named bit fields shall not be of a signed type.",
                                                    file_path,
                                                    node.start_point[0] + 1,
                                                    trigger=_node_snippet(
                                                        node
                                                    ),
                                                )
                                            )
                        continue
                    elif (
                        rule.name == "Rule 8.10"
                        and capture_name == "inline_func"
                    ):
                        modifiers = [
                            c
                            for c in node.children
                            if c.type
                            in (
                                "storage_class_specifier",
                                "type_qualifier",
                                "identifier",
                                "primitive_type",
                            )
                        ]
                        texts = [
                            source_code[m.start_byte : m.end_byte].decode(
                                "utf8", errors="ignore"
                            )
                            for m in modifiers
                        ]
                        if "inline" in texts and "static" not in texts:
                            violations.append(
                                Violation(
                                    "Rule 8.10",
                                    "An inline function shall be declared with the static storage class.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    elif rule.name == "Rule 17.2":
                        if capture_name == "recursion":
                            func_node = next(
                                (
                                    c
                                    for c in iterable_captures
                                    if c[1] == "func_name"
                                    and c[0].start_byte >= node.start_byte
                                    and c[0].end_byte <= node.end_byte
                                ),
                                None,
                            )
                            if func_node:
                                func_text = source_code[
                                    func_node[0]
                                    .start_byte : func_node[0]
                                    .end_byte
                                ].decode("utf8", errors="ignore")

                                def find_calls(n: tree_sitter.Node) -> None:
                                    if n.type == "call_expression":
                                        func_id = next(
                                            (
                                                c
                                                for c in n.children
                                                if c.type == "identifier"
                                            ),
                                            None,
                                        )
                                        if func_id:
                                            call_text = source_code[
                                                func_id.start_byte : func_id.end_byte
                                            ].decode("utf8", errors="ignore")
                                            if call_text == func_text:
                                                violations.append(
                                                    Violation(
                                                        "Rule 17.2",
                                                        "Functions shall not call themselves directly.",
                                                        file_path,
                                                        n.start_point[0] + 1,
                                                        trigger=call_text,
                                                    )
                                                )
                                    for child in n.children:
                                        find_calls(child)

                                find_calls(node)
                        continue
                    elif (
                        rule.name == "Rule 20.4"
                        and capture_name == "macro_name"
                    ):
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        keywords = {
                            "auto",
                            "break",
                            "case",
                            "char",
                            "const",
                            "continue",
                            "default",
                            "do",
                            "double",
                            "else",
                            "enum",
                            "extern",
                            "float",
                            "for",
                            "goto",
                            "if",
                            "inline",
                            "int",
                            "long",
                            "register",
                            "restrict",
                            "return",
                            "short",
                            "signed",
                            "sizeof",
                            "static",
                            "struct",
                            "switch",
                            "typedef",
                            "union",
                            "unsigned",
                            "void",
                            "volatile",
                            "while",
                            "_Alignas",
                            "_Alignof",
                            "_Atomic",
                            "_Bool",
                            "_Complex",
                            "_Generic",
                            "_Imaginary",
                            "_Noreturn",
                            "_Static_assert",
                            "_Thread_local",
                        }
                        if text in keywords:
                            violations.append(
                                Violation(
                                    "Rule 20.4",
                                    "A macro shall not be defined with the same name as a keyword.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=text,
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 8.14"
                        and capture_name == "qualifier"
                    ):
                        # Some tree-sitter builds return broad type qualifiers here; enforce
                        # a strict text check so we only report actual restrict qualifiers.
                        text = (
                            source_code[node.start_byte : node.end_byte]
                            .decode("utf8", errors="ignore")
                            .strip()
                        )
                        if text in {"restrict", "__restrict", "__restrict__"}:
                            violations.append(
                                Violation(
                                    "Rule 8.14",
                                    "The restrict type qualifier shall not be used.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=text,
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 2.1"
                        and capture_name == "unreachable"
                    ):
                        # Tree-sitter pattern-level unreachable detection is too coarse and
                        # causes many false positives in guarded-return / fail-label idioms.
                        # Keep Rule 2.1 via compiler diagnostics instead.
                        continue
                    elif (
                        rule.name == "Rule 16.3 / 16.5 / 16.6"
                        and capture_name == "switch_body_advanced"
                    ):
                        clauses = [
                            c
                            for c in node.children
                            if c.type
                            in ("case_statement", "default_statement")
                        ]
                        if len(clauses) < 2:
                            violations.append(
                                Violation(
                                    "Rule 16.6",
                                    "Every switch statement shall have at least two switch-clauses.",
                                    file_path,
                                    (
                                        (node.parent.start_point[0] + 1)
                                        if node.parent
                                        else (node.start_point[0] + 1)
                                    ),
                                    trigger=_node_snippet(
                                        node.parent if node.parent else node
                                    ),
                                )
                            )

                        if clauses:
                            default_indices = [
                                i
                                for i, c in enumerate(clauses)
                                if c.type == "default_statement"
                            ]
                            if default_indices and not (
                                0 in default_indices
                                or (len(clauses) - 1) in default_indices
                            ):
                                violations.append(
                                    Violation(
                                        "Rule 16.5",
                                        "A default label shall appear as either the first or the last switch label of a switch statement.",
                                        file_path,
                                        (
                                            (node.parent.start_point[0] + 1)
                                            if node.parent
                                            else (node.start_point[0] + 1)
                                        ),
                                        trigger=_node_snippet(
                                            node.parent
                                            if node.parent
                                            else node
                                        ),
                                    )
                                )

                            for clause_index, clause in enumerate(clauses):

                                def ends_with_break(
                                    n: tree_sitter.Node,
                                ) -> bool:
                                    if n.type in (
                                        "break_statement",
                                        "return_statement",
                                        "goto_statement",
                                        "continue_statement",
                                    ):
                                        return True
                                    if (
                                        n.type == "compound_statement"
                                        and n.children
                                    ):
                                        stmts = [
                                            c for c in n.children if c.is_named
                                        ]
                                        if stmts:
                                            return ends_with_break(stmts[-1])
                                    return False

                                label_expr_nodes = {
                                    "identifier",
                                    "number_literal",
                                    "char_literal",
                                    "string_literal",
                                    "parenthesized_expression",
                                    "binary_expression",
                                    "unary_expression",
                                    "cast_expression",
                                    "sizeof_expression",
                                }
                                stmts = [
                                    c
                                    for c in clause.children
                                    if c.is_named
                                    and c.type
                                    not in (
                                        "case_statement",
                                        "default_statement",
                                    )
                                    and c.type not in label_expr_nodes
                                ]
                                # Label-group fallthrough (multiple case labels sharing one body) is
                                # represented as clauses without statements before the body clause.
                                # Do not report those as missing break.
                                if not stmts:
                                    continue
                                last_stmt = stmts[-1]
                                if not ends_with_break(last_stmt):
                                    violations.append(
                                        Violation(
                                            "Rule 16.3",
                                            "An unconditional break statement shall terminate every switch-clause.",
                                            file_path,
                                            clause.start_point[0] + 1,
                                            trigger=_node_snippet(clause),
                                        )
                                    )
                        continue
                    elif (
                        rule.name == "Rule 20.1"
                        and capture_name == "tu_includes"
                    ):
                        seen_code = False
                        for c in node.children:
                            if c.type in (
                                "preproc_include",
                                "preproc_def",
                                "preproc_call",
                                "preproc_if",
                                "preproc_ifdef",
                                "preproc_ifndef",
                                "comment",
                            ):
                                if c.type == "preproc_include" and seen_code:
                                    violations.append(
                                        Violation(
                                            "Rule 20.1",
                                            "#include directives should only be preceded by preprocessor directives or comments.",
                                            file_path,
                                            c.start_point[0] + 1,
                                            trigger=_node_snippet(c),
                                        )
                                    )
                            elif c.is_named:
                                seen_code = True
                        continue
                    elif (
                        rule.name == "Rule 20.2"
                        and capture_name == "header_name"
                    ):
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        inner_text = text[1:-1]
                        if any(
                            char in inner_text
                            for char in ("'", '"', "\\", "/*", "//")
                        ):
                            violations.append(
                                Violation(
                                    "Rule 20.2",
                                    "The ', \" or \\ characters and the /* or // character sequences shall not occur in a header file name.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 15.5"
                        and capture_name == "func_body"
                    ):
                        return_count = 0

                        def count_returns(n: tree_sitter.Node) -> None:
                            nonlocal return_count
                            if n.type == "return_statement":
                                return_count += 1
                            # Do not traverse into nested functions (e.g. lambdas in C++)
                            if (
                                n.type == "function_definition"
                                and n != node.parent
                            ):
                                return
                            for c in n.children:
                                count_returns(c)

                        count_returns(node)
                        if return_count > 1:
                            violations.append(
                                Violation(
                                    "Rule 15.5",
                                    "A function should have a single point of exit at the end.",
                                    file_path,
                                    (
                                        (node.parent.start_point[0] + 1)
                                        if node.parent
                                        else (node.start_point[0] + 1)
                                    ),
                                    trigger=_node_snippet(
                                        node.parent if node.parent else node
                                    ),
                                )
                            )
                        continue
                    elif (
                        rule.name == "Rule 15.7"
                        and capture_name == "else_if_chain"
                    ):
                        # We only want to process the root of the if-else-if chain to prevent duplicate reporting
                        if node.parent and node.parent.type == "else_clause":
                            continue

                        # Find the last if_statement in the chain
                        curr = node
                        while True:
                            else_clause = next(
                                (
                                    c
                                    for c in curr.children
                                    if c.type == "else_clause"
                                ),
                                None,
                            )
                            if not else_clause:
                                violations.append(
                                    Violation(
                                        "Rule 15.7",
                                        "All if ... else if constructs shall be terminated with an else statement.",
                                        file_path,
                                        curr.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                                break

                            next_if = next(
                                (
                                    c
                                    for c in else_clause.children
                                    if c.type == "if_statement"
                                ),
                                None,
                            )
                            if next_if:
                                curr = next_if
                            else:
                                break  # Chain ends natively with an else block
                        continue
                    elif rule.name == "Rule 8.2" and capture_name == "param":
                        declarator = next(
                            (
                                c
                                for c in node.children
                                if c.type
                                in (
                                    "identifier",
                                    "pointer_declarator",
                                    "array_declarator",
                                    "function_declarator",
                                    "reference_declarator",
                                )
                            ),
                            None,
                        )
                        if not declarator:
                            types = [
                                c
                                for c in node.children
                                if c.type
                                in ("primitive_type", "type_identifier")
                            ]
                            type_text = "".join(
                                source_code[t.start_byte : t.end_byte].decode(
                                    "utf8", errors="ignore"
                                )
                                for t in types
                            )
                            if type_text != "void" and type_text != "":
                                violations.append(
                                    Violation(
                                        "Rule 8.2",
                                        "Function types shall be in prototype form with named parameters.",
                                        file_path,
                                        node.start_point[0] + 1,
                                        trigger=_node_snippet(node),
                                    )
                                )
                        continue
                    elif (
                        rule.name == "Rule 20.3"
                        and capture_name == "macro_def"
                    ):
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        if "\\\n" in text or "\\\r\n" in text:
                            violations.append(
                                Violation(
                                    "Rule 20.3",
                                    "The \\ character shall not be used to splice a macro definition across more than one line.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=_node_snippet(node),
                                )
                            )
                        continue
                    elif (
                        rule.name
                        in (
                            "Rule 20.8",
                            "Rule 20.9",
                            "Rule 20.13",
                            "Rule 20.14",
                        )
                        and capture_name == "tu_preproc_checks"
                    ):
                        # We only want to run the linear scan once, so we tie it to one of the rules but report both
                        if (
                            rule.name == "Rule 20.8"
                        ):  # only run once for all preprocessor line checks
                            code_lines = source_code.decode(
                                "utf8", errors="ignore"
                            ).splitlines()
                            balance = 0
                            valid_directives = {
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
                            defined_macros: set[str] = set()
                            if project_config:
                                try:
                                    defined_macros.update(
                                        str(k)
                                        for k in getattr(
                                            project_config, "defines", {}
                                        ).keys()
                                    )
                                except Exception:
                                    pass
                            predefined_macros = {
                                "__FILE__",
                                "__LINE__",
                                "__DATE__",
                                "__TIME__",
                                "__STDC__",
                                "__STDC_VERSION__",
                                "__cplusplus",
                                "__GNUC__",
                                "__clang__",
                                "__BASE_FILE__",
                                "__INCLUDE_LEVEL__",
                            }
                            header_define_cache: Dict[Path, set[str]] = {}

                            include_search_paths = [
                                file_path.parent,
                                file_path.parent.parent / "include",
                            ]
                            if project_config:
                                for inc in (
                                    getattr(project_config, "search_paths", [])
                                    or []
                                ):
                                    inc_path = Path(inc)
                                    if not inc_path.is_absolute():
                                        inc_path = (
                                            Path.cwd() / inc_path
                                        ).resolve()
                                    include_search_paths.append(inc_path)

                            def collect_header_defines(
                                header_path: Path,
                                seen: set[Path] | None = None,
                            ) -> set[str]:
                                resolved = header_path.resolve()
                                if resolved in header_define_cache:
                                    return header_define_cache[resolved]
                                if seen is None:
                                    seen = set()
                                if resolved in seen:
                                    return set()
                                seen.add(resolved)
                                macros: set[str] = set()
                                try:
                                    header_lines = resolved.read_text(
                                        encoding="utf-8", errors="ignore"
                                    ).splitlines()
                                except Exception:
                                    header_define_cache[resolved] = macros
                                    return macros
                                for hline in header_lines:
                                    stripped_h = hline.strip()
                                    if stripped_h.startswith("#"):
                                        after_hash_h = stripped_h[1:].strip()
                                        directive_h = (
                                            after_hash_h.split()[0]
                                            if after_hash_h
                                            else ""
                                        )
                                        rest_h = (
                                            after_hash_h[
                                                len(directive_h) :
                                            ].strip()
                                            if directive_h
                                            else ""
                                        )
                                        if directive_h == "define":
                                            m = re.match(
                                                r"([A-Za-z_]\w*)", rest_h
                                            )
                                            if m:
                                                macros.add(m.group(1))
                                        elif directive_h == "include":
                                            m_quote = re.match(
                                                r'"([^"]+)"', rest_h
                                            )
                                            m_angle = re.match(
                                                r"<([^>]+)>", rest_h
                                            )
                                            include_name = (
                                                m_quote.group(1)
                                                if m_quote
                                                else (
                                                    m_angle.group(1)
                                                    if m_angle
                                                    else ""
                                                )
                                            )
                                            if not include_name:
                                                continue
                                            candidates = [
                                                (
                                                    resolved.parent
                                                    / include_name
                                                ).resolve()
                                            ]
                                            for base in include_search_paths:
                                                candidates.append(
                                                    (
                                                        base / include_name
                                                    ).resolve()
                                                )
                                            child = next(
                                                (
                                                    cand
                                                    for cand in candidates
                                                    if cand.exists()
                                                ),
                                                None,
                                            )
                                            if child:
                                                macros.update(
                                                    collect_header_defines(
                                                        child, seen
                                                    )
                                                )
                                header_define_cache[resolved] = macros
                                return macros

                            def strip_wrapping_parens(expr: str) -> str:
                                out = expr.strip()
                                while out.startswith("(") and out.endswith(
                                    ")"
                                ):
                                    out = out[1:-1].strip()
                                return out

                            def parse_int_literal(text: str) -> int | None:
                                lit = strip_wrapping_parens(text).lower()
                                lit = re.sub(r"[uUlL]+$", "", lit)
                                if not lit:
                                    return None
                                try:
                                    if lit.startswith("0x"):
                                        return int(lit, 16)
                                    if lit.startswith("0b"):
                                        return int(lit, 2)
                                    if (
                                        len(lit) > 1
                                        and lit.startswith("0")
                                        and lit.isdigit()
                                    ):
                                        return int(lit, 8)
                                    if lit.isdigit() or (
                                        lit.startswith("-")
                                        and lit[1:].isdigit()
                                    ):
                                        return int(lit, 10)
                                except ValueError:
                                    return None
                                return None

                            for i, code_line in enumerate(code_lines):
                                stripped = code_line.strip()
                                if stripped.startswith("#"):
                                    after_hash = stripped[1:].strip()
                                    directive = (
                                        after_hash.split()[0]
                                        if after_hash
                                        else ""
                                    )
                                    rest = (
                                        after_hash[len(directive) :].strip()
                                        if directive
                                        else ""
                                    )

                                    # Check 20.13
                                    if not directive:
                                        violations.append(
                                            Violation(
                                                "Rule 20.13",
                                                "If the # token appears as the first token on a line, then it shall be immediately followed by a preprocessing token.",
                                                file_path,
                                                i + 1,
                                                trigger=stripped,
                                            )
                                        )
                                    if (
                                        directive
                                        and directive not in valid_directives
                                    ):
                                        violations.append(
                                            Violation(
                                                "Rule 20.13",
                                                f"A line whose first token is # shall be a valid preprocessing directive: '{directive}'",
                                                file_path,
                                                i + 1,
                                                trigger=f"#{directive}",
                                            )
                                        )

                                    if directive == "define":
                                        m = re.match(r"([A-Za-z_]\w*)", rest)
                                        if m:
                                            defined_macros.add(m.group(1))
                                    elif directive == "include":
                                        m_quote = re.match(r'"([^"]+)"', rest)
                                        m_angle = re.match(r"<([^>]+)>", rest)
                                        include_name = (
                                            m_quote.group(1)
                                            if m_quote
                                            else (
                                                m_angle.group(1)
                                                if m_angle
                                                else ""
                                            )
                                        )
                                        if include_name:
                                            candidates = [
                                                (
                                                    file_path.parent
                                                    / include_name
                                                ).resolve()
                                            ]
                                            for base in include_search_paths:
                                                candidates.append(
                                                    (
                                                        base / include_name
                                                    ).resolve()
                                                )
                                            resolved_header = next(
                                                (
                                                    cand
                                                    for cand in candidates
                                                    if cand.exists()
                                                ),
                                                None,
                                            )
                                            if resolved_header:
                                                defined_macros.update(
                                                    collect_header_defines(
                                                        resolved_header
                                                    )
                                                )
                                    elif directive == "undef":
                                        m = re.match(r"([A-Za-z_]\w*)", rest)
                                        if m:
                                            defined_macros.discard(m.group(1))

                                    # Check 20.8 + 20.9 for #if / #elif
                                    if directive in ("if", "elif"):
                                        expr = rest
                                        # Remove comments to avoid treating comment words as identifiers.
                                        expr_no_comments = re.sub(
                                            r"/\*.*?\*/", " ", expr
                                        )
                                        expr_no_comments = (
                                            expr_no_comments.split("//", 1)[0]
                                        )
                                        literal_val = parse_int_literal(
                                            expr_no_comments
                                        )
                                        if (
                                            literal_val is not None
                                            and literal_val not in (0, 1)
                                        ):
                                            violations.append(
                                                Violation(
                                                    "Rule 20.8",
                                                    f"The controlling expression of #{directive} should evaluate to 0 or 1 (found literal value {literal_val}).",
                                                    file_path,
                                                    i + 1,
                                                    trigger=f"#{directive} {expr_no_comments.strip()}",
                                                )
                                            )

                                        identifiers = re.findall(
                                            r"\b[A-Za-z_]\w*\b",
                                            expr_no_comments,
                                        )
                                        filtered = [
                                            ident
                                            for ident in identifiers
                                            if ident
                                            not in {
                                                "defined",
                                                "true",
                                                "false",
                                                "and",
                                                "or",
                                                "not",
                                            }
                                        ]
                                        for ident in filtered:
                                            if not rule_20_9_enabled:
                                                continue
                                            if (
                                                ident not in defined_macros
                                                and ident
                                                not in predefined_macros
                                                and ident
                                                not in rule_20_9_allowed
                                            ):
                                                violations.append(
                                                    Violation(
                                                        "Rule 20.9",
                                                        f"Identifier '{ident}' used in #{directive} expression is not #define'd before evaluation.",
                                                        file_path,
                                                        i + 1,
                                                        trigger=ident,
                                                    )
                                                )

                                    # Check 20.14
                                    if directive in ("if", "ifdef", "ifndef"):
                                        balance += 1
                                    elif directive == "endif":
                                        balance -= 1
                                        if balance < 0:
                                            violations.append(
                                                Violation(
                                                    "Rule 20.14",
                                                    "All #else, #elif and #endif preprocessor directives shall reside in the same file as the directive to which they are related. (Excess #endif)",
                                                    file_path,
                                                    i + 1,
                                                    trigger="#endif",
                                                )
                                            )
                                            balance = 0  # reset to avoid flood
                                    elif directive in ("else", "elif"):
                                        if balance <= 0:
                                            violations.append(
                                                Violation(
                                                    "Rule 20.14",
                                                    "All #else, #elif and #endif preprocessor directives shall reside in the same file as the directive to which they are related. (Orphaned #else/#elif)",
                                                    file_path,
                                                    i + 1,
                                                    trigger=f"#{directive}",
                                                )
                                            )
                            if balance > 0:
                                violations.append(
                                    Violation(
                                        "Rule 20.14",
                                        f"All #else, #elif and #endif preprocessor directives shall reside in the same file as the directive to which they are related. (Missing {balance} #endif)",
                                        file_path,
                                        len(code_lines),
                                        trigger=f"missing_endif={balance}",
                                    )
                                )
                        continue
                    elif rule.name == "Rule 21.X / 27.X":
                        text = source_code[
                            node.start_byte : node.end_byte
                        ].decode("utf8", errors="ignore")
                        if text in ("<stdarg.h>", "<cstdarg>"):
                            violations.append(
                                Violation(
                                    "Rule 17.1",
                                    f"The features of {text} shall not be used.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=text,
                                )
                            )
                        if text in (
                            "<setjmp.h>",
                            "<signal.h>",
                            "<stdio.h>",
                            "<cstdio>",
                            "<time.h>",
                            "<tgmath.h>",
                            "<fenv.h>",
                        ):
                            specific_rule = (
                                "Rule 21.4"
                                if text == "<setjmp.h>"
                                else (
                                    "Rule 21.5"
                                    if text == "<signal.h>"
                                    else (
                                        "Rule 21.6"
                                        if text in ("<stdio.h>", "<cstdio>")
                                        else (
                                            "Rule 21.10"
                                            if text == "<time.h>"
                                            else (
                                                "Rule 21.11"
                                                if text == "<tgmath.h>"
                                                else (
                                                    "Rule 21.12"
                                                    if text == "<fenv.h>"
                                                    else "Rule 21.X"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                            violations.append(
                                Violation(
                                    specific_rule,
                                    f"The standard header file {text} shall not be used.",
                                    file_path,
                                    node.start_point[0] + 1,
                                    trigger=text,
                                )
                            )
                        continue

                    # General rule reporting
                    violations.append(
                        Violation(
                            rule.name,
                            rule.description,
                            file_path,
                            node.start_point[0] + 1,
                            trigger=_node_snippet(node),
                        )
                    )
            except Exception as e:
                # Suppress grammar mismatch syntax errors (e.g. C++ new_expression matched on C language AST)
                if type(e).__name__ == "QueryError" and (
                    "Invalid node type" in str(e) or "Invalid syntax" in str(e)
                ):
                    continue
                import traceback

                logger.error(
                    f"Query failed for rule {rule.name} on file {file_path}: {e}"
                )
                logger.error(traceback.format_exc())

    return violations
