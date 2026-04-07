import argparse
import json
import logging
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import clang.cindex

from exodus.models.project import Project, ProjectConfig
from exodus.tools.analyze.analyze import AnalyzeTool, CrossTUDatabase
from exodus.tools.analyze.misra_clang_rules import analyze_clang_ast
from exodus.tools.analyze.libclang_config import resolve_libclang_path
from exodus.tools.analyze.misra_fallback_scans import run_fallback_source_scans
from exodus.tools.analyze.misra_cpp_postprocess_rules import (
    apply_cpp_postprocess_rules,
)
from exodus.tools.analyze.misra_rules import Violation


class AnalyzeProcessIsolationTests(unittest.TestCase):
    @staticmethod
    def _configure_test_libclang() -> None:
        library_path = resolve_libclang_path(
            preferred_path=ProjectConfig(name="demo").clang_library_file
        )
        if library_path is None:
            raise unittest.SkipTest("libclang is not available for this test")
        if getattr(clang.cindex.conf, "loaded", False):
            return
        clang.cindex.Config.set_library_file(str(library_path))

    def _tool(self, jobs: int = 4) -> AnalyzeTool:
        return AnalyzeTool(
            argparse.Namespace(
                single_rules=None,
                skip_heuristic=None,
                no_clang=False,
                debug_clang=False,
                jobs=jobs,
                misra_profile=None,
            )
        )

    def test_project_config_reads_clang_worker_env_overrides(self) -> None:
        with patch.dict(
            os.environ,
            {
                "EXODUS_CLANG_WORKER_TIMEOUT_SEC": "41",
                "EXODUS_CLANG_WORKER_PARALLELISM": "3",
                "EXODUS_CLANG_PARSE_ONLY_ON_TIMEOUT": "false",
                "EXODUS_CLANG_PARSE_ONLY_ON_CRASH": "0",
                "EXODUS_PROJECT_HEADERS_ONLY": "false",
            },
            clear=False,
        ):
            config = ProjectConfig(name="demo")

        self.assertEqual(config.clang_worker_timeout_sec, 41)
        self.assertEqual(config.clang_worker_parallelism, 3)
        self.assertFalse(config.clang_parse_only_on_timeout)
        self.assertFalse(config.clang_parse_only_on_crash)
        self.assertFalse(config.project_headers_only)

    def test_clang_worker_parallelism_prefers_project_config(self) -> None:
        tool = self._tool(jobs=8)
        config = ProjectConfig(name="demo", clang_worker_parallelism=2)

        self.assertEqual(tool._get_clang_worker_max_workers(config), 2)

    def test_clang_worker_parallelism_defaults_to_four(self) -> None:
        tool = self._tool(jobs=6)
        config = ProjectConfig(name="demo")

        self.assertEqual(config.clang_worker_parallelism, 4)
        self.assertEqual(tool._get_clang_worker_max_workers(config), 4)

    def test_fallback_unreachable_scan_ignores_single_line_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "guard.cpp"
            source.write_text(
                "\n".join(
                    [
                        "int f(bool cond) {",
                        "    if (cond) return 1;",
                        "    return 2;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            violations = run_fallback_source_scans(
                source, is_cpp_file=True, profile_key="cpp2008"
            )

        self.assertFalse(
            any(v.rule == "Rule 0-1-1" for v in violations),
            violations,
        )

    def test_fallback_unreachable_scan_reports_statement_after_block_return(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "unreachable.cpp"
            source.write_text(
                "\n".join(
                    [
                        "int f() {",
                        "    {",
                        "        return 1;",
                        "        int dead = 0;",
                        "    }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            violations = run_fallback_source_scans(
                source, is_cpp_file=True, profile_key="cpp2008"
            )

        dead_lines = [
            v.line for v in violations if v.rule == "Rule 0-1-1"
        ]
        self.assertEqual(dead_lines, [4], violations)

    def test_cpp2008_fallback_does_not_guess_missing_returns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "branchy.cpp"
            source.write_text(
                "\n".join(
                    [
                        "int f(bool cond) {",
                        "    if (cond) {",
                        "        return 1;",
                        "    }",
                        "    return 2;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            violations = run_fallback_source_scans(
                source, is_cpp_file=True, profile_key="cpp2008"
            )

        self.assertFalse(
            any(v.rule == "Rule 8-4-3" for v in violations),
            violations,
        )

    def test_header_patterns_are_root_scoped_and_skip_cache(self) -> None:
        tool = self._tool()
        source_root = Path("/tmp/demo-root")

        self.assertTrue(
            tool._header_matches_patterns(
                source_root / "logger.h",
                source_root,
                ["*.h", "src/core/**/*.h"],
            )
        )

    def test_rule_0_1_10_skips_externally_visible_functions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "runtime.cpp"
            source.write_text(
                "\n".join(
                    [
                        'extern "C" int exported_api() {',
                        "    return 1;",
                        "}",
                        "static int internal_helper() {",
                        "    return 2;",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            self._configure_test_libclang()
            index = clang.cindex.Index.create()
            tu = index.parse(str(source), args=["-std=c++17"])
            funcs = {}
            linkages = {}
            for node in tu.cursor.walk_preorder():
                if (
                    node.location.file
                    and Path(node.location.file.name).resolve()
                    == source.resolve()
                    and node.kind == clang.cindex.CursorKind.FUNCTION_DECL
                    and node.is_definition()
                ):
                    funcs[node.hash] = node
                    linkages[node.hash] = getattr(node, "linkage", None)

            violations: list[Violation] = []
            apply_cpp_postprocess_rules(
                file_path=source,
                violations=violations,
                chapter_15_funcs=[],
                unwrap_expr=lambda n: n,
                is_pointer_or_reference_kind=lambda kind: False,
                get_returned_decl=lambda n: None,
                cpp_entity_decl_lines={},
                rule_2_10_1_enabled=False,
                cpp_typo_scope_names={},
                cpp_static_duration_names={},
                cpp_defined_functions=funcs,
                cpp_function_linkage=linkages,
                cpp_called_functions=set(),
                cpp_void_func_has_side_effect={},
                cpp_var_decls={},
                cpp_var_ref_counts={},
                is_pod_like_type=lambda t: False,
                cpp_known_error_calls_ignored=[],
                logger=logging.getLogger("test"),
            )

        rule_0_1_10 = [v.trigger for v in violations if v.rule == "Rule 0-1-10"]
        self.assertIn("internal_helper", rule_0_1_10)
        self.assertNotIn("exported_api", rule_0_1_10)

    def test_rule_0_1_10_counts_callback_registration_as_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "callbacks.cpp"
            source.write_text(
                "\n".join(
                    [
                        "void register_cb(void (*cb)());",
                        "static void helper() {}",
                        "void run() {",
                        "    register_cb(helper);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            self._configure_test_libclang()
            index = clang.cindex.Index.create()
            tu = index.parse(str(source), args=["-std=c++17"])
            violations = analyze_clang_ast(
                tu,
                source,
                project_config=ProjectConfig(name="demo"),
            )

        rule_0_1_10 = [v.trigger for v in violations if v.rule == "Rule 0-1-10"]
        self.assertNotIn("helper", rule_0_1_10, violations)

    def test_timeout_retry_can_be_disabled_per_project(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            clang_worker_timeout_sec=7,
            clang_parse_only_on_timeout=False,
        )

        with patch(
            "exodus.tools.analyze.analyze.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["clang-worker"], timeout=7),
        ) as run_mock:
            tool._analyze_with_clang_subprocess(
                Path("src/demo.cpp"), is_cpp=True, config=config
            )

        self.assertEqual(run_mock.call_count, 1)

    def test_crash_retry_can_be_disabled_per_project(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            clang_parse_only_on_crash=False,
        )

        with patch(
            "exodus.tools.analyze.analyze.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["clang-worker"],
                returncode=-11,
                stdout="",
                stderr="segfault",
            ),
        ) as run_mock:
            tool._analyze_with_clang_subprocess(
                Path("src/demo.cpp"), is_cpp=True, config=config
            )

        self.assertEqual(run_mock.call_count, 1)

    def test_timeout_retry_uses_parse_only_worker_mode(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            clang_worker_timeout_sec=5,
            clang_parse_only_on_timeout=True,
        )
        responses = [
            subprocess.TimeoutExpired(cmd=["clang-worker"], timeout=5),
            subprocess.CompletedProcess(
                args=["clang-worker"],
                returncode=0,
                stdout=(
                    '{"contract_version": 1, "mode": "tu", "violations": [], '
                    '"identifiers": {}, "ext_objects": {}}'
                ),
                stderr="",
            ),
        ]

        def fake_run(*args, **kwargs):
            result = responses.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        with patch(
            "exodus.tools.analyze.analyze.subprocess.run",
            side_effect=fake_run,
        ) as run_mock:
            tool._analyze_with_clang_subprocess(
                Path("src/demo.cpp"), is_cpp=True, config=config
            )

        self.assertEqual(run_mock.call_count, 2)
        first_env = run_mock.call_args_list[0].kwargs["env"]
        second_env = run_mock.call_args_list[1].kwargs["env"]
        self.assertNotIn("EXODUS_CLANG_PARSE_ONLY", first_env)
        self.assertEqual(second_env["EXODUS_CLANG_PARSE_ONLY"], "1")

    def test_crash_artifact_contains_last_worker_state(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            clang_parse_only_on_crash=False,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            old_cwd = Path.cwd()

            def fake_run(*args, **kwargs):
                state_path = Path(kwargs["env"]["EXODUS_CLANG_STATE_FILE"])
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps(
                        {
                            "stage": "ast-walk-progress",
                            "visited_nodes": 500,
                            "node_kind": "CursorKind.CALL_EXPR",
                            "node_spelling": "dangerous_call",
                            "line": 42,
                            "column": 7,
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    args=["clang-worker"],
                    returncode=-11,
                    stdout="",
                    stderr="[clang-worker] crash\n",
                )

            try:
                os.chdir(root)
                with patch(
                    "exodus.tools.analyze.analyze.subprocess.run",
                    side_effect=fake_run,
                ):
                    tool._analyze_with_clang_subprocess(
                        Path("src/demo.cpp"), is_cpp=True, config=config
                    )
            finally:
                os.chdir(old_cwd)

            crash_file = (
                root
                / "out"
                / "analyze"
                / "demo"
                / "clang_crashes"
                / "src"
                / "demo.cpp.crash.json"
            )
            self.assertTrue(crash_file.exists())
            payload = json.loads(crash_file.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "crash-no-retry")
            self.assertEqual(payload["last_state"]["line"], 42)
            self.assertEqual(
                payload["last_state"]["node_kind"], "CursorKind.CALL_EXPR"
            )

    def test_crash_log_mentions_last_ast_context(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            clang_parse_only_on_crash=False,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            old_cwd = Path.cwd()

            def fake_run(*args, **kwargs):
                state_path = Path(kwargs["env"]["EXODUS_CLANG_STATE_FILE"])
                state_path.parent.mkdir(parents=True, exist_ok=True)
                state_path.write_text(
                    json.dumps(
                        {
                            "stage": "ast-walk-progress",
                            "visited_nodes": 500,
                            "node_kind": "CursorKind.CALL_EXPR",
                            "node_spelling": "dangerous_call",
                            "line": 42,
                            "column": 7,
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(
                    args=["clang-worker"],
                    returncode=-11,
                    stdout="",
                    stderr="[clang-worker] crash\n",
                )

            try:
                os.chdir(root)
                with patch(
                    "exodus.tools.analyze.analyze.subprocess.run",
                    side_effect=fake_run,
                ):
                    with self.assertLogs("exodus.tools.analyze.analyze", level="ERROR") as logs:
                        tool._analyze_with_clang_subprocess(
                            Path("src/demo.cpp"), is_cpp=True, config=config
                        )
            finally:
                os.chdir(old_cwd)

        combined = "\n".join(logs.output)
        self.assertIn("dangerous_call", combined)
        self.assertIn("CursorKind.CALL_EXPR", combined)
        self.assertIn("42:7", combined)

    def test_format_worker_state_inline_uses_state_file_context(self) -> None:
        tool = self._tool()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "worker.state.json"
            state_file.write_text(
                json.dumps(
                    {
                        "stage": "ast-walk-progress",
                        "visited_nodes": 250,
                        "node_kind": "CursorKind.FUNCTION_DECL",
                        "node_spelling": "demo_fn",
                        "line": 12,
                        "column": 3,
                    }
                ),
                encoding="utf-8",
            )

            summary = tool._format_worker_state_inline(state_file)

        self.assertIn("stage=ast-walk-progress", summary)
        self.assertIn("CursorKind.FUNCTION_DECL demo_fn at 12:3", summary)
        self.assertIn("visited_nodes=250", summary)

    def test_display_path_prefers_cwd_relative_paths(self) -> None:
        tool = self._tool()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            nested = root / "src" / "demo.cpp"
            nested.parent.mkdir(parents=True)
            nested.write_text("// demo\n", encoding="utf-8")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                rendered = tool._display_path(nested.resolve())
            finally:
                os.chdir(old_cwd)

        self.assertEqual(rendered, "src/demo.cpp")

    def test_clang_worker_state_update_logs_only_known_state_changes(self) -> None:
        tool = self._tool()
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "worker.state.json"

            unchanged = tool._clang_worker_state_update(
                Path("src/demo.cpp"),
                state_file,
                "state=unknown",
            )
            self.assertEqual(unchanged, "state=unknown")

            state_file.write_text(
                json.dumps(
                    {
                        "stage": "analyze-ast",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertLogs("exodus.tools.analyze.analyze", level="INFO") as logs:
                updated = tool._clang_worker_state_update(
                    Path("src/demo.cpp"),
                    state_file,
                    "state=unknown",
                )

        self.assertEqual(updated, "stage=analyze-ast")
        self.assertIn("Clang worker state: src/demo.cpp -> stage=analyze-ast", "\n".join(logs.output))

    def test_cross_tu_analyze_logs_phase_progress(self) -> None:
        db = CrossTUDatabase()
        db.add("dup_typedef", "a.c", 1, "LinkageKind.NO_LINKAGE", "typedef")
        db.add("dup_typedef", "b.c", 2, "LinkageKind.NO_LINKAGE", "typedef")
        db.update_ext("extern_symbol", "a.c", False, "a.c")
        db.add_decl_signature(
            "extern_symbol",
            "a.c",
            3,
            "int",
            [("int", "lhs")],
        )
        db.add_decl_signature(
            "extern_symbol",
            "b.c",
            4,
            "float",
            [("int", "lhs")],
        )

        with self.assertLogs("exodus.tools.analyze.analyze", level="INFO") as logs:
            violations = db.analyze()

        combined = "\n".join(logs.output)
        self.assertIn("Cross-TU phase: identifier pass starting", combined)
        self.assertIn(
            "Cross-TU phase: external object/signature pass starting",
            combined,
        )
        self.assertTrue(violations)

    def test_collect_reachable_project_headers_skips_unincluded_headers(self) -> None:
        tool = self._tool()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir()
            (root / "include").mkdir()
            (root / "src" / "main.cpp").write_text(
                '#include "used.hpp"\n#include "nested/also_used.hpp"\n',
                encoding="utf-8",
            )
            (root / "include" / "used.hpp").write_text(
                '#include "nested/also_used.hpp"\n',
                encoding="utf-8",
            )
            (root / "include" / "nested").mkdir()
            (root / "include" / "nested" / "also_used.hpp").write_text(
                "// used\n",
                encoding="utf-8",
            )
            (root / "src" / "unused.hpp").write_text("// unused\n", encoding="utf-8")
            (root / "src" / "deep").mkdir()
            (root / "src" / "deep" / "unused2.hpp").write_text(
                "// unused2\n",
                encoding="utf-8",
            )
            config = ProjectConfig(
                name="demo",
                source_root=root,
                search_paths=[Path("include")],
            )

            headers = tool._collect_reachable_project_headers(
                config,
                [root / "src" / "main.cpp"],
            )

        self.assertEqual(
            headers,
            [
                (root / "include" / "nested" / "also_used.hpp").resolve(),
                (root / "include" / "used.hpp").resolve(),
            ],
        )

    def test_project_headers_only_defaults_to_true(self) -> None:
        config = ProjectConfig(name="demo")

        self.assertTrue(config.project_headers_only)

    def test_header_patterns_are_derived_from_source_patterns(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            sources=["src/**/*.cpp", "lib/*.cc"],
        )

        patterns = tool._header_glob_patterns(config)

        self.assertIn("src/**/*.hpp", patterns)
        self.assertIn("src/**/*.h", patterns)
        self.assertIn("lib/*.hh", patterns)
        self.assertIn("lib/*.hxx", patterns)

    def test_explicit_header_patterns_override_derived_patterns(self) -> None:
        tool = self._tool()
        config = ProjectConfig(
            name="demo",
            sources=["src/**/*.cpp"],
            src_pattern_for_headers=["include/public/**/*.hpp"],
        )

        patterns = tool._header_glob_patterns(config)

        self.assertEqual(patterns, ["include/public/**/*.hpp"])

    def test_reachable_headers_respect_header_patterns(self) -> None:
        tool = self._tool()
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src").mkdir()
            (root / "include" / "public").mkdir(parents=True)
            (root / "include" / "private").mkdir(parents=True)
            (root / "src" / "main.cpp").write_text(
                '#include "public/api.hpp"\n#include "private/internal.hpp"\n',
                encoding="utf-8",
            )
            (root / "include" / "public" / "api.hpp").write_text(
                "// public\n",
                encoding="utf-8",
            )
            (root / "include" / "private" / "internal.hpp").write_text(
                "// private\n",
                encoding="utf-8",
            )
            config = ProjectConfig(
                name="demo",
                source_root=root,
                search_paths=[Path("include")],
                src_pattern_for_headers=["include/public/**/*.hpp"],
            )

            headers = tool._collect_reachable_project_headers(
                config,
                [root / "src" / "main.cpp"],
            )

        self.assertEqual(
            headers,
            [(root / "include" / "public" / "api.hpp").resolve()],
        )

    def test_parallel_header_clang_scan_collects_worker_results(self) -> None:
        tool = self._tool(jobs=3)
        config = ProjectConfig(name="demo", clang_worker_parallelism=2)
        headers = [Path("a.hpp"), Path("b.hpp")]

        with patch.object(
            AnalyzeTool,
            "_scan_header_rule_3_1_1_with_clang",
            side_effect=[
                [Violation("Rule 3-1-1", "a", Path("a.hpp"), 1)],
                [Violation("Rule 3-1-1", "b", Path("b.hpp"), 2)],
            ],
        ) as scan_mock:
            result = tool._scan_headers_rule_3_1_1_with_clang_parallel(
                headers, config
            )

        self.assertEqual(len(result), 2)
        self.assertEqual({str(v.file) for v in result}, {"a.hpp", "b.hpp"})
        self.assertEqual(scan_mock.call_count, 2)

    def test_run_returns_130_when_interrupted_in_post_clang_phase(self) -> None:
        tool = AnalyzeTool(
            argparse.Namespace(
                single_rules=None,
                skip_heuristic=["tree-sitter"],
                no_clang=True,
                debug_clang=False,
                jobs=1,
                misra_profile=None,
            )
        )
        project = Project(
            Path.cwd(),
            ProjectConfig(
                name="demo",
                sources=["src/**/*.cpp"],
                misra_profile="cpp2008",
            ),
        )

        with patch("exodus.tools.analyze.analyze.Project.load", return_value=project):
            with patch.object(
                AnalyzeTool,
                "_collect_source_files",
                return_value=[Path("src/demo.cpp")],
            ):
                with patch.object(
                    AnalyzeTool,
                    "_load_compile_commands_for_sources",
                    return_value=None,
                ):
                    with patch.object(
                        AnalyzeTool,
                        "_analyze_file",
                        return_value=None,
                    ):
                        with patch.object(
                            AnalyzeTool,
                            "_record_cpp_general_rules",
                            side_effect=KeyboardInterrupt,
                        ):
                            rc = tool.run()

        self.assertEqual(rc, 130)


if __name__ == "__main__":
    unittest.main()
