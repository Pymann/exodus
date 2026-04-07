import argparse
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from exodus.core import cli
from exodus.tools.analyze.analyze import AnalyzeTool


class AnalyzeCliTests(unittest.TestCase):
    def test_skip_heuristic_help_mentions_clang_cross_tu_link(self) -> None:
        with patch("sys.argv", ["exodus", "analyze", "--help"]):
            stdout = io.StringIO()
            with redirect_stdout(stdout), self.assertRaises(SystemExit) as ctx:
                cli.main()

        self.assertEqual(ctx.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("--skip-heuristic", help_text)
        self.assertIn("Note: skipping clang also disables", help_text)
        self.assertIn("cross-tu automatically.", help_text)

    def test_skip_heuristic_clang_also_skips_cross_tu(self) -> None:
        args = argparse.Namespace(
            single_rules=None,
            skip_heuristic=["clang"],
            no_clang=False,
            debug_clang=False,
            jobs=1,
            misra_profile=None,
        )

        tool = AnalyzeTool(args)

        self.assertIn("clang", tool.skipped_heuristics)
        self.assertIn("cross-tu", tool.skipped_heuristics)
        self.assertFalse(tool._heuristic_enabled("clang"))
        self.assertFalse(tool._heuristic_enabled("cross-tu"))

    def test_skip_heuristic_aliases_are_normalized(self) -> None:
        selected = AnalyzeTool._parse_skip_heuristics(
            ["ts,crosstu", "config", "regex"]
        )

        self.assertEqual(
            selected,
            {"tree-sitter", "cross-tu", "project-config", "header-scan"},
        )


if __name__ == "__main__":
    unittest.main()
