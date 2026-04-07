import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from exodus.models.project import Project, ProjectConfig
from exodus.tools.aiml_diagram import AimlDiagramTool


class AimlDiagramToolTests(unittest.TestCase):
    def _write_project(self, root: Path) -> None:
        Project(
            root,
            ProjectConfig(name="demo", sources=["frontend/main.aiml"]),
        ).save(root)
        (root / "frontend").mkdir()
        (root / "frontend" / "main.aiml").write_text(
            "\n".join(
                [
                    '- import: "frontend/session.aiml"',
                    "- def:",
                    "    name: main_loop",
                    "    body:",
                    "      - call: [run_session]",
                ]
            ),
            encoding="utf-8",
        )
        (root / "frontend" / "session.aiml").write_text(
            "\n".join(
                [
                    "- def:",
                    "    name: run_session",
                    "    body:",
                    "      - call: [phase_start]",
                    "      - call: [phase_draw]",
                    "      - call: [phase_spell]",
                    "- def:",
                    "    name: phase_start",
                    "    body:",
                    "      - if:",
                    '          condition: { eq: [rm, "draw"] }',
                    "          then:",
                    "            - call: [phase_draw]",
                    "- def:",
                    "    name: phase_draw",
                    "    body:",
                    "      - if:",
                    '          condition: { eq: [rm, "pass_turn"] }',
                    "          then:",
                    "            - call: [phase_spell]",
                    "- def:",
                    "    name: phase_spell",
                    "    body:",
                    '      - call: [bot_phase_spell]',
                    "- def:",
                    "    name: bot_phase_spell",
                    "    body:",
                    "      - call: [execute_card_abilities]",
                ]
            ),
            encoding="utf-8",
        )

    def test_mermaid_output_contains_state_and_usecase_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project(root)
            args = argparse.Namespace(
                path=str(root),
                config="exodus.json",
                all=False,
                entry=[],
                format="mermaid",
                diagram="both",
                output=None,
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = AimlDiagramTool(args).run()

            self.assertEqual(rc, 0)
            rendered = stdout.getvalue()
            self.assertIn("stateDiagram-v2", rendered)
            self.assertIn("phase_start --> phase_draw: run_session", rendered)
            self.assertIn("flowchart LR", rendered)
            self.assertIn("Human --> rpc_draw", rendered)
            self.assertIn("Bot --> bot_bot_phase_spell", rendered)

    def test_plantuml_usecase_output_can_be_written_to_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_project(root)
            args = argparse.Namespace(
                path=str(root),
                config="exodus.json",
                all=False,
                entry=[],
                format="plantuml",
                diagram="usecase",
                output="diagram.puml",
            )

            rc = AimlDiagramTool(args).run()

            self.assertEqual(rc, 0)
            rendered = (root / "diagram.puml").read_text(encoding="utf-8")
            self.assertIn("@startuml", rendered)
            self.assertIn('actor "Human Player" as Human', rendered)
            self.assertIn('usecase "draw"', rendered)
            self.assertIn("Human --> rpc_draw", rendered)


if __name__ == "__main__":
    unittest.main()
