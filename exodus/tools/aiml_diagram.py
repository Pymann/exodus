"""Generate project-level AIML diagrams from YAML-shaped source files."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from exodus.core.logger import get_logger
from exodus.models.project import Project


@dataclass
class AimlSymbol:
    """One AIML definition or method with extracted structure."""

    name: str
    file_path: Path
    kind: str
    calls: list[str] = field(default_factory=list)
    rpc_methods: set[str] = field(default_factory=set)


@dataclass
class AimlFile:
    """Parsed AIML file metadata."""

    path: Path
    imports: list[str] = field(default_factory=list)
    symbols: list[AimlSymbol] = field(default_factory=list)


class AimlDiagramTool:
    """Generate Mermaid or PlantUML state/use-case diagrams for AIML projects."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    def run(self) -> int:
        root = Path(self.args.path).resolve()
        files = self._load_project_files(root)
        if not files:
            self.logger.error("No AIML files found for diagram generation.")
            return 1

        output = self._render_output(files)
        if self.args.output:
            output_path = Path(self.args.output)
            if not output_path.is_absolute():
                output_path = root / output_path
            output_path.write_text(output, encoding="utf-8", newline="\n")
        else:
            sys.stdout.write(output)
            if not output.endswith("\n"):
                sys.stdout.write("\n")
        return 0

    def _load_project_files(self, root: Path) -> list[AimlFile]:
        entry_files: list[Path] = []
        if self.args.all:
            for config_name in Project.discover_config_names(root):
                project = Project.load(root, config_name=config_name)
                entry_files.extend(self._project_entry_files(project))
        else:
            project = Project.load(root, config_name=self.args.config)
            entry_files.extend(self._project_entry_files(project))

        if self.args.entry:
            for raw in self.args.entry:
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = root / candidate
                entry_files.append(candidate.resolve())

        if not entry_files:
            entry_files = sorted(root.rglob("*.aiml"))

        parsed: dict[Path, AimlFile] = {}
        pending = sorted({path.resolve() for path in entry_files if path.exists()})
        while pending:
            current = pending.pop(0)
            if current in parsed:
                continue
            file_info = self._parse_file(current)
            if file_info is None:
                continue
            parsed[current] = file_info
            for raw_import in file_info.imports:
                resolved = self._resolve_import(current, root, raw_import)
                if resolved is not None and resolved not in parsed and resolved not in pending:
                    pending.append(resolved)
        return sorted(parsed.values(), key=lambda item: str(item.path))

    @staticmethod
    def _project_entry_files(project: Project) -> list[Path]:
        patterns = [pat for pat in project.config.sources if pat.strip()]
        if not patterns:
            return sorted(project.root.rglob("*.aiml"))
        files: list[Path] = []
        for pattern in patterns:
            files.extend(
                path.resolve()
                for path in project.root.glob(pattern)
                if path.is_file() and path.suffix == ".aiml"
            )
        return sorted(set(files))

    def _parse_file(self, path: Path) -> AimlFile | None:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            self.logger.warning("Skipping AIML file %s: %s", path, exc)
            return None

        items: list[Any]
        if payload is None:
            items = []
        elif isinstance(payload, list):
            items = payload
        else:
            items = [payload]

        file_info = AimlFile(path=path)
        for item in items:
            if not isinstance(item, dict):
                continue
            if "import" in item:
                imports = item["import"]
                if isinstance(imports, str):
                    file_info.imports.append(imports)
                elif isinstance(imports, list):
                    file_info.imports.extend(
                        value for value in imports if isinstance(value, str)
                    )
            if "def" in item and isinstance(item["def"], dict):
                symbol = self._parse_symbol(path, item["def"], "def")
                if symbol is not None:
                    file_info.symbols.append(symbol)
            if "class" in item and isinstance(item["class"], dict):
                class_info = item["class"]
                class_name = str(class_info.get("name", "")).strip() or path.stem
                methods = class_info.get("methods", [])
                if isinstance(methods, list):
                    for method_item in methods:
                        if not isinstance(method_item, dict):
                            continue
                        if "def" not in method_item or not isinstance(method_item["def"], dict):
                            continue
                        symbol = self._parse_symbol(
                            path,
                            method_item["def"],
                            f"class:{class_name}",
                        )
                        if symbol is not None:
                            file_info.symbols.append(symbol)
        return file_info

    def _parse_symbol(
        self, path: Path, payload: dict[str, Any], kind: str
    ) -> AimlSymbol | None:
        name = str(payload.get("name", "")).strip()
        if not name:
            return None
        body = payload.get("body", [])
        calls = list(self._iter_calls(body))
        rpc_methods = self._collect_rpc_methods(body)
        return AimlSymbol(
            name=name,
            file_path=path,
            kind=kind,
            calls=calls,
            rpc_methods=rpc_methods,
        )

    def _resolve_import(
        self, source_file: Path, root: Path, raw_import: str
    ) -> Path | None:
        candidate = Path(raw_import)
        search_order = []
        if candidate.is_absolute():
            search_order.append(candidate)
        else:
            search_order.append((source_file.parent / candidate).resolve())
            search_order.append((root / candidate).resolve())
        for resolved in search_order:
            if resolved.exists() and resolved.is_file():
                return resolved
        return None

    def _render_output(self, files: list[AimlFile]) -> str:
        sections: list[str] = []
        if self.args.diagram in {"state", "both"}:
            sections.append(self._render_state_diagram(files))
        if self.args.diagram in {"usecase", "both"}:
            sections.append(self._render_usecase_diagram(files))
        return "\n\n".join(section for section in sections if section.strip())

    def _render_state_diagram(self, files: list[AimlFile]) -> str:
        symbols = self._all_symbols(files)
        state_names = {
            symbol.name
            for symbol in symbols.values()
            if symbol.name.startswith(("phase_", "state_"))
            or symbol.name in {"run_session", "main_loop"}
        }
        edges: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for symbol in symbols.values():
            if not (
                symbol.name in state_names
                or symbol.name.startswith(("run_", "main_"))
            ):
                continue
            ordered_states = [
                call for call in symbol.calls if call in state_names and call != symbol.name
            ]
            if symbol.name in state_names and ordered_states:
                edge = (symbol.name, ordered_states[0], symbol.name)
                if edge not in seen:
                    edges.append(edge)
                    seen.add(edge)
            for left, right in zip(ordered_states, ordered_states[1:]):
                edge = (left, right, symbol.name)
                if edge not in seen:
                    edges.append(edge)
                    seen.add(edge)

        if self.args.format == "plantuml":
            lines = ["@startuml", "hide empty description", "[*] --> run_session"]
            if not edges and "run_session" in state_names:
                lines.append("run_session --> [*]")
            for source, target, label in edges:
                lines.append(f"{source} --> {target} : {label}")
            lines.append("@enduml")
            return "\n".join(lines)

        lines = ["stateDiagram-v2", "    [*] --> run_session"]
        if not edges and "run_session" in state_names:
            lines.append("    run_session --> [*]")
        for source, target, label in edges:
            lines.append(f"    {source} --> {target}: {label}")
        return "\n".join(lines)

    def _render_usecase_diagram(self, files: list[AimlFile]) -> str:
        symbols = self._all_symbols(files)
        rpc_methods = sorted(
            {
                method
                for symbol in symbols.values()
                for method in symbol.rpc_methods
            }
        )
        bot_methods = sorted(
            symbol.name
            for symbol in symbols.values()
            if symbol.name.startswith("bot_")
        )
        system_methods = sorted(
            symbol.name
            for symbol in symbols.values()
            if symbol.name.startswith(("phase_", "run_"))
        )

        if self.args.format == "plantuml":
            lines = [
                "@startuml",
                'left to right direction',
                'actor "Human Player" as Human',
                'actor "Bot AI" as Bot',
                'actor "Session Runtime" as Runtime',
                'rectangle "AIML Project" {',
            ]
            for method in rpc_methods:
                alias = self._alias("rpc_" + method)
                lines.append(f'  usecase "{method}" as {alias}')
            for method in bot_methods:
                alias = self._alias("bot_" + method)
                lines.append(f'  usecase "{method}" as {alias}')
            for method in system_methods:
                alias = self._alias("sys_" + method)
                lines.append(f'  usecase "{method}" as {alias}')
            lines.append("}")
            for method in rpc_methods:
                lines.append(f'Human --> {self._alias("rpc_" + method)}')
            for method in bot_methods:
                lines.append(f'Bot --> {self._alias("bot_" + method)}')
            for method in system_methods:
                lines.append(f'Runtime --> {self._alias("sys_" + method)}')
            lines.append("@enduml")
            return "\n".join(lines)

        lines = ["flowchart LR", "    Human[Human Player]", "    Bot[Bot AI]", "    Runtime[Session Runtime]"]
        for method in rpc_methods:
            alias = self._alias("rpc_" + method)
            lines.append(f"    {alias}(({method}))")
            lines.append(f"    Human --> {alias}")
        for method in bot_methods:
            alias = self._alias("bot_" + method)
            lines.append(f"    {alias}(({method}))")
            lines.append(f"    Bot --> {alias}")
        for method in system_methods:
            alias = self._alias("sys_" + method)
            lines.append(f"    {alias}(({method}))")
            lines.append(f"    Runtime --> {alias}")
        return "\n".join(lines)

    @staticmethod
    def _alias(value: str) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in value)

    @staticmethod
    def _all_symbols(files: list[AimlFile]) -> dict[str, AimlSymbol]:
        symbols: dict[str, AimlSymbol] = {}
        for file_info in files:
            for symbol in file_info.symbols:
                symbols.setdefault(symbol.name, symbol)
        return symbols

    def _iter_calls(self, node: Any) -> Iterable[str]:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "call" and isinstance(value, list) and value:
                    callee = value[0]
                    if isinstance(callee, str) and callee.strip():
                        yield callee.strip()
                yield from self._iter_calls(value)
        elif isinstance(node, list):
            for item in node:
                yield from self._iter_calls(item)

    def _collect_rpc_methods(self, node: Any) -> set[str]:
        methods: set[str] = set()
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "eq" and isinstance(value, list) and len(value) == 2:
                    left, right = value
                    if (
                        isinstance(left, str)
                        and isinstance(right, str)
                        and left
                        and right
                    ):
                        if right.endswith(".method") or right in {
                            "rm",
                            "rm2",
                            "method",
                        }:
                            methods.add(left)
                        elif left.endswith(".method") or left in {
                            "rm",
                            "rm2",
                            "method",
                        }:
                            methods.add(right)
                methods.update(self._collect_rpc_methods(value))
        elif isinstance(node, list):
            for item in node:
                methods.update(self._collect_rpc_methods(item))
        return methods
