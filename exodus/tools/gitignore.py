"""Generate or extend a project .gitignore with Exodus artifacts."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Iterable, List

from exodus.core.logger import get_logger
from exodus.models.project import Project, ProjectConfig

_SECTION_HEADER = "# Exodus artifacts"
_DEFAULT_ENTRIES = ("out/", "__exodus_cache/")


class GitignoreTool:
    """Create or extend .gitignore entries for Exodus-generated artifacts."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    @staticmethod
    def _normalize_dir_entry(path: Path | str) -> str:
        text = Path(path).as_posix().strip()
        if not text or text == ".":
            return ""
        return text if text.endswith("/") else f"{text}/"

    @staticmethod
    def _linked_output_name(config: ProjectConfig) -> str:
        output_name = config.name
        if os.name == "nt":
            output_name += ".exe"
        elif config.output_type == "static_lib":
            output_name = f"lib{config.name}.a"
        elif config.output_type == "shared_lib":
            prefix = "" if config.name.startswith("lib") else "lib"
            output_name = f"{prefix}{config.name}.so"
        elif config.output_type == "wasm":
            output_name = f"{config.name}.wasm"
        return output_name

    @classmethod
    def collect_entries(
        cls, configs: Iterable[ProjectConfig] | None = None
    ) -> List[str]:
        entries: list[str] = list(_DEFAULT_ENTRIES)
        for config in configs or []:
            build_root = cls._normalize_dir_entry(config.build_root)
            if build_root and build_root not in entries:
                entries.append(build_root)

            if config.artifact_in_cwd:
                artifact_name = cls._linked_output_name(config)
                if artifact_name and artifact_name not in entries:
                    entries.append(artifact_name)

            map_file = config.linker.map_file
            if map_file and not map_file.is_absolute():
                map_entry = Path(map_file).as_posix()
                if map_entry and map_entry not in entries:
                    entries.append(map_entry)
        return entries

    def _load_configs(self) -> List[ProjectConfig]:
        configs: list[ProjectConfig] = []
        if getattr(self.args, "all", False):
            config_names = Project.discover_config_names(Path.cwd())
            for config_name in config_names:
                configs.append(Project.load(Path.cwd(), config_name=config_name).config)
            return configs

        config_name = getattr(self.args, "config", "exodus.json") or "exodus.json"
        config_path = Path.cwd() / config_name
        if not config_path.exists():
            return []
        return [Project.load(Path.cwd(), config_name=config_name).config]

    def _render_gitignore(self, current_text: str, entries: Iterable[str]) -> str:
        existing_lines = current_text.splitlines()
        existing = set(existing_lines)
        additions = [entry for entry in entries if entry and entry not in existing]
        if not additions:
            return current_text

        lines = existing_lines[:]
        if lines and lines[-1] != "":
            lines.append("")
        if _SECTION_HEADER not in existing:
            lines.append(_SECTION_HEADER)
        lines.extend(additions)
        return "\n".join(lines) + "\n"

    def run(self) -> int:
        try:
            configs = self._load_configs()
            entries = self.collect_entries(configs)
            gitignore_path = Path.cwd() / ".gitignore"
            current_text = (
                gitignore_path.read_text(encoding="utf-8")
                if gitignore_path.exists()
                else ""
            )
            updated_text = self._render_gitignore(current_text, entries)
            if updated_text == current_text:
                self.logger.info(".gitignore already covers Exodus artifacts")
                return 0

            gitignore_path.write_text(updated_text, encoding="utf-8")
            self.logger.info("updated %s", gitignore_path)
            return 0
        except Exception as exc:
            self.logger.error("Error updating .gitignore: %s", exc)
            return 1
