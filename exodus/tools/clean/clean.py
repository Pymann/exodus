"""
Clean tool implementation.
"""

import argparse
import os
import shutil
from pathlib import Path
from typing import Optional

from exodus.models.project import Project, ProjectConfig
from exodus.core.logger import get_logger


class CleanTool:
    """Tool for cleaning build artifacts."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    @staticmethod
    def _project_build_root(config: ProjectConfig) -> Path:
        project_name = (config.name or "project").strip() or "project"
        safe_name = "".join(
            ch if ch.isalnum() or ch in ("-", "_", ".") else "_"
            for ch in project_name
        )
        return config.build_root / safe_name

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
        return output_name

    def _clean_config(self, config: ProjectConfig) -> None:
        """Cleans build artifacts for a single project configuration."""
        # Remove project build directory
        build_dir = self._project_build_root(config)
        if build_dir.exists():
            self.logger.info("cleaning build dir %s", build_dir)
            shutil.rmtree(build_dir)

        # Remove linked artifact if it was placed in cwd
        if config.artifact_in_cwd:
            artifact = Path.cwd() / self._linked_output_name(config)
            if artifact.exists():
                self.logger.info("removing artifact %s", artifact)
                artifact.unlink()

    def run(self, project: Optional["Project"] = None) -> None:
        """Executes the clean command."""
        try:
            if getattr(self.args, "all", False):
                config_names = Project.discover_config_names(Path.cwd())
                if not config_names:
                    self.logger.info("no config files found, nothing to clean")
                    return
                for config_name in config_names:
                    proj = Project.load(Path.cwd(), config_name=config_name)
                    self.logger.info("cleaning project %s (%s)", proj.config.name, config_name)
                    self._clean_config(proj.config)
            else:
                if project is None:
                    config_name = (
                        getattr(self.args, "config", "exodus.json")
                        or "exodus.json"
                    )
                    project = Project.load(Path.cwd(), config_name=config_name)
                self._clean_config(project.config)

        except Exception as e:
            self.logger.error("Error cleaning: %s", e)
