"""
Init tool implementation.
"""

import argparse
import shutil
from pathlib import Path
from typing import List
from exodus.models.project import Project, ProjectConfig
from exodus.core.logger import get_logger


class InitTool:
    """Tool for initializing new projects."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.logger = get_logger(__name__)

    def run(self) -> None:
        """Executes the init command."""
        template_name = self.args.template
        target_path = Path(self.args.project).resolve()

        # Locate templates directory
        # exodus/tools/init/init.py -> exodus/
        package_root = Path(__file__).parent.parent.parent
        template_dir = package_root / "templates" / template_name

        if not template_dir.exists():
            return

        # Create target directory
        full_target_path = target_path  # Renaming for clarity
        if not full_target_path.exists():
            full_target_path.mkdir(parents=True, exist_ok=True)

        # Copy template files
        for item in template_dir.iterdir():
            if item.is_file():
                shutil.copy2(item, full_target_path)
            elif item.is_dir():
                shutil.copytree(
                    item, full_target_path / item.name, dirs_exist_ok=True
                )

        # Copy hook example
        hook_src = package_root / "templates" / "hook_example.py"
        if hook_src.exists():
            shutil.copy2(hook_src, full_target_path)

        # Check if exodus.json exists (from template)
        config_file = full_target_path / "exodus.json"
        if config_file.exists():
            # Load and update name
            project = Project.load(full_target_path)
            project.config.name = full_target_path.name
            project.config.pre_compilation = Path("hook_example.py")
            project.save(full_target_path)
        else:
            # Create and save default configuration
            config = ProjectConfig(
                name=full_target_path.name,
                version="0.1.0",
                sources=["*.c", "*.cpp", "*.cc"],  # Default sources
                pre_compilation=Path("hook_example.py"),
                # pre_linkage=Path("hook_example.py"),
            )

            project = Project(full_target_path, config)
            project.save(full_target_path)


def get_available_templates() -> List[str]:
    """Returns a list of available project templates."""
    package_root = Path(__file__).parent.parent.parent
    template_dir = package_root / "templates"
    if not template_dir.exists():
        return []

    return [
        d.name
        for d in template_dir.iterdir()
        if d.is_dir() and not d.name.startswith("__")
    ]
