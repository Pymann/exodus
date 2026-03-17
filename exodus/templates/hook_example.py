"""
Example hook script for Exodus.
This script can be configured as a pre_compilation or pre_linkage hook in project.py.
"""

from typing import TYPE_CHECKING

from exodus.core.logger import get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from exodus.models.project import ProjectConfig


def run(config: "ProjectConfig") -> None:
    """
    Hook entry point.

    Args:
        config: The project configuration object.
    """
    logger.info(f"Executing hook for project: {config.name}")

    # Example: Add a define if not present
    if "HOOK_RAN" not in config.defines:
        config.defines["HOOK_RAN"] = "1"
        logger.info("Set HOOK_RAN define.")

    # Example: Add a debug flag
    if config.debug:
        logger.info("Debug mode is active.")
        pass
        # You could modify flags here
        # config.cpp_compiler.flags.append("-DDEBUG_EXTRA")
