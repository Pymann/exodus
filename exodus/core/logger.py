"""
Logging configuration for Exodus.
"""

import logging
import sys

LOG_FORMAT = "[%(asctime)s][%(funcName)s][%(levelname)s]: %(message)s"


def configure_logging(level_name: str = "INFO") -> None:
    """
    Configures the root logger with stdout handler and specified level.

    Args:
        level_name: standard logging level name.
    """
    level = getattr(logging, level_name.upper(), logging.INFO)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(level)

    # Create handler for stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT)
    handler.setFormatter(formatter)

    # Clear existing handlers to avoid duplicates
    if logger.handlers:
        logger.handlers.clear()

    logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Returns a logger with the given name."""
    return logging.getLogger(name)
