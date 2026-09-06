"""
TraceMail AI — Standardized Logging Engine
Provides unified structured logging across all microservices.
"""

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Returns a pre-configured logger instance with clean cybersecurity formatting."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
