"""Operational logging for live runs.

Logs are deliberately separate from the event store.  They describe runtime
health and timing, while domain events remain the audit/replay source.  Callers
must pass identifiers and statuses only; request payloads and credentials do
not belong in operational logs.
"""

from __future__ import annotations

import logging
import os
import sys

LOGGER_NAME = "cloud_dast"


def configure_logging() -> None:
    """Configure one stderr handler for a CLI/container process."""

    logger = logging.getLogger(LOGGER_NAME)
    level_name = os.environ.get("CLOUD_DAST_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise TypeError("CLOUD_DAST_LOG_LEVEL must be a valid logging level")
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(handler)
