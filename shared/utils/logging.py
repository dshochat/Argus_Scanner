"""structlog setup shared across all pipeline stages."""

from __future__ import annotations

import logging
import sys
from typing import Any

try:
    import structlog
except ImportError:  # structlog is an optional dep until wired into pyproject
    structlog = None  # type: ignore[assignment]


def setup_logging(level: str = "INFO", json_output: bool = False) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        stream=sys.stderr,
        format="%(message)s",
    )
    if structlog is None:
        return
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    processors.append(
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer(),
    )
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    if structlog is None:
        return logging.getLogger(name)
    return structlog.get_logger(name)
