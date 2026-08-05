# FILE: src/forensiq/utils/logger.py
"""ForensIQ structured logging via structlog.

Provides:
    - JSON logging for production (log pipelines, ELK, Splunk)
    - Console logging for development (human-readable, colored)
    - Correlation IDs via contextvars for tracing across pipeline stages
    - Path sanitization (never log full system paths in production)
    - Context binding helpers for structured logging

Usage:
    from forensiq.utils.logger import get_logger, bind_analysis_context

    log = get_logger(__name__)

    with bind_analysis_context(dump_path="/dumps/memory.raw", correlation_id="uuid"):
        log.info("Starting extraction", plugin="windows.pslist")
        log.warning("No network connections found", pid=4)
        log.error("Timeout", plugin="windows.netscan", timeout=300)
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    pass

# ─── Context Variables ────────────────────────────────────────────────────────
# These are stored per async-task / per-thread using Python's contextvars
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_analysis_phase: ContextVar[str] = ContextVar("analysis_phase", default="")
_dump_basename: ContextVar[str] = ContextVar("dump_basename", default="")


# ─── Custom Processors ────────────────────────────────────────────────────────


def _add_correlation_id(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Inject correlation_id from context variable into every log event."""
    cid = _correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def _add_analysis_context(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Inject analysis phase and dump name into log events when set."""
    phase = _analysis_phase.get()
    dump = _dump_basename.get()
    if phase:
        event_dict["phase"] = phase
    if dump:
        event_dict["dump"] = dump
    return event_dict


def _sanitize_paths(
    logger: Any,
    method: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Remove full system paths from log values to prevent info leakage.

    NOTE: Only sanitizes values in the root of event_dict, not nested.
    Full paths are kept in 'dump', 'path', 'output_path' fields for debugging.
    """
    # Fields where full paths are acceptable (for debugging)
    allowed_path_fields = {"dump", "path", "output_path", "model_path", "dump_path"}

    for key, value in event_dict.items():
        if key in allowed_path_fields:
            continue
        if isinstance(value, str) and (value.startswith("/") or value.startswith("C:\\")):
            # Replace with basename only

            event_dict[key] = Path(value).name or value
    return event_dict


# ─── Logger Configuration ─────────────────────────────────────────────────────

_configured = False


def configure_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure structlog for ForensIQ.

    Must be called once at application startup (in CLI entry point).

    Args:
        log_level: Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL.
        log_format: Output format: 'json' (for pipelines) or 'console' (for dev).
    """
    global _configured

    if _configured:
        return

    # Configure standard library logging as a backend for structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    # Processors applied to every log event (order matters)
    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_correlation_id,
        _add_analysis_context,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    # NOTE: JSON format for production (structured log ingestion)
    # Console format for development (human-readable with colors)
    if log_format == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(
            exception_formatter=structlog.dev.plain_traceback,
        )

    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structlog logger.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        A bound structlog logger instance.

    Example:
        log = get_logger(__name__)
        log.info("Plugin complete", plugin="windows.pslist", rows=42)
    """
    return structlog.get_logger(name)


# ─── Context Managers ─────────────────────────────────────────────────────────


@contextmanager
def bind_analysis_context(
    correlation_id: str = "",
    dump_path: str = "",
    phase: str = "",
) -> Generator[None, None, None]:
    """Context manager that binds analysis metadata to all log events within scope.

    Args:
        correlation_id: Unique ID for this analysis run (e.g., UUID4).
        dump_path: Path to the memory dump being analyzed.
        phase: Current pipeline phase name (e.g., 'extraction', 'classification').

    Example:
        with bind_analysis_context(correlation_id=run_id, dump_path=str(dump)):
            log.info("Starting extraction")  # correlation_id auto-included
    """

    # Tokens for resetting context vars on exit
    tokens = []

    if correlation_id:
        tokens.append((_correlation_id, _correlation_id.set(correlation_id)))
    if dump_path:
        # Only store the basename, not full path, in context
        basename = Path(dump_path).name
        tokens.append((_dump_basename, _dump_basename.set(basename)))
    if phase:
        tokens.append((_analysis_phase, _analysis_phase.set(phase)))

    try:
        yield
    finally:
        # Reset context vars to their previous values
        for var, token in tokens:
            var.reset(token)


def set_phase(phase: str) -> None:
    """Update the current analysis phase in the logging context.

    Args:
        phase: Phase name to set (e.g., 'acquisition', 'feature_engineering').
    """
    _analysis_phase.set(phase)
