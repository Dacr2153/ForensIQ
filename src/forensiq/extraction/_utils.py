# FILE: src/forensiq/extraction/_utils.py
"""Shared utilities for Volatility 3 output parsers.

Private helpers used across all extractor modules — not part of the public API.
"""

from __future__ import annotations

from typing import Any

# Candidate column names for the PID field across different Volatility plugins.
_PID_COLS: tuple[str, ...] = ("PID", "Pid", "pid")


def _find_col(row: dict[str, Any], candidates: tuple[str, ...]) -> Any:
    """Return the value for the first matching column name in a row dict.

    Args:
        row: A single row dict from Volatility JSON output.
        candidates: Ordered list of column name candidates to try.

    Returns:
        The value for the first matching column, or None if none match.
    """
    for col in candidates:
        if col in row:
            return row[col]
    return None
