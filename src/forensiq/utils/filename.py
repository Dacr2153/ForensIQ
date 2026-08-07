# FILE: src/forensiq/utils/filename.py
"""Filename sanitization helpers."""

from __future__ import annotations

import re


def safe_filename(stem: str, max_len: int = 50) -> str:
    """Sanitize a file stem into a filesystem-safe token.

    Replaces every character that is not an ASCII letter, digit, hyphen,
    or underscore with an underscore, and caps the length.

    Args:
        stem: Raw file stem (e.g., the dump path stem) to sanitize.
        max_len: Maximum length of the returned token (default 50).

    Returns:
        A sanitized stem safe to embed in an output filename.
    """
    return re.sub(r"[^a-zA-Z0-9_-]", "_", stem)[:max_len]
