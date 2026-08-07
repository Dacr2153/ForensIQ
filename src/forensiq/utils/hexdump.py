# FILE: src/forensiq/utils/hexdump.py
"""Volatility hexdump decoding helpers."""

from __future__ import annotations


def hexdump_to_bytes(hexdump: str) -> bytes:
    """Decode a Volatility-style hexdump string to raw bytes.

    Volatility's malfind hexdump format includes an address column and an
    ASCII render column in addition to the hex bytes::

        0xfffff80411234567  4d 5a 90 00 03 00 00 00  ff ff 00 00  MZ..............

    Only whitespace-delimited tokens of pure hex digits represent real
    bytes; the address prefix and ASCII column must be ignored. Tokens are
    accepted in both Volatility byte-group (``4d 5a 90 00``) and compact
    (``4d5a 9000``) forms; any token with non-hex content (addresses like
    ``0xfffff804...``, ASCII like ``MZ....``) is dropped.

    Args:
        hexdump: Hex string from MalfindRegion.hexdump.

    Returns:
        Raw bytes decoded from the hex tokens. Empty bytes on failure.
    """
    if not hexdump:
        return b""

    byte_tokens = [
        tok
        for tok in hexdump.split()
        if tok
        and len(tok) % 2 == 0
        and all(c in "0123456789abcdefABCDEF" for c in tok)
    ]
    if not byte_tokens:
        return b""
    try:
        return bytes.fromhex("".join(byte_tokens))
    except ValueError:
        return b""
