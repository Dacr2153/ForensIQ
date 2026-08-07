# FILE: src/forensiq/integrations/_base.py
"""Shared helpers for threat-intelligence HTTP clients.

Providers (VirusTotal, MalwareBazaar) share the same sequential, rate-limited
batch pattern. This module keeps that logic in one place so a provider only
needs to implement a single ``lookup_hash`` coroutine.
"""

from __future__ import annotations

import asyncio
from typing import TypeVar

from forensiq.models.threat_intel import ThreatIntelResult

_ResultT = TypeVar("_ResultT", bound=ThreatIntelResult)


class BatchLookupMixin:
    """Provides a rate-limited ``lookup_batch`` over ``lookup_hash``.

    Subclasses must implement:

    .. code-block:: python

        async def lookup_hash(self, hash_value: str) -> _ResultT:
            ...
    """

    async def lookup_hash(self, hash_value: str) -> _ResultT:  # pragma: no cover
        """Look up a single hash (implemented by the concrete client)."""
        raise NotImplementedError

    async def lookup_batch(
        self,
        hashes: list[str],
        delay_ms: int = 100,
    ) -> dict[str, _ResultT]:
        """Look up multiple hashes with rate limiting.

        Duplicate hashes are de-duplicated (first occurrence wins). A
        courtesy delay is inserted between requests to respect provider rate
        limits; ``delay_ms <= 0`` disables the delay.

        Args:
            hashes: List of hash strings to look up.
            delay_ms: Milliseconds between requests.

        Returns:
            Dict mapping hash_value → result.
        """
        results: dict[str, _ResultT] = {}
        unique = list(dict.fromkeys(hashes))
        for i, hash_value in enumerate(unique):
            results[hash_value] = await self.lookup_hash(hash_value)
            if i < len(unique) - 1 and delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000)
        return results
