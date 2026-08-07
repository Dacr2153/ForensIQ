# FILE: src/forensiq/integrations/virustotal.py
"""VirusTotal API v3 client for hash-based IOC lookups.

Requires API key: set FORENSIQ_VT_API_KEY environment variable.
Free API tier: 4 requests/minute, 500 requests/day.

API documentation: https://developers.virustotal.com/reference/files

Usage:
    async with VirusTotalClient(api_key="your_key") as client:
        result = await client.lookup_hash("abc123...")
        if result.is_malicious:
            print(f"Detected by {result.positives}/{result.total} engines")

Note: VT API v3 uses SHA256 as the primary hash identifier.
MD5 lookups are supported but SHA256 is preferred.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from forensiq.config.settings import get_settings
from forensiq.integrations._base import BatchLookupMixin
from forensiq.models.threat_intel import ThreatIntelResult
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

_VT_API_BASE = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD = 3  # Engines needed to flag as malicious
# MD5 (32), SHA-1 (40), SHA-256 (64) — all lowercase hex
_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")

# Transient-error retry policy: 429 rate limits, 5xx, and connection/timeout
# errors are retried up to 3 times with exponential backoff. 4xx responses
# (other than 429) are not transient and are not retried.
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 2.0


@dataclass
class VTResult(ThreatIntelResult):
    """Extended ThreatIntelResult with VirusTotal-specific fields."""

    positives: int = 0
    total: int = 0
    detection_names: dict[str, str] = field(default_factory=dict)


class VirusTotalClient(BatchLookupMixin):
    """Async VirusTotal API v3 client.

    Args:
        api_key: VirusTotal API key. If None, reads from FORENSIQ_VT_API_KEY env.
        timeout: Request timeout in seconds.
    """

    def __init__(self, api_key: str | None = None, timeout: int = 20) -> None:
        if api_key is None:
            try:
                api_key = get_settings().VT_API_KEY
            except Exception:
                api_key = ""
        if not api_key:
            import os

            api_key = os.environ.get("FORENSIQ_VT_API_KEY", "")
        self._api_key = api_key
        self._timeout = timeout
        self._client: Any = None

    def is_configured(self) -> bool:
        """Return True if API key is available."""
        return bool(self._api_key)

    async def __aenter__(self) -> VirusTotalClient:
        if not self.is_configured():
            log.debug("VirusTotal API key not configured — integration disabled")
            return self
        try:
            import httpx

            self._client = httpx.AsyncClient(
                timeout=self._timeout,
                headers={"x-apikey": self._api_key},
            )
        except ImportError:
            log.warning("httpx not available — VirusTotal integration disabled")
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    async def lookup_hash(self, hash_value: str) -> VTResult:
        """Look up a file hash on VirusTotal.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            VTResult with detection counts and engine names.
        """
        hash_type = (
            "sha256" if len(hash_value) == 64 else "sha1" if len(hash_value) == 40 else "md5"
        )

        empty_result = VTResult(
            hash_value=hash_value,
            hash_type=hash_type,
            source="virustotal",
            is_malicious=False,
            verdict="unavailable",
        )

        # Reject malformed hashes — a non-hex / wrong-length string must never
        # be sent in the request path.
        if not _HASH_RE.fullmatch(hash_value):
            log.debug("Rejected malformed hash", hash=hash_value[:8])
            empty_result.verdict = "error"
            return empty_result

        if not self._client or not self.is_configured():
            return empty_result

        # Retry transient failures (429 rate limits, 5xx, connection/timeout
        # errors) with exponential backoff. Return the final response.
        response: Any = None
        last_status: int = 0
        for attempt in range(_MAX_RETRIES):
            try:
                response = await self._client.get(f"{_VT_API_BASE}/files/{hash_value}")
                last_status = int(response.status_code)
                if last_status not in (429,) and last_status < 500:
                    break
            except Exception as exc:
                log.debug(
                    "VirusTotal request failed",
                    hash=hash_value[:8],
                    attempt=attempt + 1,
                    error=str(exc),
                )
                last_status = 0
            if attempt < _MAX_RETRIES - 1:
                await asyncio.sleep(_BASE_BACKOFF_SECONDS * (2**attempt))

        if response is None or last_status == 0:
            empty_result.verdict = "error"
            return empty_result

        if response.status_code == 404:
            return VTResult(
                hash_value=hash_value,
                hash_type=hash_type,
                source="virustotal",
                is_malicious=False,
                verdict="unknown",
            )

        if response.status_code == 429:
            log.warning("VirusTotal rate limit exceeded")
            empty_result.verdict = "rate_limited"
            return empty_result

        if response.status_code != 200:
            log.debug("VirusTotal returned non-200", status=response.status_code)
            empty_result.verdict = "error"
            return empty_result

        try:
            data = response.json()
        except Exception as exc:
            log.debug("VirusTotal JSON parse error", error=str(exc))
            empty_result.verdict = "error"
            return empty_result

        # Guard against 200 responses carrying an error body or unexpected shape
        # — an unguarded `.get()` here previously produced false "clean" verdicts.
        if not isinstance(data, dict) or data.get("error"):
            log.debug("VirusTotal returned error body", hash=hash_value[:8])
            empty_result.verdict = "error"
            return empty_result

        data_attrs = data.get("data")
        attrs = data_attrs.get("attributes", {}) if isinstance(data_attrs, dict) else {}
        if not isinstance(attrs, dict):
            attrs = {}
        stats = attrs.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            stats = {}
        results = attrs.get("last_analysis_results", {})
        if not isinstance(results, dict):
            results = {}

        positives = int(stats.get("malicious", 0) or 0)
        total = sum(int(v) for v in stats.values()) if stats else 0
        is_malicious = positives >= _MALICIOUS_THRESHOLD

        # Collect detection engine names for malicious engines
        detection_names = {
            engine: info.get("result", "")
            for engine, info in results.items()
            if isinstance(info, dict)
            and info.get("category") == "malicious"
            and info.get("result")
        }

        # Get best malware name from popular AV engines
        malware_name = ""
        priority_engines = ["Kaspersky", "Microsoft", "Symantec", "Sophos", "ESET-NOD32"]
        for eng in priority_engines:
            if detection_names.get(eng):
                malware_name = detection_names[eng]
                break
        if not malware_name and detection_names:
            malware_name = next(iter(detection_names.values()))

        # VT reports first_submission_date as a Unix epoch (int) — normalize to ISO.
        first_seen = attrs.get("first_submission_date", "")
        if isinstance(first_seen, (int, float)) and first_seen:
            first_seen = datetime.fromtimestamp(first_seen, tz=UTC).isoformat()

        return VTResult(
            hash_value=hash_value,
            hash_type=hash_type,
            source="virustotal",
            is_malicious=is_malicious,
            verdict="malicious" if is_malicious else "clean",
            malware_name=malware_name,
            tags=attrs.get("tags", []) or [],
            first_seen=str(first_seen or ""),
            raw_response=attrs,
            positives=positives,
            total=total,
            detection_names=detection_names,
        )
