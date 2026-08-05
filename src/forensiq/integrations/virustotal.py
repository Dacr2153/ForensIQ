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

from dataclasses import dataclass, field
from typing import Any

from forensiq.integrations.malwarebazaar import ThreatIntelResult
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

_VT_API_BASE = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD = 3  # Engines needed to flag as malicious


@dataclass
class VTResult(ThreatIntelResult):
    """Extended ThreatIntelResult with VirusTotal-specific fields."""

    positives: int = 0
    total: int = 0
    detection_names: dict[str, str] = field(default_factory=dict)


class VirusTotalClient:
    """Async VirusTotal API v3 client.

    Args:
        api_key: VirusTotal API key. If None, reads from FORENSIQ_VT_API_KEY env.
        timeout: Request timeout in seconds.
    """

    def __init__(self, api_key: str | None = None, timeout: int = 20) -> None:
        import os

        self._api_key = api_key or os.environ.get("FORENSIQ_VT_API_KEY", "")
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

        if not self._client or not self.is_configured():
            return empty_result

        try:
            response = await self._client.get(
                f"{_VT_API_BASE}/files/{hash_value}",
            )
        except Exception as exc:
            log.debug("VirusTotal lookup failed", hash=hash_value[:8], error=str(exc))
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

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        positives = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        is_malicious = positives >= _MALICIOUS_THRESHOLD

        # Collect detection engine names for malicious engines
        detection_names = {
            engine: info.get("result", "")
            for engine, info in results.items()
            if info.get("category") == "malicious" and info.get("result")
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

        return VTResult(
            hash_value=hash_value,
            hash_type=hash_type,
            source="virustotal",
            is_malicious=is_malicious,
            verdict="malicious" if is_malicious else "clean",
            malware_name=malware_name,
            tags=attrs.get("tags", []),
            first_seen=attrs.get("first_submission_date", ""),
            raw_response=attrs,
            positives=positives,
            total=total,
            detection_names=detection_names,
        )
