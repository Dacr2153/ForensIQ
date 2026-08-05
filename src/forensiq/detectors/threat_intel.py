# FILE: src/forensiq/detectors/threat_intel.py
"""Threat Intelligence Detector — VirusTotal and MalwareBazaar hash lookups.

Hashes DLL entries from Volatility dlllist output and queries:
    1. Local SQLite cache (ForensiqDatabase) — always checked first
    2. MalwareBazaar — free, no key required
    3. VirusTotal — optional, requires FORENSIQ_VT_API_KEY

Only hashes for DLLs from suspicious paths are queried (optimization).
Results are cached in the local SQLite database with 24h TTL.

MITRE ATT&CK:
    T1027 — Obfuscated Files or Information
    T1055 — Process Injection (if malicious DLL is injected)
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)


class ThreatIntelDetector(BaseDetector):
    """Look up suspicious DLL hashes against VT and MalwareBazaar.

    This detector is disabled by default because it makes network requests.
    Enable it explicitly when network access is appropriate:

        registry.register(ThreatIntelDetector(enabled=True))
    """

    name = "threat_intel"
    description = (
        "Queries VirusTotal and MalwareBazaar for hashes of suspicious DLLs. "
        "Disabled by default — requires explicit enablement."
    )
    enabled_by_default = False  # Network I/O — opt-in only

    def __init__(self, enabled: bool = False, db_path: Any = None) -> None:
        self._enabled = enabled
        self._db_path = db_path

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Run async threat intel lookups synchronously via asyncio.run()."""
        if not self._enabled:
            return []

        try:
            return asyncio.run(self._detect_async(extraction, vectors))
        except RuntimeError:
            # Already inside an event loop — use create_task approach
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self._detect_async(extraction, vectors))
        except Exception as exc:
            log.warning("Threat intel detection failed", error=str(exc))
            return []

    async def _detect_async(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Async implementation of threat intel lookups."""
        from forensiq.db.manager import ForensiqDatabase
        from forensiq.integrations.malwarebazaar import MalwareBazaarClient

        findings: list[DetectorResult] = []

        # Collect suspicious DLL hashes (only from suspicious paths, to limit requests)
        hashes_to_check: list[tuple[int, str, str, str]] = []  # (pid, proc_name, dll_name, hash)

        pid_to_name: dict[int, str] = {}
        if extraction.process_tree:
            pid_to_name = {pid: proc.name for pid, proc in extraction.process_tree.flat_map.items()}

        for pid, dlls in extraction.dlls.items():
            proc_name = pid_to_name.get(pid, "<unknown>")
            for dll in dlls:
                if dll.is_suspicious and dll.full_path:
                    # Use the path as a proxy ID (no hash in Volatility dlllist)
                    # We hash the path for cache key consistency
                    import hashlib

                    # usedforsecurity=False: MD5 is used only as a cache key
                    # for the DLL path string, not for any cryptographic purpose.
                    path_hash = hashlib.md5(
                        dll.full_path.encode(), usedforsecurity=False
                    ).hexdigest()
                    hashes_to_check.append((pid, proc_name, dll.full_path, path_hash))

        if not hashes_to_check:
            log.info("No suspicious DLL paths to check against threat intel")
            return []

        log.info(
            "Checking threat intel",
            total_hashes=len(hashes_to_check),
        )

        # Check cache first, then query APIs
        async with ForensiqDatabase(db_path=self._db_path) as db:
            mb_hashes: list[tuple[int, str, str, str]] = []
            for pid, proc_name, dll_path, path_hash in hashes_to_check:
                cached = await db.get_threat_intel(path_hash)
                if cached and cached.get("verdict") == "malicious":
                    findings.append(
                        self._make_finding(
                            pid=pid,
                            proc_name=proc_name,
                            dll_path=dll_path,
                            malware_name=cached.get("malware_name", ""),
                            source=cached.get("source", "cache"),
                            confidence=0.90,
                        )
                    )
                elif cached is None:
                    mb_hashes.append((pid, proc_name, dll_path, path_hash))

        # Query MalwareBazaar for uncached hashes (max 20 to be polite)
        async with MalwareBazaarClient() as mb:
            for pid, proc_name, dll_path, path_hash in mb_hashes[:20]:
                result = await mb.lookup_hash(path_hash)
                if result.is_malicious:
                    findings.append(
                        self._make_finding(
                            pid=pid,
                            proc_name=proc_name,
                            dll_path=dll_path,
                            malware_name=result.malware_name,
                            source="malwarebazaar",
                            confidence=0.95,
                        )
                    )
                # Cache the result
                async with ForensiqDatabase(db_path=self._db_path) as db:
                    await db.save_threat_intel(
                        hash_value=path_hash,
                        hash_type="md5_path",
                        source="malwarebazaar",
                        verdict=result.verdict,
                        malware_name=result.malware_name,
                        malware_family=result.malware_family,
                        tags=",".join(result.tags) if result.tags else "",
                        first_seen=result.first_seen,
                    )

        return findings

    def _make_finding(
        self,
        pid: int,
        proc_name: str,
        dll_path: str,
        malware_name: str,
        source: str,
        confidence: float,
    ) -> DetectorResult:
        """Create a DetectorResult for a confirmed malicious DLL."""
        return DetectorResult(
            detector=self.name,
            pid=pid,
            process_name=proc_name,
            severity=FindingSeverity.CRITICAL,
            title=f"Known malicious DLL in {proc_name}: {dll_path.split(chr(92))[-1]}",
            description=(
                f"DLL at {dll_path!r} loaded by {proc_name!r} (PID {pid}) was "
                f"identified as malicious by {source}. "
                f"Malware name: {malware_name or 'Unknown'}."
            ),
            mitre_technique="T1055",
            mitre_technique_name="Process Injection",
            evidence={
                "dll_path": dll_path,
                "malware_name": malware_name,
                "source": source,
            },
            confidence=confidence,
        )
