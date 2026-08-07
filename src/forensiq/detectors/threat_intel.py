# FILE: src/forensiq/detectors/threat_intel.py
"""Threat Intelligence Detector — VirusTotal-first hash IOC lookups.

Queries genuine SHA-256 content hashes of suspicious DLLs against:
    1. Local SQLite cache (ForensiqDatabase) — always checked first
    2. VirusTotal — primary source (requires FORENSIQ_VT_API_KEY)
    3. MalwareBazaar — secondary fallback (free, no key required)

Only real file-content hashes are ever sent to the APIs. A hash computed
from the DLL *path string* is meaningless to VT/MalwareBazaar and is never
fabricated. DLLs without a known content hash are skipped entirely.

Hashes are only collected for DLLs from suspicious paths (optimization).
Results are cached in the local SQLite database with 24h TTL.

MITRE ATT&CK:
    T1027 — Obfuscated Files or Information
    T1055 — Process Injection (if malicious DLL is injected)
"""

from __future__ import annotations

import asyncio
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VT_DEFAULT_DELAY_MS = 15_000  # VT free tier: 4 requests/minute
_MB_DEFAULT_DELAY_MS = 100  # MalwareBazaar courtesy delay
_MAX_HASHES_DEFAULT = 20


@dataclass(frozen=True)
class _Candidate:
    """A suspicious DLL carrying a genuine content hash."""

    pid: int
    proc_name: str
    dll_path: str
    sha256: str


def _run_coroutine_sync(coro: Any) -> list[DetectorResult]:
    """Run an async detector coroutine from a sync context.

    Works both outside any event loop (plain asyncio.run) and when called
    from inside a running loop (e.g. the pipeline's async run()), where the
    coroutine is executed on a dedicated daemon thread with its own loop.
    """
    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        box: dict[str, list[DetectorResult]] = {}

        def _target() -> None:
            box["result"] = asyncio.run(coro)

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()
        thread.join()
        return box["result"]
    finally:
        coro.close()


class ThreatIntelDetector(BaseDetector):
    """Look up suspicious DLL content hashes against VT and MalwareBazaar.

    This detector is disabled by default because it makes network requests.
    It is registered in the default registry only when a VirusTotal API key
    is configured (FORENSIQ_VT_API_KEY).

        registry.register(ThreatIntelDetector(enabled=True, vt_api_key="..."))
    """

    name = "threat_intel"
    description = (
        "Queries VirusTotal (primary) and MalwareBazaar (fallback) for "
        "genuine SHA-256 content hashes of suspicious DLLs. Disabled by "
        "default — requires a VirusTotal API key."
    )
    enabled_by_default = False  # Network I/O — opt-in only

    def __init__(
        self,
        enabled: bool = False,
        db_path: Any = None,
        vt_api_key: str | None = None,
        vt_delay_ms: int = _VT_DEFAULT_DELAY_MS,
        mb_delay_ms: int = _MB_DEFAULT_DELAY_MS,
        max_hashes: int = _MAX_HASHES_DEFAULT,
    ) -> None:
        self._enabled = enabled
        self._db_path = db_path
        self._vt_api_key = vt_api_key
        self._vt_delay_ms = vt_delay_ms
        self._mb_delay_ms = mb_delay_ms
        self._max_hashes = max_hashes
        self.enabled_by_default = enabled

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Run async threat intel lookups synchronously."""
        if not self._enabled:
            return []

        try:
            return _run_coroutine_sync(self._detect_async(extraction, vectors))
        except Exception as exc:
            log.warning("Threat intel detection failed", error=str(exc))
            return []

    def _collect_content_hash_candidates(
        self,
        extraction: ExtractionResult,
    ) -> list[_Candidate]:
        """Collect suspicious DLLs that carry a genuine SHA-256 content hash.

        Only DLLs whose content hash is known (64 hex chars) are returned.
        No hash is ever derived from the path string.
        """
        pid_to_name = extraction.process_tree.name_map if extraction.process_tree else {}

        candidates: list[_Candidate] = []
        seen: set[str] = set()

        for pid, dlls in extraction.dlls.items():
            proc_name = pid_to_name.get(pid, "<unknown>")
            for dll in dlls:
                if not dll.is_suspicious:
                    continue
                sha256 = (getattr(dll, "content_sha256", "") or "").strip().lower()
                if not _SHA256_RE.fullmatch(sha256):
                    continue
                if sha256 in seen:
                    continue
                seen.add(sha256)
                candidates.append(
                    _Candidate(
                        pid=pid,
                        proc_name=proc_name,
                        dll_path=dll.full_dll_name,
                        sha256=sha256,
                    )
                )
                if len(candidates) >= self._max_hashes:
                    return candidates
        return candidates

    async def _detect_async(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Async implementation of threat intel lookups."""
        from forensiq.db.manager import ForensiqDatabase
        from forensiq.integrations.malwarebazaar import MalwareBazaarClient
        from forensiq.integrations.virustotal import VirusTotalClient

        findings: list[DetectorResult] = []
        candidates = self._collect_content_hash_candidates(extraction)

        if not candidates:
            log.info("No suspicious DLL content hashes to check against threat intel")
            return []

        log.info("Checking threat intel", total_hashes=len(candidates))

        # 1. Check the local cache first
        uncached: list[_Candidate] = []
        async with ForensiqDatabase(db_path=self._db_path) as db:
            for cand in candidates:
                cached = await db.get_threat_intel(cand.sha256)
                if cached and cached.get("verdict") == "malicious":
                    findings.append(
                        self._make_finding(
                            cand=cand,
                            malware_name=cached.get("malware_name", ""),
                            source=cached.get("source", "cache"),
                            confidence=0.90,
                        )
                    )
                elif cached is None:
                    uncached.append(cand)

        if not uncached:
            return findings

        # 2. VirusTotal first (primary source, batched + rate limited)
        vt_results: dict[str, Any] = {}
        vt_client = VirusTotalClient(api_key=self._vt_api_key)
        if vt_client.is_configured():
            async with vt_client as client:
                vt_results = await client.lookup_batch(
                    [c.sha256 for c in uncached],
                    delay_ms=self._vt_delay_ms,
                )

        # 3. MalwareBazaar fallback for hashes VT could not resolve
        mb_pending: list[_Candidate] = []
        for cand in uncached:
            vt_result = vt_results.get(cand.sha256)
            if vt_result is None or vt_result.verdict in (
                "unknown",
                "error",
                "rate_limited",
                "unavailable",
            ):
                mb_pending.append(cand)
            elif vt_result.verdict == "malicious":
                findings.append(
                    self._make_finding(
                        cand=cand,
                        malware_name=vt_result.malware_name,
                        source="virustotal",
                        confidence=0.95,
                        positives=vt_result.positives,
                        total=vt_result.total,
                    )
                )

        mb_results: dict[str, Any] = {}
        if mb_pending:
            async with MalwareBazaarClient() as mb:
                mb_results = await mb.lookup_batch(
                    [c.sha256 for c in mb_pending],
                    delay_ms=self._mb_delay_ms,
                )
            for cand in mb_pending:
                mb_result = mb_results.get(cand.sha256)
                if mb_result is not None and mb_result.verdict == "malicious":
                    findings.append(
                        self._make_finding(
                            cand=cand,
                            malware_name=mb_result.malware_name,
                            source="malwarebazaar",
                            confidence=0.95,
                        )
                    )

        # 4. Cache every resolvable result
        async with ForensiqDatabase(db_path=self._db_path) as db:
            for cand in uncached:
                result = vt_results.get(cand.sha256) or mb_results.get(cand.sha256)
                if result is None or result.verdict in ("error", "unavailable"):
                    continue
                await db.save_threat_intel(
                    hash_value=cand.sha256,
                    hash_type="sha256",
                    source=result.source,
                    verdict=result.verdict,
                    malware_name=result.malware_name,
                    malware_family=result.malware_family,
                    tags=",".join(result.tags) if result.tags else "",
                    first_seen=result.first_seen,
                    raw_json=result.raw_response,
                )

        return findings

    def _make_finding(
        self,
        cand: _Candidate,
        malware_name: str,
        source: str,
        confidence: float,
        positives: int | None = None,
        total: int | None = None,
    ) -> DetectorResult:
        """Create a DetectorResult for a confirmed malicious DLL."""
        detection_detail = ""
        if positives is not None and total is not None:
            detection_detail = f" ({positives}/{total} engines)"
        return DetectorResult(
            detector=self.name,
            pid=cand.pid,
            process_name=cand.proc_name,
            severity=FindingSeverity.CRITICAL,
            title=f"Known malicious DLL in {cand.proc_name}: {cand.dll_path.split(chr(92))[-1]}",
            description=(
                f"DLL at {cand.dll_path!r} loaded by {cand.proc_name!r} (PID "
                f"{cand.pid}) was identified as malicious by {source}"
                f"{detection_detail}. Malware name: {malware_name or 'Unknown'}."
            ),
            mitre_technique="T1055",
            mitre_technique_name="Process Injection",
            evidence={
                "dll_path": cand.dll_path,
                "sha256": cand.sha256,
                "malware_name": malware_name,
                "source": source,
            },
            confidence=confidence,
        )
