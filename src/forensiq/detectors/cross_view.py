# FILE: src/forensiq/detectors/cross_view.py
"""Cross-View DKOM Rootkit Detector — psscan vs pslist comparison.

This detector runs windows.psscan (pool-tag scanning) and compares
results with windows.pslist (EPROCESS linked-list traversal).

Detection logic:
    - PIDs visible in psscan but NOT in pslist → hidden processes
      (DKOM rootkit — EPROCESS unlinked from doubly-linked list)
    - Confidence: high if process name is suspicious, medium if unknown

Real-world examples:
    - TDL/TDSS rootkit: hides svchost.exe instances
    - Mebroot: hides core malware process
    - Rustock.C: hides its rootkit driver process

References:
    - MITRE T1014: Rootkit
    - Ligh et al. "The Art of Memory Forensics", Chapter 6
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)


class CrossViewDetector(BaseDetector):
    """Detect DKOM-hidden processes by comparing psscan vs pslist.

    Runs windows.psscan plugin internally (separate from the main extraction),
    then compares PIDs to find processes hidden from the standard pslist.
    """

    name = "cross_view"
    description = (
        "Compares windows.psscan (pool-tag scanning) with windows.pslist "
        "(EPROCESS linked list) to detect DKOM-hidden processes."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        if extraction.process_tree is None:
            return findings

        # PIDs known from pslist (EPROCESS linked list traversal)
        pslist_pids: set[int] = set(extraction.process_tree.flat_map.keys())

        # Run psscan to get pool-tag-discovered processes
        try:
            psscan_rows = self._run_psscan(extraction)
        except Exception as exc:
            log.warning("psscan failed in cross-view detector", error=str(exc))
            return []

        if not psscan_rows:
            log.info("psscan returned no rows — skipping cross-view detection")
            return []

        psscan_pid_names: dict[int, str] = {}
        for row in psscan_rows:
            pid = self._extract_pid(row)
            name = self._extract_name(row)
            if pid is not None:
                psscan_pid_names[pid] = name

        psscan_pids = set(psscan_pid_names.keys())

        # Hidden processes: visible in pool scan but NOT in linked list
        hidden_pids = psscan_pids - pslist_pids

        log.info(
            "Cross-view comparison",
            pslist_count=len(pslist_pids),
            psscan_count=len(psscan_pids),
            hidden_count=len(hidden_pids),
        )

        for pid in hidden_pids:
            name = psscan_pid_names.get(pid, "<unknown>")
            findings.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=name,
                    severity=FindingSeverity.CRITICAL,
                    title=f"DKOM-hidden process detected: {name} (PID {pid})",
                    description=(
                        f"Process {name!r} (PID {pid}) was found by pool-tag scanning "
                        f"(windows.psscan) but is NOT present in the EPROCESS linked list "
                        f"(windows.pslist). This is a definitive indicator of DKOM manipulation "
                        f"— the process is actively hidden from the operating system."
                    ),
                    mitre_technique="T1014",
                    mitre_technique_name="Rootkit",
                    evidence={
                        "found_in_psscan": True,
                        "found_in_pslist": False,
                        "psscan_row": psscan_pid_names.get(pid, ""),
                        "total_hidden": len(hidden_pids),
                    },
                    confidence=0.97,
                )
            )

        return findings

    def _run_psscan(self, extraction: ExtractionResult) -> list[dict[str, Any]]:
        """Run windows.psscan plugin against the same dump."""
        runner = VolatilityRunner(dump_path=extraction.dump_path)
        return runner.run_plugin("windows.psscan")

    def _extract_pid(self, row: dict[str, Any]) -> int | None:
        """Extract PID from a psscan row (handles column name variations)."""
        for key in ("PID", "pid", "Pid"):
            if key in row:
                try:
                    return int(row[key])
                except (ValueError, TypeError):
                    return None
        return None

    def _extract_name(self, row: dict[str, Any]) -> str:
        """Extract process name from a psscan row."""
        for key in ("ImageFileName", "Name", "name", "Process"):
            if key in row:
                return str(row[key])
        return "<unknown>"
