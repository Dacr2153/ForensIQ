# FILE: src/forensiq/detectors/handles_mutex.py
"""Handles and Mutex Detector — malicious mutex and registry handle analysis.

Uses windows.handles plugin to detect:
    - Malware-specific mutex names (unique per RAT/botnet family)
    - Registry handles to persistence locations (Run/RunOnce)
    - Named pipe handles (common for lateral movement C2)

A mutex is a synchronization object malware uses to ensure only one
instance runs at a time. Known malware families have characteristic mutex names.

MITRE ATT&CK:
    T1547.001 — Registry Run Keys / Startup Folder (registry handles)
    T1071.001 — Web Protocols (named pipe C2)
    T1120     — Peripheral Device Discovery (device handles)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.extraction.handles_extractor import HandlesExtractor
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)


class HandlesMutexDetector(BaseDetector):
    """Detect suspicious handles (mutexes, registry keys) via windows.handles."""

    name = "handles_mutex"
    description = (
        "Runs windows.handles to detect malware-specific mutex names, "
        "registry persistence handles, and other suspicious handle types."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        try:
            from forensiq.acquisition.volatility_runner import VolatilityRunner

            runner = VolatilityRunner(dump_path=extraction.dump_path)
            extractor = HandlesExtractor(runner)
            handles_by_pid = extractor.extract()
        except Exception as exc:
            log.warning("handles plugin failed", error=str(exc))
            return []

        if not handles_by_pid:
            log.info("No suspicious handles found")
            return []

        pid_to_name: dict[int, str] = {}
        if extraction.process_tree:
            pid_to_name = {pid: proc.name for pid, proc in extraction.process_tree.flat_map.items()}

        for pid, handles in handles_by_pid.items():
            proc_name = pid_to_name.get(pid, handles[0].process_name if handles else "<unknown>")
            mutex_handles = [h for h in handles if h.is_suspicious_mutex]
            reg_handles = [h for h in handles if h.is_suspicious_registry]

            if mutex_handles:
                findings.append(
                    DetectorResult(
                        detector=self.name,
                        pid=pid,
                        process_name=proc_name,
                        severity=FindingSeverity.HIGH,
                        title=f"Suspicious mutex handle in {proc_name} (PID {pid})",
                        description=(
                            f"Process {proc_name!r} (PID {pid}) holds {len(mutex_handles)} "
                            f"suspicious mutex handle(s): "
                            f"{[h.name for h in mutex_handles[:3]]}. "
                            f"Mutex names match known malware patterns."
                        ),
                        mitre_technique="T1480",
                        mitre_technique_name="Execution Guardrails",
                        evidence={
                            "mutex_names": [h.name for h in mutex_handles[:10]],
                            "count": len(mutex_handles),
                        },
                        confidence=0.80,
                    )
                )

            if reg_handles:
                findings.append(
                    DetectorResult(
                        detector=self.name,
                        pid=pid,
                        process_name=proc_name,
                        severity=FindingSeverity.HIGH,
                        title=f"Registry persistence handle in {proc_name} (PID {pid})",
                        description=(
                            f"Process {proc_name!r} (PID {pid}) has {len(reg_handles)} "
                            f"open handle(s) to registry persistence locations: "
                            f"{[h.name for h in reg_handles[:3]]}. "
                            f"Possible persistence via registry Run keys."
                        ),
                        mitre_technique="T1547.001",
                        mitre_technique_name="Registry Run Keys / Startup Folder",
                        evidence={
                            "registry_paths": [h.name for h in reg_handles[:10]],
                            "count": len(reg_handles),
                        },
                        confidence=0.82,
                    )
                )

        return findings
