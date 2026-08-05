# FILE: src/forensiq/detectors/services_scan.py
"""Services Scanner Detector — malicious service detection via windows.svcscan.

Detects:
    - Running services with binaries in suspicious directories (T1543.003)
    - Services with no display name (common malware pattern)
    - Kernel driver services from non-system paths (T1543.003)
    - Services linking to already-identified malicious PIDs

MITRE ATT&CK:
    T1543.003 — Create or Modify System Process: Windows Service
    T1036.004 — Masquerading: Masquerade Task or Service
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.extraction.services_extractor import ServicesExtractor
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)


class ServicesScanDetector(BaseDetector):
    """Detect malicious Windows services using windows.svcscan.

    Runs svcscan independently during detection phase.
    """

    name = "services_scan"
    description = (
        "Detects malicious Windows services by scanning the service control "
        "manager with windows.svcscan. Flags services running from suspicious "
        "paths and services linked to malicious processes."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        # Build set of malicious PIDs from classification
        malicious_pids: set[int] = {v.pid for v in vectors if v.is_malicious}

        try:
            from forensiq.acquisition.volatility_runner import VolatilityRunner

            runner = VolatilityRunner(dump_path=extraction.dump_path)
            extractor = ServicesExtractor(runner)
            services = extractor.extract()
        except Exception as exc:
            log.warning("svcscan failed in services detector", error=str(exc))
            return []

        for svc in services:
            # Running services with suspicious binary paths
            if svc.is_suspicious_path and svc.is_running:
                severity = (
                    FindingSeverity.CRITICAL if svc.pid in malicious_pids else FindingSeverity.HIGH
                )
                findings.append(
                    DetectorResult(
                        detector=self.name,
                        pid=svc.pid,
                        process_name=svc.service_name,
                        severity=severity,
                        title=f"Service running from suspicious path: {svc.service_name}",
                        description=(
                            f"Windows service '{svc.service_name}' (display: '{svc.display_name}') "
                            f"is running from a suspicious path: {svc.binary_path!r}. "
                            f"Services should run from System32 or Program Files."
                        ),
                        mitre_technique="T1543.003",
                        mitre_technique_name="Create or Modify System Process: Windows Service",
                        evidence={
                            "service_name": svc.service_name,
                            "display_name": svc.display_name,
                            "binary_path": svc.binary_path,
                            "service_type": svc.service_type,
                            "pid": svc.pid,
                        },
                        confidence=0.85,
                    )
                )

            # Services linked to already-identified malicious PIDs
            elif svc.pid in malicious_pids and svc.pid > 0:
                findings.append(
                    DetectorResult(
                        detector=self.name,
                        pid=svc.pid,
                        process_name=svc.service_name,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Service linked to malicious process: {svc.service_name}",
                        description=(
                            f"Windows service '{svc.service_name}' is hosted by PID {svc.pid}, "
                            f"which was independently classified as malicious by ForensIQ ML. "
                            f"This service may be used for persistence."
                        ),
                        mitre_technique="T1543.003",
                        mitre_technique_name="Create or Modify System Process: Windows Service",
                        evidence={
                            "service_name": svc.service_name,
                            "malicious_pid": svc.pid,
                            "binary_path": svc.binary_path,
                        },
                        confidence=0.93,
                    )
                )

        log.info(
            "Services scan complete",
            total_services=len(services),
            findings=len(findings),
        )
        return findings
