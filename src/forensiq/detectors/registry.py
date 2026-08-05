# FILE: src/forensiq/detectors/registry.py
"""Detector plugin registry and runner.

The DetectorRegistry discovers, manages and runs all registered detectors.
It is the single entry point for running all detections in the pipeline.

Usage:
    registry = DetectorRegistry()
    registry.register(MyDetector())
    findings = registry.run_all(extraction, vectors)

Or use the global default registry:
    from forensiq.detectors.registry import get_default_registry
    findings = get_default_registry().run_all(extraction, vectors)
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from forensiq.detectors.base import BaseDetector, DetectorResult
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)


class DetectorRegistry:
    """Registry that manages and runs all detector plugins.

    Detectors are run in registration order.
    Each detector failure is caught and logged but does not abort others.
    """

    def __init__(self) -> None:
        self._detectors: list[BaseDetector] = []

    def register(self, detector: BaseDetector) -> DetectorRegistry:
        """Register a detector instance.

        Args:
            detector: Instantiated BaseDetector subclass.

        Returns:
            self (for method chaining).
        """
        if not detector.name:
            raise ValueError(f"Detector {detector!r} has no name set")
        self._detectors.append(detector)
        log.debug("Detector registered", detector=detector.name)
        return self

    def run_all(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Run all enabled detectors and aggregate findings.

        Args:
            extraction: Full extraction result from Volatility 3.
            vectors: Classified feature vectors.

        Returns:
            Combined list of all DetectorResult findings, sorted by severity.
        """
        all_findings: list[DetectorResult] = []

        for detector in self._detectors:
            if not detector.enabled_by_default:
                continue
            t0 = time.monotonic()
            try:
                findings = detector.detect(extraction, vectors)
                elapsed = round((time.monotonic() - t0) * 1000, 1)
                log.info(
                    "Detector complete",
                    detector=detector.name,
                    findings=len(findings),
                    elapsed_ms=elapsed,
                )
                all_findings.extend(findings)
            except Exception as exc:
                log.warning(
                    "Detector failed (non-fatal)",
                    detector=detector.name,
                    error=str(exc),
                )

        # Sort by severity (critical first), then by pid
        all_findings.sort(
            key=lambda f: (-f.severity.score, f.pid),
        )
        return all_findings

    @property
    def detector_names(self) -> list[str]:
        """List of registered detector names."""
        return [d.name for d in self._detectors]

    def __len__(self) -> int:
        return len(self._detectors)


def build_default_registry(is_linux: bool = False, vt_api_key: str = "") -> DetectorRegistry:
    """Build the default DetectorRegistry with all built-in detectors.

    Windows-only detectors (cross_view, services_scan, handles_mutex) are
    excluded automatically when is_linux=True — those plugins (psscan,
    svcscan, handles) only exist in the windows.* Volatility 3 namespace
    and will always fail with exit code 1 on a Linux/LiME dump.

    The ThreatIntelDetector is registered only when a VirusTotal API key is
    provided (vt_api_key), since it performs network I/O. Without a key it is
    omitted entirely — MalwareBazaar is only used as a fallback for hashes
    VirusTotal could not resolve, so VT-first requires the VT key.

    Args:
        is_linux: True when analyzing a Linux memory dump.
        vt_api_key: VirusTotal API v3 key (from FORENSIQ_VT_API_KEY). Empty
            disables the threat-intel detector.

    Returns:
        Configured DetectorRegistry with all enabled detectors.
    """
    from forensiq.detectors.malfind_strings import MalfindStringsDetector
    from forensiq.detectors.pe_header import PEHeaderDetector
    from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

    registry = DetectorRegistry()
    registry.register(ProcessAnomalyDetector())
    registry.register(MalfindStringsDetector())
    registry.register(PEHeaderDetector())

    if not is_linux:
        from forensiq.detectors.cross_view import CrossViewDetector
        from forensiq.detectors.handles_mutex import HandlesMutexDetector
        from forensiq.detectors.services_scan import ServicesScanDetector

        registry.register(CrossViewDetector())
        registry.register(ServicesScanDetector())
        registry.register(HandlesMutexDetector())

    if vt_api_key:
        from forensiq.detectors.threat_intel import ThreatIntelDetector

        registry.register(
            ThreatIntelDetector(enabled=True, vt_api_key=vt_api_key)
        )

    return registry
