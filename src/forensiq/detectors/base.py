# FILE: src/forensiq/detectors/base.py
"""Base interface for all ForensIQ detector plugins.

Every detector must implement the BaseDetector ABC. Detectors are
stateless, pure-function analyzers that receive the full ExtractionResult
and return a list of DetectorResult findings.

Design principles:
    - Detectors never modify the input data
    - A detector failure never aborts the pipeline (caught in DetectorRegistry)
    - Each finding carries a MITRE ATT&CK technique reference
    - Results are aggregated and deduplicated by the registry

Example detector:
    class MyDetector(BaseDetector):
        name = "my_detector"
        description = "Detects something suspicious"

        def detect(self, extraction, vectors) -> list[DetectorResult]:
            results = []
            for proc in extraction.process_tree.processes:
                if is_suspicious(proc):
                    results.append(DetectorResult(
                        detector=self.name,
                        pid=proc.pid,
                        process_name=proc.name,
                        severity=FindingSeverity.HIGH,
                        title="Suspicious process found",
                        description="...",
                        mitre_technique="T1055",
                        mitre_technique_name="Process Injection",
                        evidence={"key": "value"},
                    ))
            return results
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector


class FindingSeverity(StrEnum):
    """Severity levels for detector findings — aligned with CVSS qualitative scale."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        """Numeric score for sorting (higher = more severe)."""
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


@dataclass
class DetectorResult:
    """A single finding produced by a detector.

    Fields:
        detector: Name of the detector that produced this finding.
        pid: Process ID (0 if system-level finding).
        process_name: Process image name.
        severity: CRITICAL / HIGH / MEDIUM / LOW / INFO.
        title: Short one-line description of the finding.
        description: Full human-readable explanation.
        mitre_technique: ATT&CK technique ID (e.g., "T1055").
        mitre_technique_name: Human-readable technique name.
        evidence: Arbitrary dict with raw evidence data (for JSON export).
        timestamp: When the finding was generated.
        confidence: 0.0-1.0 confidence estimate (detector-specific).
    """

    detector: str
    pid: int
    process_name: str
    severity: FindingSeverity
    title: str
    description: str
    mitre_technique: str = ""
    mitre_technique_name: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "detector": self.detector,
            "pid": self.pid,
            "process_name": self.process_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_name": self.mitre_technique_name,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
            "confidence": round(self.confidence, 4),
        }


class BaseDetector(abc.ABC):
    """Abstract base class for all ForensIQ detector plugins.

    Subclass this and implement detect() to create a new detector.
    Register an instance with DetectorRegistry.register().
    """

    #: Unique snake_case name for this detector (used as registry key)
    name: str = ""

    #: Human-readable description shown in logs and reports
    description: str = ""

    #: Whether this detector is enabled by default
    enabled_by_default: bool = True

    @abc.abstractmethod
    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Run detection logic and return findings.

        Args:
            extraction: Full ExtractionResult from Volatility 3 plugins.
            vectors: Classified ProcessFeatureVector list (post-ML scoring).

        Returns:
            List of DetectorResult findings. Empty list if nothing found.
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r})"
