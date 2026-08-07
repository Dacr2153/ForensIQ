# FILE: src/forensiq/pipeline/linux_scoring.py
"""Heuristic threat scoring for Linux dumps.

The XGBoost classifier is trained on Windows memory (CIC-MalMem2022) and
cannot be applied to Linux dumps.  This module derives a per-process
threat_score from the highest-severity detector finding so downstream
pipeline stages (timeline, top_threats, YARA generation, suspicious_count)
can still produce meaningful output.
"""

from __future__ import annotations

from forensiq.detectors.base import DetectorResult
from forensiq.models.features import ProcessFeatureVector
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

_LINUX_HEURISTIC_SCORE: dict[str, float] = {
    "critical": 0.85,
    "high": 0.70,  # Corroborated evidence required to reach HIGH; clear margin above threshold
    "medium": 0.45,  # Suspicious but below default 0.65 threshold — not marked malicious
    "low": 0.20,
    "info": 0.0,
}


def apply_linux_heuristic_scores(
    vectors: list[ProcessFeatureVector],
    detector_findings: list[DetectorResult],
    threshold: float = 0.65,
) -> list[ProcessFeatureVector]:
    """Assign heuristic threat scores to Linux process vectors from detector findings.

    Score mapping:
        critical finding → 0.85  (marked malicious well above default 0.65 threshold)
        high     finding → 0.70  (marked malicious; HIGH requires corroborated evidence)
        medium   finding → 0.45  (suspicious but NOT malicious at default threshold)
        low/info finding → 0.20 / 0.0  (informational, not malicious)

    Args:
        vectors: Per-process feature vectors (threat_score = 0.0 post-classification skip).
        detector_findings: All DetectorResult objects from the detector phase.
        threshold: Threat threshold above which a process is marked malicious.

    Returns:
        Updated vector list with heuristic threat_score and ensemble_score set.
    """
    # Build a map: PID → highest heuristic score from detector findings
    pid_score: dict[int, float] = {}
    for finding in detector_findings:
        severity_key = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        score = _LINUX_HEURISTIC_SCORE.get(severity_key.lower(), 0.0)
        pid_score[finding.pid] = max(pid_score.get(finding.pid, 0.0), score)

    if not pid_score:
        return vectors

    updated: list[ProcessFeatureVector] = []
    for v in vectors:
        score = pid_score.get(v.pid, 0.0)
        if score > 0.0:
            updated.append(
                v.model_copy(
                    update={
                        "threat_score": score,
                        "ensemble_score": score,
                        "is_malicious": score >= threshold,
                    }
                )
            )
        else:
            updated.append(v)

    # Re-sort by threat_score descending (mirrors classifier behavior)
    updated.sort(key=lambda x: x.threat_score, reverse=True)
    return updated
