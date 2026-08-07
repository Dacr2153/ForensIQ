# FILE: src/forensiq/detectors/process_anomaly.py
"""Process Anomaly Detector — adaptive threshold + masquerading detection.

Detects:
    - Suspicious parent-child relationships (T1036.005)
    - Process name masquerading (T1036)
    - System processes running from wrong paths (T1036.005)
    - Suspicious execution from temp/user dirs (T1204.002)
    - Processes with high threat score using adaptive thresholds by type
    - Linux-specific RWX / compromised-binary / path / DLL checks
      (implemented in the LinuxProcessChecksMixin)

Adaptive thresholds:
    System critical processes (lsass, csrss, smss, etc.) use a higher
    detection threshold (0.92) because they are always "anomalous" by
    ML metrics but almost never actually malicious. User processes use
    the default threshold (0.65).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.detectors.process_anomaly_linux import LinuxProcessChecksMixin
from forensiq.features.heuristics import LEGITIMATE_PARENT_CHILD, _get_process_stem

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

# Children whose parent relationship is strictly validated. The valid-parent
# values are derived from the single-source LEGITIMATE_PARENT_CHILD table so
# the two views can never drift apart.
_STRICT_PARENT_CHILDREN: frozenset[str] = frozenset(
    {
        "smss",
        "csrss",
        "wininit",
        "winlogon",
        "services",
        "lsass",
        "lsm",
        "svchost",
        "taskhost",
        "spoolsv",
        "explorer",
    }
)


def _build_valid_parent_map() -> dict[str, set[str]]:
    """Invert the canonical parent→child table into child → valid parents.

    Returns:
        Mapping of child stem → set of valid parent stems for the strictly
        validated system processes.
    """
    child_to_parents: dict[str, set[str]] = {}
    for parent, children in LEGITIMATE_PARENT_CHILD.items():
        for child in children:
            child_to_parents.setdefault(child, set()).add(parent)
    return {child: child_to_parents.get(child, set()) for child in _STRICT_PARENT_CHILDREN}


# Processes that legitimately run as children of specific parents
# Format: child stem -> set of valid parent stems (derived from heuristics)
VALID_PARENT_MAP: dict[str, set[str]] = _build_valid_parent_map()

# System processes that should ONLY run from %SystemRoot%\System32\
SYSTEM_ONLY_PROCESSES: set[str] = {
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "smss.exe",
    "services.exe",
    "lsm.exe",
}

# Adaptive thresholds: critical system processes need higher score before
# they are flagged as malicious (they have unusual ML features by default)
ADAPTIVE_THRESHOLDS: dict[str, float] = {
    "system": 0.97,
    "smss.exe": 0.95,
    "csrss.exe": 0.95,
    "wininit.exe": 0.95,
    "lsass.exe": 0.92,
    "services.exe": 0.92,
    "winlogon.exe": 0.90,
    "lsm.exe": 0.92,
    "svchost.exe": 0.85,
    "spoolsv.exe": 0.80,
    "explorer.exe": 0.75,
}


class ProcessAnomalyDetector(LinuxProcessChecksMixin, BaseDetector):
    """Detect process anomalies using heuristic rules and adaptive thresholds.

    This detector runs heuristic checks on all processes, independent of
    the ML threat score. It catches masquerading and structural anomalies
    that the XGBoost model may miss.
    """

    name = "process_anomaly"
    description = (
        "Detects process masquerading, wrong-parent spawning, "
        "suspicious execution paths, and applies adaptive thresholds "
        "for critical system processes."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        if extraction.process_tree is None:
            return findings

        # Detect OS type from dump extension (mirrors analysis_pipeline logic)
        is_linux = getattr(extraction, "is_linux", False)

        # Build PID→name lookup for parent checks
        pid_to_name = {
            pid: name.lower() for pid, name in extraction.process_tree.name_map.items()
        }

        for v in vectors:
            if is_linux:
                # Linux-specific heuristic checks (no ML classifier output available)
                findings.extend(self._check_linux_rwx_memory(v))
                findings.extend(self._check_linux_compromised_binary(v))
                findings.extend(self._check_linux_suspicious_path(v, extraction))
                findings.extend(self._check_linux_suspicious_dll(v, extraction))
            else:
                # Windows-specific checks
                findings.extend(self._check_adaptive_threshold(v))
                findings.extend(self._check_parent_relationship(v, pid_to_name))
                findings.extend(self._check_system_process_path(v))
                findings.extend(self._check_suspicious_path(v))

        return findings

    # ─── Individual Windows Checks ────────────────────────────────────────────

    def _check_adaptive_threshold(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Re-evaluate threat score using process-type-specific thresholds.

        System-critical processes are only flagged at a higher score to
        reduce false positives on processes the ML model was not optimally
        trained for.
        """
        results: list[DetectorResult] = []
        proc_lower = v.name.lower()
        adaptive_threshold = ADAPTIVE_THRESHOLDS.get(proc_lower, 0.65)

        # Process was marked malicious by ML but is a critical system process
        # → only flag if it also exceeds the adaptive threshold
        if v.is_malicious and proc_lower in ADAPTIVE_THRESHOLDS:
            if v.threat_score < adaptive_threshold:
                # Downgrade: score is below adaptive threshold, this is likely a FP
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=v.pid,
                        process_name=v.name,
                        severity=FindingSeverity.INFO,
                        title=f"ML flag downgraded: {v.name} below adaptive threshold",
                        description=(
                            f"Process {v.name!r} (PID {v.pid}) was flagged malicious by ML "
                            f"with score {v.threat_score:.3f}, but adaptive threshold for this "
                            f"critical system process is {adaptive_threshold:.2f}. "
                            f"Treated as informational (likely false positive)."
                        ),
                        mitre_technique="",
                        evidence={
                            "threat_score": v.threat_score,
                            "adaptive_threshold": adaptive_threshold,
                            "is_system_critical": True,
                        },
                        confidence=0.3,
                    )
                )
            else:
                # Confirmed high-confidence malicious system process
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=v.pid,
                        process_name=v.name,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Critical system process anomaly: {v.name}",
                        description=(
                            f"Critical system process {v.name!r} (PID {v.pid}) scored "
                            f"{v.threat_score:.3f}, exceeding the adaptive threshold of "
                            f"{adaptive_threshold:.2f} for this process type. "
                            f"High-confidence malicious activity."
                        ),
                        mitre_technique="T1036.005",
                        mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                        evidence={
                            "threat_score": v.threat_score,
                            "adaptive_threshold": adaptive_threshold,
                        },
                        confidence=min(v.threat_score, 1.0),
                    )
                )

        return results

    def _check_parent_relationship(
        self,
        v: ProcessFeatureVector,
        pid_to_name: dict[int, str],
    ) -> list[DetectorResult]:
        """Check that process is spawned by a valid parent."""
        results: list[DetectorResult] = []
        proc_stem = _get_process_stem(v.name)

        if proc_stem not in VALID_PARENT_MAP:
            return results

        valid_parents = VALID_PARENT_MAP[proc_stem]
        actual_parent_name = pid_to_name.get(v.ppid, "unknown").lower()
        actual_parent_stem = _get_process_stem(actual_parent_name)

        # Special case: parent PID 0 / not found (orphaned or System root) is
        # OK for some processes. "unknown" means the PPID was not in the process
        # tree — we cannot verify the relationship, so do not flag it.
        if not valid_parents or actual_parent_stem in valid_parents:
            return results
        if actual_parent_name == "unknown" or v.ppid <= 0:
            return results

        results.append(
            DetectorResult(
                detector=self.name,
                pid=v.pid,
                process_name=v.name,
                severity=FindingSeverity.HIGH,
                title=f"Unexpected parent process: {v.name} spawned by {actual_parent_name}",
                description=(
                    f"Process {v.name!r} (PID {v.pid}) is spawned by "
                    f"{actual_parent_name!r} (PID {v.ppid}), but valid parents are: "
                    f"{sorted(valid_parents)}. "
                    f"This may indicate process injection or malicious spawning."
                ),
                mitre_technique="T1036.005",
                mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                evidence={
                    "actual_parent": actual_parent_name,
                    "valid_parents": sorted(valid_parents),
                    "ppid": v.ppid,
                },
                confidence=0.85,
            )
        )
        return results

    def _check_system_process_path(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Check that system-only processes run from System32."""
        results: list[DetectorResult] = []
        proc_lower = v.name.lower()

        if proc_lower not in SYSTEM_ONLY_PROCESSES:
            return results

        # is_system_path is True if path contains System32/syswow64/etc.
        if not v.is_system_path:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=FindingSeverity.CRITICAL,
                    title=f"System process running outside System32: {v.name}",
                    description=(
                        f"Critical system process {v.name!r} (PID {v.pid}) is NOT "
                        f"running from a system directory. This is a strong indicator of "
                        f"malware masquerading as a legitimate system process."
                    ),
                    mitre_technique="T1036.005",
                    mitre_technique_name="Masquerading: Match Legitimate Name or Location",
                    evidence={
                        "is_system_path": v.is_system_path,
                        "process_name": v.name,
                    },
                    confidence=0.95,
                )
            )
        return results

    def _check_suspicious_path(
        self,
        v: ProcessFeatureVector,
    ) -> list[DetectorResult]:
        """Flag processes executing from Temp, AppData, Downloads, etc."""
        results = []

        # We infer path from is_system_path=False + threat indicators
        # ProcessFeatureVector doesn't store the raw path, but DLL paths do
        # Use suspicious_dll_count > 0 from user dirs as a proxy
        if v.suspicious_dll_count > 3 and not v.is_system_path and v.threat_score > 0.4:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=v.pid,
                    process_name=v.name,
                    severity=FindingSeverity.MEDIUM,
                    title=f"Multiple suspicious DLLs from user directories: {v.name}",
                    description=(
                        f"Process {v.name!r} (PID {v.pid}) loaded {v.suspicious_dll_count} DLLs "
                        f"from user-writable directories (Temp, AppData, Downloads). "
                        f"Threat score: {v.threat_score:.3f}. Possible DLL side-loading."
                    ),
                    mitre_technique="T1574.001",
                    mitre_technique_name="Hijack Execution Flow: DLL Search Order Hijacking",
                    evidence={
                        "suspicious_dll_count": v.suspicious_dll_count,
                        "threat_score": v.threat_score,
                    },
                    confidence=0.7,
                )
            )
        return results
