# FILE: src/forensiq/pipeline/timeline.py
"""Extensible timeline rule registry for ForensIQ.

Each MITRE ATT&CK timeline detection is encapsulated as a ``TimelineRule``
sub-class.  Adding a new technique requires only:

    1. Subclass ``TimelineRule`` and implement ``build_event()``.
    2. Append an instance to ``_DEFAULT_RULES``.

No other pipeline code needs to change.

Usage:
    from forensiq.pipeline.timeline import build_timeline

    events = build_timeline(vectors, is_linux=True)
"""

from __future__ import annotations

import abc
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from forensiq.models.report import ThreatEvent

if TYPE_CHECKING:
    from forensiq.models.features import ProcessFeatureVector

# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class TimelineRule(abc.ABC):
    """Abstract base for a single MITRE ATT&CK timeline detection rule.

    Each rule is stateless and receives a single :class:`ProcessFeatureVector`.
    It returns a :class:`ThreatEvent` if the condition is met, or ``None`` if
    the process does not match.

    Sub-classes must implement :meth:`build_event`.  The ``is_linux`` flag lets
    rules skip OS-specific checks (e.g. encoded PowerShell is Windows-only).
    """

    @abc.abstractmethod
    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        """Evaluate the rule against *vector* and optionally produce an event.

        Args:
            vector: Per-process feature vector (post-classification).
            is_linux: True when the dump originates from a Linux system.
            baseline_sev: ``"critical"`` if the process is malicious, else
                ``"medium"``.  Rules should not produce *higher* severity than
                this ceiling so that suspicious-only processes never escalate
                the overall threat level.
            now: Analysis timestamp (shared across all rules for consistency).

        Returns:
            A :class:`ThreatEvent` if the condition matches, ``None`` otherwise.
        """


# ---------------------------------------------------------------------------
# Concrete rules
# ---------------------------------------------------------------------------


class MalfindHitsRule(TimelineRule):
    """T1055 — Process Injection via malfind RWX regions."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.malfind_hits <= 0:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="process_injection",
            severity=baseline_sev,
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) has "
                f"{vector.malfind_hits} suspicious memory region(s) with execute "
                f"permissions detected by malfind. Possible reflective injection "
                f"or shellcode."
            ),
            mitre_technique="T1055",
            mitre_technique_name="Process Injection",
        )


class VADRWXRule(TimelineRule):
    """T1055.012 — Process Hollowing via RWX VAD regions."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.vad_rwx_count <= 2:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="vad_rwx",
            severity="high",
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) has "
                f"{vector.vad_rwx_count} virtual address descriptor(s) with RWX "
                f"protection. Common indicator of process hollowing or code "
                f"injection preparation."
            ),
            mitre_technique="T1055.012",
            mitre_technique_name="Process Hollowing",
        )


class EncodedCmdlineRule(TimelineRule):
    """T1059.001 — Encoded/obfuscated PowerShell (Windows only)."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        # Skipped on Linux: bare hex patterns match SHA-256 hashes and git
        # commit hashes that are legitimately present in Linux process cmdlines.
        if not vector.has_encoded_cmdline or is_linux:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="encoded_cmdline",
            severity="high",
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) launched with "
                f"Base64-encoded or heavily obfuscated command-line arguments. "
                f"Common indicator of PowerShell payload delivery or script-based "
                f"malware."
            ),
            mitre_technique="T1059.001",
            mitre_technique_name="Command and Scripting Interpreter: PowerShell",
        )


class MasqueradingRule(TimelineRule):
    """T1036.005 — Process masquerading via high name entropy outside system paths."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.process_name_entropy <= 3.5 or vector.is_system_path:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="masquerading",
            severity="medium",
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) has high name "
                f"entropy ({vector.process_name_entropy:.2f} bits) and runs "
                f"outside system directories. Possible malware masquerading as "
                f"a legitimate process."
            ),
            mitre_technique="T1036.005",
            mitre_technique_name="Masquerading: Match Legitimate Name or Location",
        )


class C2ConnectionRule(TimelineRule):
    """T1071 — External C2 connections."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.external_connection_count <= 0:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="c2_connection",
            severity="critical" if vector.is_malicious else "high",
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) has "
                f"{vector.external_connection_count} connection(s) to external "
                f"(non-RFC1918) IP addresses. Possible Command & Control traffic."
            ),
            mitre_technique="T1071",
            mitre_technique_name="Application Layer Protocol",
        )


class LsasDumpingRule(TimelineRule):
    """T1003.001 — LSASS credential dumping via suspicious DLLs."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.name.lower() not in ("lsass.exe", "lsass"):
            return None
        if vector.suspicious_dll_count <= 0:
            return None
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="lsass_suspicious_dll",
            severity="critical",
            description=(
                f"lsass.exe (PID {vector.pid}) has {vector.suspicious_dll_count} "
                f"suspicious DLL(s) loaded from non-standard paths. Possible "
                f"credential dumping attack (Mimikatz, ProcDump, etc.)."
            ),
            mitre_technique="T1003.001",
            mitre_technique_name="OS Credential Dumping: LSASS Memory",
        )


class SuspiciousDLLRule(TimelineRule):
    """T1140 — Deobfuscation / suspicious DLLs in non-lsass processes."""

    def build_event(
        self,
        vector: ProcessFeatureVector,
        is_linux: bool,
        baseline_sev: str,
        now: datetime,
    ) -> ThreatEvent | None:
        if vector.suspicious_dll_count <= 0:
            return None
        if vector.name.lower() in ("lsass.exe", "lsass"):
            return None  # Handled by LsasDumpingRule
        return ThreatEvent(
            timestamp=now,
            pid=vector.pid,
            process_name=vector.name,
            event_type="suspicious_dll",
            severity="medium",
            description=(
                f"Process {vector.name!r} (PID {vector.pid}) loaded "
                f"{vector.suspicious_dll_count} DLL(s) from suspicious paths "
                f"(Temp, AppData, memfd, non-standard directories). Possible "
                f"DLL side-loading or unpack-to-disk behavior."
            ),
            mitre_technique="T1140",
            mitre_technique_name="Deobfuscate/Decode Files or Information",
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

#: Default ordered list of timeline rules applied by :func:`build_timeline`.
#: To add a new rule, append an instance here — no pipeline code changes needed.
_DEFAULT_RULES: list[TimelineRule] = [
    MalfindHitsRule(),
    VADRWXRule(),
    EncodedCmdlineRule(),
    MasqueradingRule(),
    C2ConnectionRule(),
    LsasDumpingRule(),
    SuspiciousDLLRule(),
]

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def build_timeline(
    vectors: list[ProcessFeatureVector],
    is_linux: bool = False,
    rules: list[TimelineRule] | None = None,
) -> list[ThreatEvent]:
    """Build a forensic timeline from classified process feature vectors.

    Iterates over every process that is either malicious or has a threat score
    ≥ 0.35 (suspicious), then applies each registered :class:`TimelineRule`.
    Rules that match produce a :class:`ThreatEvent`; rules that do not match
    return ``None`` and are skipped.

    Args:
        vectors: Post-classification process feature vectors.
        is_linux: Pass ``True`` for Linux dumps to suppress Windows-only rules
            (e.g. :class:`EncodedCmdlineRule`).
        rules: Optional custom rule list.  Defaults to :data:`_DEFAULT_RULES`.
            Pass a subset or extended list to customise detections without
            touching this module.

    Returns:
        Timeline events sorted critical-first then alphabetically by process name.
    """
    active_rules = rules if rules is not None else _DEFAULT_RULES
    events: list[ThreatEvent] = []
    now = datetime.now(tz=UTC)

    for v in vectors:
        if not v.is_malicious and v.threat_score < 0.35:
            continue

        # Severity ceiling: malicious processes may produce CRITICAL events;
        # suspicious-only processes are capped at MEDIUM to prevent them from
        # escalating the overall report threat_level.
        baseline_sev = "critical" if v.is_malicious else "medium"

        for rule in active_rules:
            event = rule.build_event(v, is_linux, baseline_sev, now)
            if event is not None:
                events.append(event)

    events.sort(key=lambda e: (_SEVERITY_ORDER.get(e.severity, 4), e.process_name))
    return events
