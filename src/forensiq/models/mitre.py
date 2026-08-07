# FILE: src/forensiq/models/mitre.py
"""MITRE ATT&CK technique mapping and aggregation.

Provides:
    - MITRE_TECHNIQUES: dict of technique_id → metadata for techniques used
      by ForensIQ detectors
    - MitreTechnique: Pydantic model for a single technique
    - build_mitre_summary(): Aggregate techniques from all findings

References:
    - https://attack.mitre.org/
    - MITRE ATT&CK v14 (Windows)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ─── MITRE ATT&CK Technique Database ─────────────────────────────────────────
# Format: technique_id → {name, tactic, description, url}
MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1014": {
        "name": "Rootkit",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use rootkits to hide the presence of programs, files,"
            " network connections, services, drivers, and other system components."
        ),
        "url": "https://attack.mitre.org/techniques/T1014/",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to make an executable or file difficult to"
            " discover or analyze by encrypting, encoding, or otherwise obfuscating"
            " its contents."
        ),
        "url": "https://attack.mitre.org/techniques/T1027/",
    },
    "T1027.001": {
        "name": "Binary Padding",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use binary padding to add junk data and change the"
            " on-disk representation of malware."
        ),
        "url": "https://attack.mitre.org/techniques/T1027/001/",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login"
            " and credential material."
        ),
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to access credential material stored in the"
            " process memory of the Local Security Authority Subsystem Service"
            " (LSASS)."
        ),
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to manipulate features of their artifacts to"
            " make them appear legitimate or benign to users and/or security tools."
        ),
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    "T1036.004": {
        "name": "Masquerade Task or Service",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to manipulate the name of a task or service to"
            " make it appear legitimate or benign."
        ),
        "url": "https://attack.mitre.org/techniques/T1036/004/",
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may match or approximate the name or location of"
            " legitimate files or resources when naming/placing them."
        ),
        "url": "https://attack.mitre.org/techniques/T1036/005/",
    },
    "T1043": {
        "name": "Commonly Used Port",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate over a commonly used port to bypass"
            " firewalls or network detection systems."
        ),
        "url": "https://attack.mitre.org/techniques/T1043/",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": (
            "Adversaries may inject code into processes in order to evade"
            " process-based defenses as well as possibly elevate privileges."
        ),
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": (
            "Adversaries may inject malicious code into suspended and hollowed"
            " processes in order to evade process-based defenses."
        ),
        "url": "https://attack.mitre.org/techniques/T1055/012/",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute"
            " commands, scripts, or binaries."
        ),
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols to avoid"
            " detection/network filtering by blending in with existing traffic."
        ),
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols"
            " associated with web traffic to avoid detection."
        ),
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may use obfuscated files or information to hide artifacts"
            " of an intrusion from analysis."
        ),
        "url": "https://attack.mitre.org/techniques/T1140/",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon specific actions by a user in order to gain"
            " execution."
        ),
        "url": "https://attack.mitre.org/techniques/T1204/",
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon a user opening a malicious file in order to"
            " gain execution."
        ),
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may create or modify system-level processes to repeatedly"
            " execute malicious payloads as part of persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1543/",
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may create or modify Windows services to repeatedly"
            " execute malicious payloads as part of persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1543/003/",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may configure system settings to automatically execute a"
            " program during system boot or logon to maintain persistence."
        ),
        "url": "https://attack.mitre.org/techniques/T1547/",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may achieve persistence by adding a program to a startup"
            " folder or referencing it with a Registry run key."
        ),
        "url": "https://attack.mitre.org/techniques/T1547/001/",
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "Persistence, Privilege Escalation, Defense Evasion",
        "description": (
            "Adversaries may execute their own malicious payloads by hijacking the"
            " way operating systems run programs."
        ),
        "url": "https://attack.mitre.org/techniques/T1574/",
    },
    "T1574.001": {
        "name": "DLL Search Order Hijacking",
        "tactic": "Persistence, Privilege Escalation, Defense Evasion",
        "description": (
            "Adversaries may execute their own malicious payloads by hijacking the"
            " search order used to load DLLs."
        ),
        "url": "https://attack.mitre.org/techniques/T1574/001/",
    },
}


@dataclass
class MitreTechnique:
    """A single MITRE ATT&CK technique with observation count."""

    technique_id: str
    name: str
    tactic: str
    description: str
    url: str
    observation_count: int = 0
    observed_pids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON/HTML report."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "url": self.url,
            "observation_count": self.observation_count,
            "observed_pids": sorted(set(self.observed_pids))[:10],
        }


def build_mitre_summary(
    timeline_events: list[Any],
    detector_findings: list[Any],
) -> list[dict[str, Any]]:
    """Build deduplicated MITRE ATT&CK technique list from all findings.

    Args:
        timeline_events: List of ThreatEvent objects (have mitre_technique field).
        detector_findings: List of DetectorResult objects (have mitre_technique field).

    Returns:
        List of MitreTechnique dicts, sorted by observation count descending.
    """
    technique_map: dict[str, MitreTechnique] = {}

    def _add(technique_id: str, pid: int) -> None:
        if not technique_id:
            return
        if technique_id not in technique_map:
            meta = MITRE_TECHNIQUES.get(technique_id, {})
            technique_map[technique_id] = MitreTechnique(
                technique_id=technique_id,
                name=meta.get("name", technique_id),
                tactic=meta.get("tactic", "Unknown"),
                description=meta.get("description", ""),
                url=meta.get(
                    "url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                ),
            )
        technique_map[technique_id].observation_count += 1
        technique_map[technique_id].observed_pids.append(pid)

    for event in timeline_events:
        _add(getattr(event, "mitre_technique", ""), getattr(event, "pid", 0))

    for finding in detector_findings:
        technique_id = (
            finding.get("mitre_technique", "")
            if isinstance(finding, dict)
            else getattr(finding, "mitre_technique", "")
        )
        pid = finding.get("pid", 0) if isinstance(finding, dict) else getattr(finding, "pid", 0)
        _add(technique_id, pid)

    techniques = list(technique_map.values())
    techniques.sort(key=lambda t: -t.observation_count)
    return [t.to_dict() for t in techniques]
