# FILE: src/forensiq/detectors/malfind_strings.py
"""Malfind Strings Extractor Detector.

Extracts printable strings from malfind memory regions and looks for
suspicious Indicators of Compromise (IOCs):
    - URLs / IP addresses (C2 beacons)
    - Windows registry paths (persistence)
    - Executable paths in temp/appdata
    - PE artifact strings (MZ header text, LoadLibrary calls)
    - Known malware mutex names
    - Base64-encoded payloads

Also detects PE headers embedded in malfind hexdumps (T1055 evidence).

MITRE ATT&CK:
    T1055   — Process Injection
    T1071   — Application Layer Protocol (C2 URLs)
    T1547   — Boot or Logon Autostart (registry Run keys)
    T1027   — Obfuscated Files or Information (encoded strings)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector


# ─── IOC Patterns ─────────────────────────────────────────────────────────────

# Matches http/https URLs
_RE_URL = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,200}",
    re.IGNORECASE,
)

# Matches IPv4:port or bare IPv4
_RE_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?::\d{1,5})?\b",
)

# Windows registry Run/RunOnce persistence keys
_RE_REGISTRY_RUN = re.compile(
    r"(?:SOFTWARE\\Microsoft\\Windows(?:NT)?\\CurrentVersion\\Run(?:Once)?|"
    r"SYSTEM\\CurrentControlSet\\Services)",
    re.IGNORECASE,
)

# Paths in suspicious directories
_RE_SUSPICIOUS_PATH = re.compile(
    r"[a-zA-Z]:\\(?:Users\\[^\\]+\\AppData|Windows\\Temp|Temp|ProgramData)"
    r"\\[^\x00\n\r\"]{4,100}\.(?:exe|dll|bat|ps1|vbs|cmd|scr)",
    re.IGNORECASE,
)

# PowerShell encoded command
_RE_PS_ENCODED = re.compile(
    r"(?:powershell|pwsh)[^\n]{0,50}(?:-enc|-encodedcommand)",
    re.IGNORECASE,
)

# Base64 blocks of ≥32 chars (possible encoded payloads)
_RE_BASE64 = re.compile(
    r"[A-Za-z0-9+/]{32,}(?:={0,2})",
)

# Known DLL injection / reflective loading strings
_INJECTION_STRINGS = frozenset(
    {
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryexa",
        "virtualalloc",
        "virtualprotect",
        "createremotethread",
        "ntcreatethread",
        "ntwritevirtualmemory",
        "reflectivedllinjection",
        "reflectiveloader",
        "dllinjectiontest",
    }
)

# PE header magic in hex representation used by Volatility malfind output
_MZ_HEX_PATTERN = re.compile(r"\b4d5a(?:90|50|00)", re.IGNORECASE)  # "MZ\x90" or "MZ\x50"


# ─── Linux IOC Patterns ───────────────────────────────────────────────────────
# Applied only to Linux memory dumps. Windows-specific patterns (registry, PE
# headers, Win32 APIs) are intentionally excluded — they either never match on
# Linux or trigger false positives in JIT-compiled code (Electron, browsers).

# Interactive reverse shell patterns: /bin/sh -i, nc -e /bin/sh, mkfifo pipe
_RE_LINUX_REVERSE_SHELL = re.compile(
    r"(?:/bin/(?:sh|bash|dash|zsh|ksh)\s+[-](?:i|c|p)"
    r"|\bnc\b.{0,40}/bin/(?:sh|bash)"
    r"|ncat.{0,40}/bin/(?:sh|bash)"
    r"|mkfifo\s+.{0,60}(?:/tmp|/dev/shm|/var/tmp))",
    re.IGNORECASE,
)

# Sensitive Linux credential file paths (not just /etc/passwd — it is readable
# by everyone and appears in many legitimate binaries as a lookup path)
_RE_LINUX_CRED = re.compile(
    r"/etc/(?:shadow|sudoers|gshadow|security/passwd)\b",
    re.IGNORECASE,
)

# Linux persistence mechanisms: LD_PRELOAD injection, cron, SSH key injection
_RE_LINUX_PERSISTENCE = re.compile(
    r"(?:LD_PRELOAD\s*="
    r"|/etc/ld\.so\.preload"
    r"|\.ssh/authorized_keys"
    r"|/etc/cron\.(?:d|daily|weekly|monthly|hourly)/"
    r"|/var/spool/cron/crontabs/)",
    re.IGNORECASE,
)

# Fileless execution / in-memory staging locations
_RE_LINUX_STAGING = re.compile(
    r"(?:/dev/shm/[^\x00\n\r \"]{4,}"
    r"|/proc/self/(?:mem|fd/\d)"
    r"|(?:memfd_create|process_vm_writev|ptrace)\b)",
    re.IGNORECASE,
)


class MalfindStringsDetector(BaseDetector):
    """Extract strings from malfind regions and identify IOCs.

    Parses the hexdump from MalfindRegion.hexdump field, converts to
    printable strings, then applies regex patterns for C2 URLs, IPs,
    registry keys, suspicious paths, and injection artifacts.
    """

    name = "malfind_strings"
    description = (
        "Extracts printable strings from malfind memory regions and "
        "identifies IOCs: C2 URLs, IP addresses, registry persistence, "
        "suspicious paths, and injection artifacts."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        findings: list[DetectorResult] = []

        # All IOC patterns in this detector are Windows-specific:
        # registry Run keys, Win32 API strings (VirtualAlloc, CreateRemoteThread),
        # Windows-style executable paths, and MZ/PE header detection.
        # On Linux, these patterns either never match or produce false positives:
        # JIT-compiled pages (V8/Electron, systemd-compiled code) contain legitimate
        # external IPs (GitHub CDN, NTP servers, DNS resolvers) that match _RE_IP.
        # Linux process anomaly detection is handled by ProcessAnomalyDetector.
        if getattr(extraction, "is_linux", False):
            return self._detect_linux(extraction, vectors)

        if not extraction.malfind:
            return findings

        # Map PID → process name from process tree
        pid_to_name: dict[int, str] = {}
        if extraction.process_tree:
            pid_to_name = {pid: proc.name for pid, proc in extraction.process_tree.flat_map.items()}

        for pid, regions in extraction.malfind.items():
            proc_name = pid_to_name.get(pid, "<unknown>")
            for region in regions:
                region_findings = self._analyze_region(pid, proc_name, region)
                findings.extend(region_findings)

        return findings

    def _analyze_region(
        self,
        pid: int,
        proc_name: str,
        region: Any,
    ) -> list[DetectorResult]:
        """Analyze a single malfind region for IOCs."""
        results: list[DetectorResult] = []

        hexdump = getattr(region, "hexdump", "") or ""
        disasm = getattr(region, "disassembly", "") or ""

        # Convert hex bytes to raw bytes for string extraction
        raw_bytes = self._hexdump_to_bytes(hexdump)
        printable = self._extract_printable_strings(raw_bytes, min_length=6)
        combined_text = "\n".join(printable) + "\n" + disasm

        # Check for PE MZ header in hexdump bytes
        if raw_bytes and len(raw_bytes) >= 2 and raw_bytes[:2] == b"MZ":
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.CRITICAL,
                    title=f"PE header (MZ) found in injected region: {proc_name}",
                    description=(
                        f"Process {proc_name!r} (PID {pid}) has an injected memory region "
                        f"starting with 'MZ' (PE/DLL header). This is definitive evidence "
                        f"of reflective DLL injection or process hollowing."
                    ),
                    mitre_technique="T1055",
                    mitre_technique_name="Process Injection",
                    evidence={
                        "vad_start": hex(getattr(region, "start", 0)),
                        "vad_end": hex(getattr(region, "end", 0)),
                        "protection": getattr(region, "protection", ""),
                        "first_bytes": raw_bytes[:16].hex() if raw_bytes else "",
                    },
                    confidence=0.99,
                )
            )
            return results  # No need to check more patterns — PE injection confirmed

        # URL / C2 pattern
        urls = _RE_URL.findall(combined_text)
        if urls:
            # Filter out obviously benign URLs (Microsoft, Windows update)
            suspicious_urls = [
                u
                for u in urls
                if not any(
                    d in u.lower()
                    for d in (
                        "microsoft.com",
                        "windows.com",
                        "windowsupdate.com",
                        "msftncsi.com",
                        "msecnd.net",
                    )
                )
            ]
            if suspicious_urls:
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=pid,
                        process_name=proc_name,
                        severity=FindingSeverity.CRITICAL,
                        title=f"C2 URL strings in injected region: {proc_name}",
                        description=(
                            f"Injected memory region in {proc_name!r} (PID {pid}) contains "
                            f"{len(suspicious_urls)} URL(s) that may be C2 beacons: "
                            f"{suspicious_urls[:3]}"
                        ),
                        mitre_technique="T1071",
                        mitre_technique_name="Application Layer Protocol",
                        evidence={"urls": suspicious_urls[:10]},
                        confidence=0.9,
                    )
                )

        # IP address pattern
        ips = _RE_IP.findall(combined_text)
        if ips:
            external_ips = [
                ip
                for ip in ips
                if not any(
                    ip.startswith(p)
                    for p in (
                        "127.",
                        "10.",
                        "192.168.",
                        "172.16.",
                        "172.17.",
                        "172.18.",
                        "172.19.",
                        "172.20.",
                        "172.21.",
                        "172.22.",
                        "172.23.",
                        "172.24.",
                        "172.25.",
                        "172.26.",
                        "172.27.",
                        "172.28.",
                        "172.29.",
                        "172.30.",
                        "172.31.",
                        "0.0.0.",
                        "255.",
                        "169.254.",
                    )
                )
            ]
            if external_ips:
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=pid,
                        process_name=proc_name,
                        severity=FindingSeverity.HIGH,
                        title=f"External IP addresses in injected region: {proc_name}",
                        description=(
                            f"Injected memory region in {proc_name!r} (PID {pid}) contains "
                            f"external IP addresses: {external_ips[:5]}. Possible C2 hardcoded IPs."
                        ),
                        mitre_technique="T1071",
                        mitre_technique_name="Application Layer Protocol",
                        evidence={"external_ips": external_ips[:10]},
                        confidence=0.85,
                    )
                )

        # Registry persistence
        reg_matches = _RE_REGISTRY_RUN.findall(combined_text)
        if reg_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Registry persistence key in injected region: {proc_name}",
                    description=(
                        f"Injected memory region in {proc_name!r} (PID {pid}) contains "
                        f"Windows registry persistence paths: {list(set(reg_matches))[:3]}"
                    ),
                    mitre_technique="T1547",
                    mitre_technique_name="Boot or Logon Autostart Execution",
                    evidence={"registry_keys": list(set(reg_matches))[:10]},
                    confidence=0.88,
                )
            )

        # Suspicious executable paths
        path_matches = _RE_SUSPICIOUS_PATH.findall(combined_text)
        if path_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Suspicious executable path in injected region: {proc_name}",
                    description=(
                        f"Injected memory region in {proc_name!r} (PID {pid}) contains "
                        f"executable paths in suspicious directories: {path_matches[:3]}"
                    ),
                    mitre_technique="T1204.002",
                    mitre_technique_name="User Execution: Malicious File",
                    evidence={"paths": path_matches[:10]},
                    confidence=0.80,
                )
            )

        # Injection API strings (case-insensitive)
        combined_lower = combined_text.lower()
        found_injection = [s for s in _INJECTION_STRINGS if s in combined_lower]
        if found_injection:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"DLL injection API strings in memory: {proc_name}",
                    description=(
                        f"Injected memory region in {proc_name!r} (PID {pid}) contains "
                        f"known injection API strings: {found_injection[:5]}"
                    ),
                    mitre_technique="T1055",
                    mitre_technique_name="Process Injection",
                    evidence={"api_strings": found_injection},
                    confidence=0.85,
                )
            )

        return results

    # ─── Linux IOC Scanner ────────────────────────────────────────────────────

    def _detect_linux(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        """Linux-specific IOC extraction from malfind regions (Gap 2 coverage).

        Scans anonymous RWX memory pages for attacker tradecraft strings that
        ProcessAnomalyDetector does not inspect at the string level.
        Windows-specific patterns (PE headers, registry, Win32 APIs) are not
        applied — they never appear in Linux memory.

        Detected IOC categories:
            - Interactive reverse shell strings (/bin/sh -i, nc -e, mkfifo)
            - Credential file paths (/etc/shadow, /etc/sudoers)
            - LD_PRELOAD and cron/SSH persistence strings
            - /dev/shm staging and memfd_create fileless execution patterns
        """
        findings: list[DetectorResult] = []

        if not extraction.malfind:
            return findings

        pid_to_name: dict[int, str] = {}
        if extraction.process_tree:
            pid_to_name = {pid: proc.name for pid, proc in extraction.process_tree.flat_map.items()}

        for pid, regions in extraction.malfind.items():
            proc_name = pid_to_name.get(pid, "<unknown>")
            for region in regions:
                findings.extend(self._analyze_linux_region(pid, proc_name, region))

        return findings

    def _analyze_linux_region(
        self,
        pid: int,
        proc_name: str,
        region: Any,
    ) -> list[DetectorResult]:
        """Scan a single Linux malfind region for attacker-specific IOC strings."""
        results = []

        hexdump = getattr(region, "hexdump", "") or ""
        disasm = getattr(region, "disassembly", "") or ""
        raw_bytes = self._hexdump_to_bytes(hexdump)
        printable = self._extract_printable_strings(raw_bytes, min_length=6)
        combined_text = "\n".join(printable) + "\n" + disasm

        # Reverse shell → CRITICAL (active exploitation indicator)
        rs_matches = _RE_LINUX_REVERSE_SHELL.findall(combined_text)
        if rs_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.CRITICAL,
                    title=f"Reverse shell strings in RWX region: {proc_name}",
                    description=(
                        f"Process {proc_name!r} (PID {pid}) has anonymous RWX memory "
                        f"containing reverse shell command patterns. Strong indicator of "
                        f"active post-exploitation or an in-memory implant."
                    ),
                    mitre_technique="T1059.004",
                    mitre_technique_name="Command and Scripting Interpreter: Unix Shell",
                    evidence={"patterns": [str(m) for m in rs_matches[:5]]},
                    confidence=0.90,
                )
            )

        # Credential file paths → HIGH
        cred_matches = _RE_LINUX_CRED.findall(combined_text)
        if cred_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Credential file path in RWX region: {proc_name}",
                    description=(
                        f"Process {proc_name!r} (PID {pid}) has anonymous RWX memory "
                        f"containing paths to sensitive Linux credential files "
                        f"({list(set(cred_matches))[:3]}). Possible credential dumping "
                        f"or privilege escalation attack."
                    ),
                    mitre_technique="T1003.008",
                    mitre_technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
                    evidence={"paths": list(set(cred_matches))[:10]},
                    confidence=0.80,
                )
            )

        # Persistence strings → HIGH
        persist_matches = _RE_LINUX_PERSISTENCE.findall(combined_text)
        if persist_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Linux persistence indicator in RWX region: {proc_name}",
                    description=(
                        f"Process {proc_name!r} (PID {pid}) has anonymous RWX memory "
                        f"containing Linux persistence artifact strings "
                        f"({list(set(persist_matches))[:3]}). Possible LD_PRELOAD hijacking, "
                        f"cron persistence, or SSH key injection."
                    ),
                    mitre_technique="T1574.006",
                    mitre_technique_name="Hijack Execution Flow: LD_PRELOAD",
                    evidence={"indicators": list(set(persist_matches))[:10]},
                    confidence=0.78,
                )
            )

        # Fileless staging / in-memory execution → HIGH
        staging_matches = _RE_LINUX_STAGING.findall(combined_text)
        if staging_matches:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Fileless execution indicator in RWX region: {proc_name}",
                    description=(
                        f"Process {proc_name!r} (PID {pid}) has anonymous RWX memory "
                        f"containing fileless execution patterns "
                        f"({list(set(staging_matches))[:3]}). Possible /dev/shm staging "
                        f"or memfd_create-based implant."
                    ),
                    mitre_technique="T1620",
                    mitre_technique_name="Reflective Code Loading",
                    evidence={"indicators": list(set(staging_matches))[:10]},
                    confidence=0.82,
                )
            )

        return results

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _hexdump_to_bytes(self, hexdump: str) -> bytes:
        """Convert a Volatility hexdump string to raw bytes.

        Volatility malfind hexdump format (example line):
            0x7ffe0000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  MZ......  ........

        We strip the address prefix and ASCII column, extract hex bytes.
        """
        if not hexdump:
            return b""

        hex_bytes = []
        for line in hexdump.splitlines():
            # Remove address column (0x...)
            if line.startswith("0x"):
                parts = line.split()
                # Skip the first element (address), collect hex pairs until ASCII
                for part in parts[1:]:
                    if len(part) == 2:
                        try:
                            hex_bytes.append(int(part, 16))
                        except ValueError:
                            break  # Hit ASCII column
                    else:
                        break
        try:
            return bytes(hex_bytes)
        except (OverflowError, ValueError):
            return b""

    def _extract_printable_strings(
        self,
        data: bytes,
        min_length: int = 6,
    ) -> list[str]:
        """Extract printable ASCII strings from raw bytes (like GNU strings)."""
        if not data:
            return []

        strings: list[str] = []
        current: list[int] = []

        for byte in data:
            # Printable ASCII: 0x20-0x7E
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
            else:
                if len(current) >= min_length:
                    strings.append(bytes(current).decode("ascii", errors="replace"))
                current = []

        if len(current) >= min_length:
            strings.append(bytes(current).decode("ascii", errors="replace"))

        return strings
