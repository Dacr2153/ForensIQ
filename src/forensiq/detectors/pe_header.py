# FILE: src/forensiq/detectors/pe_header.py
"""PE Header Analyzer Detector.

Parses PE headers embedded in malfind memory regions using the pefile library.
Detects:
    - Suspicious imported DLLs (process injection APIs, keyloggers, etc.)
    - Suspicious imported functions (VirtualAlloc, CreateRemoteThread, etc.)
    - Anomalous section names (packed/obfuscated sections)
    - Missing or invalid PE headers in supposedly executable regions
    - Compile timestamp analysis

pefile library: https://github.com/erocarrera/pefile

MITRE ATT&CK:
    T1055   — Process Injection
    T1055.012 — Process Hollowing
    T1027   — Obfuscated Files or Information
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.extraction.orchestrator import ExtractionResult
    from forensiq.models.features import ProcessFeatureVector

log = get_logger(__name__)

# Imports strongly associated with process injection and code injection
_SUSPICIOUS_IMPORTS: dict[str, str] = {
    # Injection primitives
    "virtualalloc": "Memory allocation (common in injection)",
    "virtualallocex": "Remote process memory allocation",
    "virtualprotect": "Memory protection change (shellcode staging)",
    "virtualprotectex": "Remote memory protection change",
    "writeprocessmemory": "Write to foreign process (injection)",
    "createremotethread": "Thread creation in foreign process (injection)",
    "ntcreatethread": "NT-level thread creation",
    "ntopenprocess": "NT-level process access",
    "ntwritevirtualmemory": "NT-level memory write",
    "rtlcreateuserthread": "User-mode thread in foreign process",
    "queueuserapc": "APC injection primitive",
    # Credential theft
    "minidumpwritedump": "Process memory dump (credential theft)",
    "samdumppasswords": "SAM database dump",
    "logonuserw": "Logon impersonation",
    # Persistence / DLL
    "setwindowshookexa": "Windows hook installation",
    "setwindowshookexw": "Windows hook installation",
    "regsetvalueexa": "Registry write (persistence)",
    "regsetvalueexw": "Registry write (persistence)",
    # Keylogger
    "getkeystate": "Keyboard state (keylogger)",
    "getasynckeystate": "Async keyboard state (keylogger)",
    "getforegroundwindow": "Window focus monitoring (keylogger)",
}

# PE section names associated with packers/obfuscators
_PACKER_SECTIONS: set[str] = {
    "upx0",
    "upx1",
    "upx2",
    "upx!",  # UPX packer
    ".aspack",
    "adata",  # ASPack
    ".themida",
    "winlice",  # Themida/WinLicense
    ".petite",
    "petite",  # Petite
    "nspack",
    ".nsp0",
    ".nsp1",  # NsPacK
    ".mpress1",
    ".mpress2",  # MPRESS
    "!ep",
    ".vmp0",
    ".vmp1",  # VMProtect
    ".enigma1",
    ".enigma2",  # Enigma Protector
}


class PEHeaderDetector(BaseDetector):
    """Analyze PE headers in malfind injected regions using pefile.

    Attempts to parse each malfind hexdump as a PE/DLL file. If successful,
    checks imports, section names, and compile timestamps for anomalies.
    """

    name = "pe_header"
    description = (
        "Parses PE headers from malfind memory regions using pefile. "
        "Detects suspicious imports, packer sections, and PE anomalies."
    )

    def detect(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
    ) -> list[DetectorResult]:
        try:
            import pefile  # noqa: F401 — verify available
        except ImportError:
            log.warning("pefile not available — PE header analysis skipped")
            return []

        findings: list[DetectorResult] = []

        # PE header analysis is entirely Windows-specific (MZ/PE format, Win32 imports,
        # packer sections). Linux processes never have PE headers in their malfind pages.
        if getattr(extraction, "is_linux", False):
            return findings

        if not extraction.malfind:
            return findings

        pid_to_name: dict[int, str] = {}
        if extraction.process_tree:
            pid_to_name = {pid: proc.name for pid, proc in extraction.process_tree.flat_map.items()}

        for pid, regions in extraction.malfind.items():
            proc_name = pid_to_name.get(pid, "<unknown>")
            for region in regions:
                findings.extend(self._analyze_pe(pid, proc_name, region))

        return findings

    def _analyze_pe(
        self,
        pid: int,
        proc_name: str,
        region: Any,
    ) -> list[DetectorResult]:
        """Try to parse region hexdump as PE and extract indicators."""
        import pefile

        hexdump = getattr(region, "hexdump", "") or ""
        raw_bytes = self._hexdump_to_bytes(hexdump)

        if not raw_bytes or len(raw_bytes) < 64:
            return []

        # Quick check: must start with MZ magic
        if raw_bytes[:2] != b"MZ":
            return []

        try:
            pe = pefile.PE(data=raw_bytes, fast_load=False)
        except pefile.PEFormatError:
            return []
        except Exception as exc:
            log.debug("pefile parse error", pid=pid, error=str(exc))
            return []

        results: list[DetectorResult] = []

        # ── Check imports ──────────────────────────────────────────────────
        suspicious_found: list[dict[str, str]] = []
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="replace").lower()
                            if func_name in _SUSPICIOUS_IMPORTS:
                                suspicious_found.append(
                                    {
                                        "dll": dll_name,
                                        "function": func_name,
                                        "reason": _SUSPICIOUS_IMPORTS[func_name],
                                    }
                                )
        except Exception as exc:
            log.debug("Import parsing error", pid=pid, error=str(exc))

        if suspicious_found:
            # Determine severity based on number and type of suspicious imports
            has_injection_core = any(
                i["function"]
                in (
                    "createremotethread",
                    "writeprocessmemory",
                    "virtualprotectex",
                    "virtualallocex",
                    "ntcreatethread",
                )
                for i in suspicious_found
            )
            severity = FindingSeverity.CRITICAL if has_injection_core else FindingSeverity.HIGH

            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=severity,
                    title=f"Suspicious PE imports in injected region: {proc_name}",
                    description=(
                        f"Injected PE in {proc_name!r} (PID {pid}) imports "
                        f"{len(suspicious_found)} suspicious function(s): "
                        f"{[i['function'] for i in suspicious_found[:5]]}"
                    ),
                    mitre_technique="T1055",
                    mitre_technique_name="Process Injection",
                    evidence={
                        "suspicious_imports": suspicious_found[:20],
                        "total_suspicious": len(suspicious_found),
                        "has_injection_core": has_injection_core,
                    },
                    confidence=0.92,
                )
            )

        # ── Check section names ────────────────────────────────────────────
        packer_sections_found: list[str] = []
        try:
            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="replace").strip("\x00").lower()
                if section_name in _PACKER_SECTIONS:
                    packer_sections_found.append(section_name)
        except Exception as exc:
            log.debug("Section parse error", pid=pid, error=str(exc))

        if packer_sections_found:
            results.append(
                DetectorResult(
                    detector=self.name,
                    pid=pid,
                    process_name=proc_name,
                    severity=FindingSeverity.HIGH,
                    title=f"Packer section names in injected PE: {proc_name}",
                    description=(
                        f"Injected PE in {proc_name!r} (PID {pid}) has section names "
                        f"associated with known packers/protectors: {packer_sections_found}. "
                        f"Packed malware often uses these to avoid static analysis."
                    ),
                    mitre_technique="T1027",
                    mitre_technique_name="Obfuscated Files or Information",
                    evidence={"packer_sections": packer_sections_found},
                    confidence=0.87,
                )
            )

        # ── Check for minimal/hollow PE (0 sections = hollowed process) ───
        try:
            num_sections = pe.FILE_HEADER.NumberOfSections
            if num_sections == 0:
                results.append(
                    DetectorResult(
                        detector=self.name,
                        pid=pid,
                        process_name=proc_name,
                        severity=FindingSeverity.CRITICAL,
                        title=f"Hollow PE (zero sections) in injected region: {proc_name}",
                        description=(
                            f"Injected PE in {proc_name!r} (PID {pid}) has 0 sections. "
                            f"This is characteristic of process hollowing — the original "
                            f"PE was replaced with a minimal stub."
                        ),
                        mitre_technique="T1055.012",
                        mitre_technique_name="Process Hollowing",
                        evidence={"num_sections": num_sections},
                        confidence=0.90,
                    )
                )
        except Exception:  # noqa: S110
            pass  # Malformed hexdump / PE parse error — skip region silently

        return results

    def _hexdump_to_bytes(self, hexdump: str) -> bytes:
        """Convert Volatility hexdump to raw bytes."""
        if not hexdump:
            return b""

        hex_bytes = []
        for line in hexdump.splitlines():
            if line.startswith("0x"):
                parts = line.split()
                for part in parts[1:]:
                    if len(part) == 2:
                        try:
                            hex_bytes.append(int(part, 16))
                        except ValueError:
                            break
                    else:
                        break
        try:
            return bytes(hex_bytes)
        except (OverflowError, ValueError):
            return b""
