# FILE: src/forensiq/yara/dll_scanner.py
"""YARA scanning of DLL memory regions from memory dumps.

Scans malfind hexdump regions and injected memory found in suspicious
processes against a set of built-in detection YARA rules.

The scanner uses the yara-python library to compile and apply rules
against the raw bytes decoded from Volatility's malfind hexdump output.

Built-in rules target:
  - PE header indicators in injected memory
  - Common shellcode patterns (NOP sleds, PUSH/RET chains)
  - Known packer signatures (UPX, MPRESS)
  - Reflective DLL injection markers
  - Cobalt Strike beacon patterns
  - Meterpreter stage 1 indicators

Usage:
    from forensiq.yara.dll_scanner import YARADLLScanner
    scanner = YARADLLScanner()
    hits = scanner.scan_extraction(extraction_result, suspicious_pids={3388, 4096})
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensiq.utils.hexdump import hexdump_to_bytes
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Built-in YARA Rules ──────────────────────────────────────────────────────
# These rules are compiled at import time and detect common memory injection
# patterns in hexdump data from Volatility's malfind plugin output.

_BUILTIN_RULES_SOURCE = r"""
rule forensiq_pe_in_injected_memory {
    meta:
        description = "PE header (MZ) in injected/private memory — hollowing or injection"
        author      = "ForensIQ Built-in"
        severity    = "high"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 or $pe
}

rule forensiq_nop_sled_shellcode {
    meta:
        description = "NOP sled pattern in injected memory — common shellcode precursor"
        author      = "ForensIQ Built-in"
        severity    = "high"
    strings:
        $nop8  = { 90 90 90 90 90 90 90 90 }
        $nop16 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        any of them
}

rule forensiq_upx_packer {
    meta:
        description = "UPX packer signature found — binary is packed, likely to evade AV"
        author      = "ForensIQ Built-in"
        severity    = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        any of them
}

rule forensiq_reflective_dll_injection {
    meta:
        description = "Reflective DLL loader pattern — process loads DLL from memory without disk"
        author      = "ForensIQ Built-in"
        severity    = "high"
    strings:
        $reflective_loader = "ReflectiveDLLInjection" ascii nocase
        $load_library_r    = "LoadLibraryR" ascii
        $dll_entry         = "DllMain" ascii
    condition:
        any of them
}

rule forensiq_cobalt_strike_beacon {
    meta:
        description = "Cobalt Strike beacon indicators found in process memory"
        author      = "ForensIQ Built-in"
        severity    = "critical"
    strings:
        $cs1 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $cs2 = "beacon.dll" ascii nocase
        $cs3 = "%s (admin)" ascii
        $cs4 = "cobalt strike" ascii nocase
        $cs5 = { 48 83 EC 20 41 B8 }
    condition:
        any of them
}

rule forensiq_meterpreter_stager {
    meta:
        description = "Metasploit meterpreter stager patterns in injected memory"
        author      = "ForensIQ Built-in"
        severity    = "critical"
    strings:
        $msf1 = "meterpreter" ascii nocase
        $msf2 = "METERPRETER" ascii
        $msf3 = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $msf4 = "ReflectiveLoader" ascii
    condition:
        any of them
}

rule forensiq_process_injection_createremotethread {
    meta:
        description = "CreateRemoteThread injection pattern — common code injection technique"
        author      = "ForensIQ Built-in"
        severity    = "high"
    strings:
        $crt  = "CreateRemoteThread" ascii nocase
        $vae  = "VirtualAllocEx" ascii nocase
        $wpm  = "WriteProcessMemory" ascii nocase
    condition:
        2 of them
}

rule forensiq_powershell_encoded_payload {
    meta:
        description = "PowerShell encoded command in process memory — fileless execution"
        author      = "ForensIQ Built-in"
        severity    = "high"
    strings:
        $enc1 = "powershell" ascii nocase
        $enc2 = "-EncodedCommand" ascii nocase
        $enc3 = "-enc " ascii nocase
        $b64  = /[A-Za-z0-9+\/]{50,}={0,2}/
    condition:
        ($enc1 or $enc2 or $enc3) and $b64
}

rule forensiq_suspicious_api_hashing {
    meta:
        description = "API hashing / dynamic import resolution — common in shellcode/packed malware"
        author      = "ForensIQ Built-in"
        severity    = "medium"
    strings:
        $ror13 = { C1 C8 0D }
        $xor1  = { 31 C0 99 }
        $hash1 = { 33 C9 AC 84 C0 74 }
    condition:
        2 of them
}
"""


@dataclass
class YARADLLHit:
    """A single YARA rule match on a memory region."""

    pid: int
    process_name: str
    region_start: int
    region_end: int
    rule_name: str
    rule_description: str
    severity: str  # "low", "medium", "high", "critical"
    match_strings: list[str] = field(default_factory=list)


class YARADLLScanner:
    """Scans injected memory regions using built-in + user YARA rules.

    Compiles the rule set once at construction time. Thread-safe for
    reading; don't mutate after construction.
    """

    def __init__(self, extra_rules_dir: Path | None = None) -> None:
        """Initialize and compile YARA rules.

        Args:
            extra_rules_dir: Optional directory of additional .yar/.yara files
                             to compile alongside the built-in rules. Rules are
                             compiled per-file so a syntax error in one file
                             never disables the rest of the scanner.
        """
        self._compiled_rules: list[Any] = []

        try:
            import yara
        except ImportError:
            log.warning("yara-python not installed — DLL YARA scanning disabled")
            return

        self._compile_source(yara, "builtin", _BUILTIN_RULES_SOURCE, "<builtin>")

        if extra_rules_dir and extra_rules_dir.is_dir():
            for yar_file in sorted(extra_rules_dir.glob("*.yar")) + sorted(
                extra_rules_dir.glob("*.yara")
            ):
                try:
                    source = yar_file.read_text(encoding="utf-8")
                except OSError as exc:
                    log.warning(
                        "Failed to read YARA file", path=str(yar_file), error=str(exc)
                    )
                    continue
                self._compile_source(yara, yar_file.stem, source, str(yar_file))

        log.info(
            "YARADLLScanner compiled",
            rule_sets=len(self._compiled_rules),
            extra_dir=str(extra_rules_dir) if extra_rules_dir else None,
        )

    def _compile_source(
        self,
        yara: Any,
        name: str,
        source: str,
        display_path: str,
    ) -> None:
        """Compile one rule source in isolation.

        A syntax error in this source is logged and does not abort the scanner —
        the rest of the rule sets remain usable.
        """
        try:
            compiled = yara.compile(source=source)
        except Exception as exc:
            log.warning(
                "Skipping YARA source with compile error",
                name=name,
                path=display_path,
                error=str(exc),
            )
            return
        if compiled:
            self._compiled_rules.append(compiled)
            log.debug("Compiled YARA source", name=name, path=display_path)

    @property
    def is_ready(self) -> bool:
        """True if at least one YARA rule set compiled successfully."""
        return len(self._compiled_rules) > 0

    def scan_extraction(
        self,
        extraction: Any,  # ExtractionResult (avoid circular import)
        suspicious_pids: set[int] | None = None,
    ) -> list[YARADLLHit]:
        """Scan malfind memory regions from an ExtractionResult.

        Decodes the hexdump bytes from each malfind region and runs
        the compiled YARA rules against them.

        Args:
            extraction: ExtractionResult with malfind data.
            suspicious_pids: Optional set of PIDs to limit scanning.
                             None → scan all PIDs with malfind hits.

        Returns:
            List of YARADLLHit objects for every rule match found.
        """
        if not self.is_ready:
            log.warning("YARADLLScanner not ready — skipping DLL YARA scan")
            return []

        hits: list[YARADLLHit] = []
        pids_to_scan = (
            suspicious_pids if suspicious_pids is not None else set(extraction.malfind.keys())
        )

        for pid in pids_to_scan:
            regions = extraction.malfind.get(pid, [])
            if not regions:
                continue

            # Get process name
            proc_name = "unknown"
            if extraction.process_tree:
                proc = extraction.process_tree.flat_map.get(pid)
                if proc:
                    proc_name = proc.name

            for region in regions:
                raw_bytes = hexdump_to_bytes(region.hexdump)
                if not raw_bytes:
                    continue

                region_hits = self._scan_bytes(raw_bytes)
                for rule_name, rule_desc, severity, match_strings in region_hits:
                    hits.append(
                        YARADLLHit(
                            pid=pid,
                            process_name=proc_name,
                            region_start=region.start,
                            region_end=region.end,
                            rule_name=rule_name,
                            rule_description=rule_desc,
                            severity=severity,
                            match_strings=match_strings[:5],  # Limit to 5 per hit
                        )
                    )

        log.info(
            "DLL YARA scan complete",
            pids_scanned=len(pids_to_scan),
            hits=len(hits),
        )
        return hits

    def _scan_bytes(self, data: bytes) -> list[tuple[str, str, str, list[str]]]:
        """Scan raw bytes against all compiled YARA rule sets.

        Returns:
            List of (rule_name, description, severity, matched_strings).
        """
        if not self.is_ready:
            return []

        results: list[tuple[str, str, str, list[str]]] = []
        for compiled in self._compiled_rules:
            try:
                matches = compiled.match(data=data)
            except Exception as exc:
                log.debug("YARA scan error (non-fatal)", error=str(exc))
                continue
            for match in matches:
                meta = match.meta or {}
                description = str(meta.get("description", ""))
                severity = str(meta.get("severity", "medium"))
                # Collect matched string identifiers
                match_strs = []
                for m in match.strings:
                    if hasattr(m, "identifier"):
                        match_strs.append(m.identifier)
                    elif isinstance(m, (list, tuple)) and len(m) >= 2:
                        match_strs.append(str(m[1]))
                results.append((match.rule, description, severity, match_strs))

        return results
