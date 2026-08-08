# FILE: src/forensiq/extraction/vad_extractor.py
"""VAD and malfind artifact extraction from Volatility 3.

Plugins used:
    windows.vadinfo   — Virtual Address Descriptors (memory region map)
    windows.malfind   — Suspicious executable private memory regions

Usage:
    from forensiq.extraction.vad_extractor import VADExtractor
    from forensiq.acquisition.volatility_runner import VolatilityRunner

    runner = VolatilityRunner(dump_path=Path("/dumps/memory.raw"))
    extractor = VADExtractor(runner)
    vad_data = extractor.extract_vad()
    malfind_data = extractor.extract_malfind()
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.extraction._utils import _PID_COLS, _find_col
from forensiq.models.artifact import MalfindRegion, VADEntry
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Column name mappings ──────────────────────────────────────────────────────
_START_COLS = ("Start", "start", "VadStart", "StartingVpn")
_END_COLS = ("End", "end", "VadEnd", "EndingVpn")
_TAG_COLS = ("Tag", "tag", "VadTag")
# Linux proc.Maps uses "Flags" (e.g. "r-xp"); Windows uses "Protection" (e.g. "PAGE_EXECUTE")
_PROT_COLS = ("Protection", "protection", "VadProtection", "Flags")
_VAD_TYPE_COLS = ("VadType", "vad_type", "Type")
# Linux proc.Maps uses "File Path"
_FILE_COLS = ("MappedFile", "mapped_file", "Filename", "File", "File Path")
_HEXDUMP_COLS = ("Hexdump", "hexdump", "Hex", "Bytes")
_DISASM_COLS = ("Disasm", "disasm", "Disassembly", "Assembly")

# Kernel-managed VMA pseudo-files that are expected and benign — never treat
# these as suspicious even though they appear "anonymous" in /proc/PID/maps.
_KERNEL_PSEUDO_FILES = frozenset({"[vdso]", "[vvar]", "[vsyscall]", "[heap]", "[stack]"})


def _parse_addr(val: Any) -> int:
    """Parse a memory address (hex or int) from Volatility output."""
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val or val in ("-", "N/A"):
            return 0
        try:
            if val.startswith(("0x", "0X")):
                return int(val, 16)
            return int(val)
        except ValueError:
            return 0
    return 0


class VADExtractor:
    """Extracts VAD and malfind artifacts from Volatility 3 plugins.

    Args:
        runner: Configured VolatilityRunner for the target dump.
    """

    # Matches e.g. "rwxp", "r-xp", "rw-p" in /proc/PID/maps perms field
    _MAPS_LINE_RE = re.compile(
        r"^([0-9a-f]+)-([0-9a-f]+)\s+([rwxsp-]{4})\s+[0-9a-f]+\s+[0-9a-f:]+\s+\d+\s*(.*)?$"
    )

    def _malfind_from_proc_maps(self, pids: list[int]) -> dict[int, list[MalfindRegion]]:
        """Identify suspicious anonymous executable regions via /proc/PID/maps.

        A region is flagged as suspicious when it is both writable and executable
        (rwx) AND has no backing file (anonymous mapping) — the classic signature
        of shellcode / injected code.  JIT compilers also use rwx pages, so this
        will have false positives, but those are filtered by the ML model / detectors.

        This is a fallback for when linux.malware.malfind fails (e.g. kernel 6.1+
        maple-tree VMA management that Volatility 3 does not yet support).
        """
        result: dict[int, list[MalfindRegion]] = {}
        proc_root = Path("/proc")
        if not proc_root.exists():
            return result
        for pid in pids:
            maps_file = proc_root / str(pid) / "maps"
            try:
                for line in maps_file.read_text(errors="replace").splitlines():
                    m = self._MAPS_LINE_RE.match(line)
                    if not m:
                        continue
                    start_hex, end_hex, perms, path = m.groups()
                    path = (path or "").strip()
                    # Anonymous: no file path, or special pseudo-files like [heap]/[stack].
                    # Exclude kernel-managed pseudo-files ([vdso] etc.) — they are
                    # expected and must not be flagged as injected code.
                    if path in _KERNEL_PSEUDO_FILES:
                        continue
                    is_anon = not path or path.startswith("[")
                    is_rwx = "r" in perms and "w" in perms and "x" in perms
                    if is_anon and is_rwx:
                        result.setdefault(pid, []).append(
                            MalfindRegion(
                                pid=pid,
                                start=int(start_hex, 16),
                                end=int(end_hex, 16),
                                protection=perms,
                                tag=path or "anon",
                                hexdump="",
                                disassembly="",
                            )
                        )
            except (PermissionError, FileNotFoundError, OSError):
                pass
        total = sum(len(v) for v in result.values())
        if total:
            log.info(
                "Anonymous RWX regions found via /proc/PID/maps (linux.malware.malfind fallback)",
                total=total,
                pids=len(result),
            )
        return result

    def _vad_from_proc_maps(self, pids: set[int]) -> dict[int, list[VADEntry]]:
        """Read VMA regions from /proc/PID/maps as fallback for linux.proc.

        Covers the same information as linux.proc (kernel VMA walk) but reads
        directly from the live /proc filesystem.  Works for live analysis;
        historical dumps cannot use this path.
        """
        result: dict[int, list[VADEntry]] = {}
        proc_root = Path("/proc")
        if not proc_root.exists():
            return result
        for pid in pids:
            maps_file = proc_root / str(pid) / "maps"
            try:
                for line in maps_file.read_text(errors="replace").splitlines():
                    m = self._MAPS_LINE_RE.match(line)
                    if not m:
                        continue
                    start_hex, end_hex, perms, path = m.groups()
                    path = (path or "").strip()
                    result.setdefault(pid, []).append(
                        VADEntry(
                            pid=pid,
                            start=int(start_hex, 16),
                            end=int(end_hex, 16),
                            tag="",
                            protection=perms,
                            vad_type="",
                            mapped_file=path if path and not path.startswith("[") else None,
                        )
                    )
            except (PermissionError, FileNotFoundError, OSError):
                pass
        total = sum(len(v) for v in result.values())
        if total:
            log.info(
                "VAD regions read from /proc/PID/maps (linux.proc fallback)",
                total=total,
                pids=len(result),
            )
        return result

    def __init__(self, runner: VolatilityRunner) -> None:
        self._runner = runner

    def _row_to_vad_entry(self, row: dict[str, Any]) -> VADEntry | None:
        """Convert a single vadinfo row to a VADEntry."""
        pid_raw = _find_col(row, _PID_COLS)
        if pid_raw is None:
            return None

        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            return None

        mapped_file_raw = _find_col(row, _FILE_COLS)
        mapped_file: str | None = None
        if mapped_file_raw is not None:
            cleaned = str(mapped_file_raw).strip().rstrip("\x00")
            if cleaned and cleaned not in ("-", "N/A", ""):
                mapped_file = cleaned

        return VADEntry(
            pid=pid,
            start=_parse_addr(_find_col(row, _START_COLS)),
            end=_parse_addr(_find_col(row, _END_COLS)),
            tag=str(_find_col(row, _TAG_COLS) or "").strip(),
            protection=str(_find_col(row, _PROT_COLS) or "").strip(),
            vad_type=str(_find_col(row, _VAD_TYPE_COLS) or "").strip(),
            mapped_file=mapped_file,
        )

    def _row_to_malfind_region(self, row: dict[str, Any]) -> MalfindRegion | None:
        """Convert a single malfind row to a MalfindRegion."""
        pid_raw = _find_col(row, _PID_COLS)
        if pid_raw is None:
            return None

        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            return None

        # Hexdump and disassembly may be multi-line strings in Volatility output
        hexdump_raw = _find_col(row, _HEXDUMP_COLS)
        hexdump = str(hexdump_raw).strip() if hexdump_raw else ""

        disasm_raw = _find_col(row, _DISASM_COLS)
        disasm = str(disasm_raw).strip() if disasm_raw else ""

        return MalfindRegion(
            pid=pid,
            start=_parse_addr(_find_col(row, _START_COLS)),
            end=_parse_addr(_find_col(row, _END_COLS)),
            protection=str(_find_col(row, _PROT_COLS) or "").strip(),
            tag=str(_find_col(row, _TAG_COLS) or "").strip(),
            hexdump=hexdump,
            disassembly=disasm,
        )

    def extract_vad(self) -> dict[int, list[VADEntry]]:
        """Run windows.vadinfo and return VAD entries grouped by PID.

        VADinfo can be very slow on large dumps (many GB) due to the number
        of VAD entries. It is run with the default timeout (300s).

        Returns:
            Dict mapping PID → list of VADEntry objects.
        """
        log.info("Extracting VAD entries (may take a while for large dumps)")
        # Linux: linux.proc (memory maps)  Windows: windows.vadinfo
        plugin = "linux.proc" if self._runner.is_linux else "windows.vadinfo"
        try:
            rows = self._runner.run_plugin(plugin)
        except Exception as exc:
            log.warning(
                f"{plugin} failed, continuing without VAD data",
                error=str(exc),
            )
            return {}

        vad_by_pid: dict[int, list[VADEntry]] = {}
        skipped = 0

        for row in rows:
            entry = self._row_to_vad_entry(row)
            if entry is None:
                skipped += 1
                continue
            vad_by_pid.setdefault(entry.pid, []).append(entry)

        total = sum(len(v) for v in vad_by_pid.values())
        log.info(
            "VAD entries extracted",
            total=total,
            pids_with_vads=len(vad_by_pid),
            skipped=skipped,
        )
        return vad_by_pid

    def extract_malfind(self) -> dict[int, list[MalfindRegion]]:
        """Run windows.malfind and return suspicious regions grouped by PID.

        Returns:
            Dict mapping PID → list of MalfindRegion objects.
            Empty dict if malfind produces no output.
        """
        log.info("Extracting malfind regions")
        # Linux: linux.malware.malfind  Windows: windows.malfind
        plugin = "linux.malware.malfind" if self._runner.is_linux else "windows.malfind"
        try:
            rows = self._runner.run_plugin(plugin)
        except Exception as exc:
            log.warning(
                f"{plugin} failed, continuing without malfind data",
                error=str(exc),
            )
            return {}

        malfind_by_pid: dict[int, list[MalfindRegion]] = {}
        skipped = 0

        for row in rows:
            region = self._row_to_malfind_region(row)
            if region is None:
                skipped += 1
                continue
            malfind_by_pid.setdefault(region.pid, []).append(region)

        total = sum(len(v) for v in malfind_by_pid.values())
        log.info(
            "Malfind regions extracted",
            total=total,
            pids_with_hits=len(malfind_by_pid),
            skipped=skipped,
        )
        return malfind_by_pid

    async def extract_malfind_async(self) -> dict[int, list[MalfindRegion]]:
        """Async variant: run malfind plugin, with /proc fallback for Linux."""
        log.info("Extracting malfind regions (async)")
        plugin = "linux.malware.malfind" if self._runner.is_linux else "windows.malfind"
        rows: list[dict[str, Any]] = []
        try:
            rows = await self._runner.run_plugin_async(plugin)
        except Exception as exc:
            log.warning(f"{plugin} async failed, continuing", error=str(exc))

        malfind_by_pid: dict[int, list[MalfindRegion]] = {}
        skipped = 0
        for row in rows:
            region = self._row_to_malfind_region(row)
            if region is None:
                skipped += 1
                continue
            malfind_by_pid.setdefault(region.pid, []).append(region)

        total = sum(len(v) for v in malfind_by_pid.values())
        log.info(
            "Malfind regions extracted (async)", total=total, pids_with_hits=len(malfind_by_pid)
        )

        # Fallback: on Linux, use /proc/PID/maps to find anonymous rwx regions
        # when the plugin fails (e.g. kernel 6.1+ maple-tree VMA management).
        if self._runner.is_linux and total == 0:
            log.info("linux.malware.malfind returned 0 results — falling back to /proc/PID/maps")
            all_pids = [
                int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit() and p.is_dir()
            ]
            malfind_by_pid = self._malfind_from_proc_maps(all_pids)

        return malfind_by_pid

    async def extract_vad_for_pids_async(self, pids: set[int]) -> dict[int, list[VADEntry]]:
        """Async variant: run vadinfo selectively, with /proc fallback for Linux."""
        if not pids:
            return {}
        log.info("Extracting VAD entries (async, selective)", requested_pids=sorted(pids))
        plugin = "linux.proc" if self._runner.is_linux else "windows.vadinfo"
        rows: list[dict[str, Any]] = []
        try:
            rows = await self._runner.run_plugin_async(plugin)
        except Exception as exc:
            log.warning(f"{plugin} async failed (selective)", error=str(exc))

        vad_by_pid: dict[int, list[VADEntry]] = {}
        skipped = 0
        filtered_out = 0
        for row in rows:
            entry = self._row_to_vad_entry(row)
            if entry is None:
                skipped += 1
                continue
            if entry.pid not in pids:
                filtered_out += 1
                continue
            vad_by_pid.setdefault(entry.pid, []).append(entry)

        total = sum(len(v) for v in vad_by_pid.values())
        log.info(
            "Selective VAD extraction complete (async)",
            total=total,
            requested_pids=len(pids),
            pids_with_data=len(vad_by_pid),
            filtered_out=filtered_out,
        )

        # Fallback: on Linux, read /proc/PID/maps when linux.proc fails
        # (e.g. kernel 6.1+ maple-tree VMA management unsupported by Volatility 3).
        if self._runner.is_linux and total == 0:
            log.info("linux.proc returned 0 results — falling back to /proc/PID/maps")
            vad_by_pid = self._vad_from_proc_maps(pids)

        return vad_by_pid
