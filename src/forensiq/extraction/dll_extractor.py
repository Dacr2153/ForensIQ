# FILE: src/forensiq/extraction/dll_extractor.py
"""DLL loaded-module extraction from Volatility 3 windows.dlllist plugin.

windows.dlllist enumerates the PEB InMemoryOrderModuleList for each process,
revealing all loaded DLLs including injected ones.

Reflective DLL injection bypasses this (no PEB entry) but leaves traces
in the VAD which malfind/vadinfo capture.

Usage:
    from forensiq.extraction.dll_extractor import DLLExtractor
    from forensiq.acquisition.volatility_runner import VolatilityRunner

    runner = VolatilityRunner(dump_path=Path("/dumps/memory.raw"))
    extractor = DLLExtractor(runner)
    dlls = extractor.extract()
    # dlls: dict[int, list[DLLEntry]] keyed by PID
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.extraction._utils import _PID_COLS, _find_col
from forensiq.models.artifact import DLLEntry
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Column name mappings ──────────────────────────────────────────────────────
# Linux library_list uses "LoadAddress"
_BASE_COLS = ("Base", "base", "DllBase", "LoadAddress")
_SIZE_COLS = ("Size", "size", "SizeOfImage")
# Linux library_list uses "Path"
_FULL_NAME_COLS = ("FullDllName", "full_dll_name", "FullName", "Path", "Filename")
_LOAD_COUNT_COLS = ("LoadCount", "load_count", "ReferenceCount")


def _parse_int_hex(val: Any, default: int = 0) -> int:
    """Parse integer or hex string from Volatility."""
    if val is None:
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val or val in ("-", "N/A"):
            return default
        try:
            if val.startswith(("0x", "0X")):
                return int(val, 16)
            return int(val)
        except ValueError:
            return default
    return default


class DLLExtractor:
    """Extracts DLL loaded-module lists from windows.dlllist plugin.

    Args:
        runner: Configured VolatilityRunner for the target dump.
    """

    # Matches shared library paths in /proc/PID/maps
    _SO_RE = re.compile(r"\.so(\.[\d.]+)?$")

    def _dlls_from_proc_maps(self, pids: list[int]) -> dict[int, list[DLLEntry]]:
        """Read loaded shared libraries from /proc/PID/maps as fallback.

        Only file-backed readable mappings whose path ends in .so (or .so.N)
        are collected.  Each unique path is emitted once per PID.
        """
        result: dict[int, list[DLLEntry]] = {}
        proc_root = Path("/proc")
        if not proc_root.exists():
            return result
        for pid in pids:
            maps_file = proc_root / str(pid) / "maps"
            try:
                seen_paths: set[str] = set()
                for line in maps_file.read_text(errors="replace").splitlines():
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    path = parts[5]
                    # Skip anonymous, device, and non-so paths
                    if not path or path.startswith("["):
                        continue
                    if not self._SO_RE.search(path):
                        continue
                    if path in seen_paths:
                        continue
                    seen_paths.add(path)
                    addr_range = parts[0]
                    base_hex = addr_range.split("-")[0]
                    try:
                        base = int(base_hex, 16)
                    except ValueError:
                        base = 0
                    result.setdefault(pid, []).append(
                        DLLEntry(
                            pid=pid,
                            base=base,
                            size=0,
                            full_dll_name=path,
                            load_count=1,
                        )
                    )
            except (PermissionError, FileNotFoundError, OSError):
                pass
        total = sum(len(v) for v in result.values())
        if total:
            log.info(
                "Shared libraries read from /proc/PID/maps (linux.library_list fallback)",
                total=total,
                pids=len(result),
            )
        return result

    def __init__(self, runner: VolatilityRunner, dll_root: Path | None = None) -> None:
        self._runner = runner
        # Content hashing is wired into extraction so all pipeline paths
        # (sequential / parallel / async) populate genuine content_sha256 for
        # suspicious DLLs — enabling real threat-intel lookups.
        self._dll_root = dll_root

    def _hash_content(
        self,
        dlls_by_pid: dict[int, list[DLLEntry]],
    ) -> dict[int, list[DLLEntry]]:
        """Populate genuine content_sha256 for suspicious DLLs.

        Resolves DLL paths to real files (under FORENSIQ_DLL_ROOT when set,
        otherwise as absolute host paths — the live Linux case) and computes
        SHA-256 of the file content. Never fabricates a hash.

        Args:
            dlls_by_pid: DLL entries grouped by PID.

        Returns:
            Updated dict with content_sha256 populated where resolvable.
        """
        from forensiq.extraction.dll_hasher import DLLContentHasher

        hasher = DLLContentHasher(dll_root=self._dll_root)
        return hasher.hash_dlls(dlls_by_pid)

    def _row_to_dll_entry(self, row: dict[str, Any]) -> DLLEntry | None:
        """Convert a single dlllist row to a DLLEntry.

        Args:
            row: A single row from windows.dlllist JSON output.

        Returns:
            DLLEntry if parseable, None otherwise.
        """
        pid_raw = _find_col(row, _PID_COLS)
        if pid_raw is None:
            return None

        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            return None

        full_name_raw = _find_col(row, _FULL_NAME_COLS)
        full_name = str(full_name_raw).strip().rstrip("\x00") if full_name_raw else ""

        return DLLEntry(
            pid=pid,
            base=_parse_int_hex(_find_col(row, _BASE_COLS)),
            size=_parse_int_hex(_find_col(row, _SIZE_COLS)),
            full_dll_name=full_name,
            load_count=_parse_int_hex(_find_col(row, _LOAD_COUNT_COLS), default=1),
        )

    def extract(self) -> dict[int, list[DLLEntry]]:
        """Run windows.dlllist and return DLL entries grouped by PID.

        Returns:
            Dict mapping PID → list of DLLEntry objects.
            Processes with no DLLs listed are absent from the dict.
        """
        log.info("Extracting DLL lists")
        # Linux: linux.library_list  Windows: windows.dlllist
        plugin = "linux.library_list" if self._runner.is_linux else "windows.dlllist"
        try:
            rows = self._runner.run_plugin(plugin)
        except Exception as exc:
            log.warning(
                f"{plugin} failed, continuing without DLL data",
                error=str(exc),
            )
            return {}

        dlls_by_pid: dict[int, list[DLLEntry]] = {}
        skipped = 0

        for row in rows:
            entry = self._row_to_dll_entry(row)
            if entry is None:
                skipped += 1
                continue
            dlls_by_pid.setdefault(entry.pid, []).append(entry)

        total = sum(len(v) for v in dlls_by_pid.values())
        log.info(
            "DLL entries extracted",
            total=total,
            pids_with_dlls=len(dlls_by_pid),
            skipped=skipped,
        )
        return self._hash_content(dlls_by_pid)

    async def extract_async(self) -> dict[int, list[DLLEntry]]:
        """Async variant: run windows.dlllist via asyncio subprocess."""
        log.info("Extracting DLL lists (async)")
        plugin = "linux.library_list" if self._runner.is_linux else "windows.dlllist"
        try:
            rows = await self._runner.run_plugin_async(plugin)
        except Exception as exc:
            log.warning(f"{plugin} async failed, continuing", error=str(exc))
            return {}

        dlls_by_pid: dict[int, list[DLLEntry]] = {}
        skipped = 0
        for row in rows:
            entry = self._row_to_dll_entry(row)
            if entry is None:
                skipped += 1
                continue
            dlls_by_pid.setdefault(entry.pid, []).append(entry)

        total = sum(len(v) for v in dlls_by_pid.values())
        log.info(
            "DLL entries extracted (async)",
            total=total,
            pids_with_dlls=len(dlls_by_pid),
            skipped=skipped,
        )

        # If the Volatility plugin failed and we're on a live Linux system,
        # fall back to /proc/PID/maps which lists all loaded shared libraries.
        if not dlls_by_pid and self._runner.is_linux:
            all_pids: list[int] = []
            # We don't have access to process list here, so scan /proc directly
            try:
                all_pids = [int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit()]
            except OSError:
                pass
            if all_pids:
                dlls_by_pid = self._dlls_from_proc_maps(all_pids)

        return self._hash_content(dlls_by_pid)
