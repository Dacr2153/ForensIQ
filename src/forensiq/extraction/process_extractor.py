# FILE: src/forensiq/extraction/process_extractor.py
"""Process artifact extraction from Volatility 3 plugin output.

Plugins used:
    windows.pslist   — Running and terminated processes (PID, PPID, threads, handles)
    windows.pstree   — Process hierarchy (same data structured as a tree)
    windows.cmdline  — Command-line arguments from PEB

Usage:
    from forensiq.extraction.process_extractor import ProcessExtractor
    from forensiq.acquisition.volatility_runner import VolatilityRunner

    runner = VolatilityRunner(dump_path=Path("/dumps/memory.raw"))
    extractor = ProcessExtractor(runner)
    tree = extractor.extract()
    # tree: ProcessTree with all processes and hierarchy
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.extraction._utils import _PID_COLS, _find_col
from forensiq.models.process import ProcessArtifact, ProcessNode, ProcessTree
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Column name mappings ──────────────────────────────────────────────────────
# Volatility 3 may use slightly different column names between versions.
# These lists are tried in order; first match wins.

_PPID_COLS = ("PPID", "PPid", "Ppid", "ppid")
# Linux pslist uses "COMM" (15-char comm field); Windows uses "ImageFileName"
_NAME_COLS = ("ImageFileName", "Name", "name", "COMM")
_THREADS_COLS = ("Threads", "threads")
_HANDLES_COLS = ("Handles", "handles")
_SESSION_COLS = ("SessionId", "Session", "SessionID")
_WOW64_COLS = ("Wow64", "WoW64", "wow64")
# Linux pslist uses "CREATION TIME"
_CREATE_COLS = ("CreateTime", "create_time", "CreationTime", "CREATION TIME")
_EXIT_COLS = ("ExitTime", "exit_time")
# Linux pslist uses "OFFSET (V)" as the task_struct virtual address
_DTB_COLS = ("DTB", "Dtb", "dtb", "OFFSET (V)")
_PEB_COLS = ("PebBase", "Peb", "peb_base")


def _parse_vol_timestamp(ts: Any) -> datetime | None:
    """Parse a Volatility 3 timestamp value to a UTC datetime.

    Volatility 3 may return:
        - ISO 8601 string: "2024-01-15 10:30:45.000000"
        - Integer (epoch seconds or Windows FILETIME)
        - None / empty string for processes without a timestamp

    Args:
        ts: Raw timestamp value from Volatility row dict.

    Returns:
        UTC datetime, or None if the timestamp is not available.
    """
    if ts is None:
        return None
    if isinstance(ts, str):
        ts_str = ts.strip()
        if not ts_str or ts_str in ("-", "N/A", "0", ""):
            return None
        # Volatility sometimes formats as: "2024-01-15 10:30:45.000000 UTC"
        ts_str = ts_str.replace(" UTC", "").strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_str, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        log.debug("Could not parse timestamp", value=ts_str)
        return None
    if isinstance(ts, (int, float)):
        if ts <= 0:
            return None
        try:
            # If it looks like a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
            # Windows FILETIME values are typically > 1e17
            if ts > 1e14:
                # Convert from Windows FILETIME to Unix epoch
                EPOCH_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01
                unix_ts = ts / 1e7 - EPOCH_DIFF
                return datetime.fromtimestamp(unix_ts, tz=UTC)
            # Otherwise treat as Unix epoch seconds
            return datetime.fromtimestamp(float(ts), tz=UTC)
        except (OSError, OverflowError, ValueError):
            return None
    return None


def _parse_bool(val: Any) -> bool:
    """Parse Volatility boolean-like values."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def _parse_int(val: Any, default: int = 0) -> int:
    """Parse integer from Volatility output (handles None, str, hex strings)."""
    if val is None:
        return default
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if not val or val in ("-", "N/A"):
            return default
        try:
            if val.startswith("0x") or val.startswith("0X"):
                return int(val, 16)
            return int(val)
        except ValueError:
            return default
    return default


class ProcessExtractor:
    """Extracts process artifacts from Volatility 3 plugins and builds a ProcessTree.

    Combines output from:
        1. windows.pslist — primary process list with all metadata
        2. windows.cmdline — command-line arguments (PID → cmdline mapping)

    The pstree plugin is NOT used separately since pslist gives us the PPID
    we need to reconstruct the hierarchy manually (more reliable).

    Args:
        runner: Configured VolatilityRunner for the target dump.
    """

    def __init__(self, runner: VolatilityRunner) -> None:
        self._runner = runner

    def _cmdlines_from_proc(self, pids: list[int]) -> dict[int, str]:
        """Read cmdlines from /proc/PID/cmdline as fallback for linux.psaux.

        Used for live memory analysis when Volatility's linux.psaux crashes
        (e.g. due to RANDSTRUCT hiding mm_struct fields before the ISF is
        rebuilt, or other per-process access errors).
        Kernel threads (PID 2+, no cmdline file or empty) are silently skipped.

        Returns:
            PID → cmdline string for each readable process.
        """
        result: dict[int, str] = {}
        proc_root = Path("/proc")
        if not proc_root.exists():
            return result
        for pid in pids:
            try:
                data = (proc_root / str(pid) / "cmdline").read_bytes()
                if data:
                    cmdline = data.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                    if cmdline:
                        result[pid] = cmdline
            except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
                pass
        if result:
            log.info(
                "Cmdlines read from /proc (linux.psaux fallback — ISF rebuild may fix this)",
                count=len(result),
            )
        return result

    def _exe_paths_from_proc(self, pids: list[int]) -> dict[int, str]:
        """Read executable paths from /proc/PID/exe for Linux live-analysis processes.

        The ``linux.pslist`` plugin only provides the short COMM name (15 chars);
        it does not emit the full executable path. Reading /proc/PID/exe gives the
        real absolute path needed for is_system_path, path_depth and path_entropy
        feature computation.

        This is only called for Linux live/LiME analysis. The current system's
        /proc must correspond to the dump being analyzed (normal for live analysis).

        Returns:
            PID → absolute executable path for each readable process.
        """
        result: dict[int, str] = {}
        proc_root = Path("/proc")
        if not proc_root.exists():
            return result
        for pid in pids:
            try:
                import os as _os

                exe_path = _os.readlink(str(proc_root / str(pid) / "exe"))  # noqa: PTH115
                # readlink on a deleted executable appends " (deleted)" — strip it
                exe_path = exe_path.replace(" (deleted)", "").strip()
                if exe_path:
                    result[pid] = exe_path
            except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
                pass
        log.debug("Executable paths read from /proc", count=len(result))
        return result

    def _build_artifact_from_row(self, row: dict[str, Any]) -> ProcessArtifact | None:
        """Build a ProcessArtifact from a single pslist row dict.

        Args:
            row: A single row from windows.pslist JSON output.

        Returns:
            ProcessArtifact if valid, None if the row is malformed.
        """
        pid_raw = _find_col(row, _PID_COLS)
        ppid_raw = _find_col(row, _PPID_COLS)
        name_raw = _find_col(row, _NAME_COLS)

        if pid_raw is None or name_raw is None:
            log.warning("Skipping malformed process row", row_keys=list(row.keys()))
            return None

        pid = _parse_int(pid_raw)
        ppid = _parse_int(ppid_raw)
        name = str(name_raw).strip().rstrip("\x00") or f"<unknown:{pid}>"

        # Image file name (full path from PEB — often more informative than name)
        image_file_name_raw = _find_col(row, ("ImageFilePath", "Filename", "image_file_name"))
        image_file_name = str(image_file_name_raw).strip() if image_file_name_raw else ""

        create_time = _parse_vol_timestamp(_find_col(row, _CREATE_COLS))
        exit_time = _parse_vol_timestamp(_find_col(row, _EXIT_COLS))

        return ProcessArtifact(
            pid=pid,
            ppid=ppid,
            name=name,
            image_file_name=image_file_name,
            create_time=create_time,
            exit_time=exit_time,
            is_active=exit_time is None,
            threads=_parse_int(_find_col(row, _THREADS_COLS)),
            handles=_parse_int(_find_col(row, _HANDLES_COLS)),
            session_id=_parse_int(_find_col(row, _SESSION_COLS)),
            wow64=_parse_bool(_find_col(row, _WOW64_COLS)),
            peb_base=_parse_int(_find_col(row, _PEB_COLS)),
            dtb=_parse_int(_find_col(row, _DTB_COLS)),
        )

    def _extract_cmdlines(self) -> dict[int, str]:
        """Run the appropriate cmdline plugin and return a PID → cmdline string mapping.

        Returns:
            Dict mapping PID to command line string.
            PIDs with no cmdline (terminated processes) are absent.
        """
        cmdline_map: dict[int, str] = {}
        # Linux: linux.psaux (PID, PPID, COMM, ARGS)
        # Windows: windows.cmdline
        plugin = "linux.psaux" if self._runner.is_linux else "windows.cmdline"
        try:
            rows = self._runner.run_plugin(plugin)
        except Exception as exc:
            log.warning(f"{plugin} failed, proceeding without cmdlines", error=str(exc))
            return cmdline_map

        for row in rows:
            pid_raw = _find_col(row, _PID_COLS)
            # Linux psaux uses "ARGS"; Windows uses "Args" / "Cmdline" / "CommandLine"
            cmdline_raw = _find_col(row, ("ARGS", "Args", "Cmdline", "CommandLine", "cmdline"))
            if pid_raw is not None and cmdline_raw is not None:
                pid = _parse_int(pid_raw)
                cmdline = str(cmdline_raw).strip()
                # Filter out Volatility's "N/A" and empty placeholders
                if cmdline and cmdline not in ("N/A", "-", "???"):
                    cmdline_map[pid] = cmdline

        log.debug("Extracted command lines", count=len(cmdline_map))
        return cmdline_map

    def _build_tree(self, processes: list[ProcessArtifact]) -> ProcessTree:
        """Build a ProcessTree from a flat list of ProcessArtifacts.

        Uses PPID references to establish parent-child relationships.
        Processes whose PPID is not in the process list become roots
        (includes System, smss.exe, and DKOM-orphaned processes).

        Args:
            processes: All ProcessArtifacts from pslist.

        Returns:
            ProcessTree with roots, flat_map, and full hierarchy.
        """
        flat_map = {p.pid: p for p in processes}
        pid_set = set(flat_map.keys())

        # Create a node for each process
        nodes: dict[int, ProcessNode] = {}
        for pid, artifact in flat_map.items():
            nodes[pid] = ProcessNode(artifact=artifact, children=[], depth=0)

        # Build children lists
        children_map: dict[int, list[int]] = {pid: [] for pid in pid_set}
        roots: list[int] = []

        for pid, artifact in flat_map.items():
            ppid = artifact.ppid
            if ppid == 0 or ppid == pid or ppid not in pid_set:
                # This is a root: System (PPID=0), self-referencing, or orphan
                roots.append(pid)
            else:
                children_map[ppid].append(pid)

        # Populate ProcessNode.children
        for ppid, child_pids in children_map.items():
            if ppid in nodes:
                nodes[ppid].children = [nodes[c] for c in child_pids if c in nodes]

        # Assign depths using BFS from roots
        from collections import deque

        queue: deque[tuple[int, int]] = deque((pid, 0) for pid in roots)
        while queue:
            pid, depth = queue.popleft()
            if pid in nodes:
                # Rebuild node with correct depth (Pydantic models are immutable by default)
                old_node = nodes[pid]
                nodes[pid] = ProcessNode(
                    artifact=old_node.artifact,
                    children=old_node.children,
                    depth=depth,
                )
                for child in nodes[pid].children:
                    queue.append((child.artifact.pid, depth + 1))

        return ProcessTree(
            roots=[nodes[pid] for pid in roots if pid in nodes],
            flat_map=flat_map,
        )

    def extract(self) -> ProcessTree:
        """Extract all process artifacts from the memory dump.

        Runs windows.pslist and windows.cmdline, combines results, and
        returns a fully constructed ProcessTree.

        Returns:
            ProcessTree containing all processes and their hierarchy.

        Raises:
            ExtractionError: If pslist returns no processes (unrecoverable).
        """
        from forensiq.utils.exceptions import MissingPluginOutputError

        plugin = "linux.pslist" if self._runner.is_linux else "windows.pslist"
        log.info("Extracting process list", plugin=plugin)
        rows = self._runner.run_plugin(plugin)

        if not rows:
            raise MissingPluginOutputError(
                plugin=plugin,
                dump_path=str(self._runner.dump_path),
            )

        # Build ProcessArtifacts from pslist rows
        processes: list[ProcessArtifact] = []
        for row in rows:
            artifact = self._build_artifact_from_row(row)
            if artifact is not None:
                processes.append(artifact)

        log.info("Processes extracted from pslist", count=len(processes))

        # Enrich with command lines
        cmdline_map = self._extract_cmdlines()
        enriched: list[ProcessArtifact] = []
        for proc in processes:
            if proc.pid in cmdline_map:
                # Rebuild with cmdline set (Pydantic model copy with override)
                enriched.append(proc.model_copy(update={"cmdline": cmdline_map[proc.pid]}))
            else:
                enriched.append(proc)

        # For Linux: enrich image_file_name from /proc/PID/exe.
        # linux.pslist only provides the 15-char COMM field; the full executable
        # path is needed for is_system_path, path_depth, and path_entropy features.
        if self._runner.is_linux:
            exe_paths = self._exe_paths_from_proc([p.pid for p in enriched])
            if exe_paths:
                enriched = [
                    proc.model_copy(update={"image_file_name": exe_paths[proc.pid]})
                    if proc.pid in exe_paths and not proc.image_file_name
                    else proc
                    for proc in enriched
                ]
                log.info("Enriched exe paths from /proc", count=len(exe_paths))

        tree = self._build_tree(enriched)
        log.info(
            "Process tree built",
            total=len(tree.flat_map),
            roots=len(tree.roots),
        )
        return tree

    async def extract_async(self) -> ProcessTree:
        """Async variant: runs windows.pslist and windows.cmdline concurrently.

        Both plugins are independent reads on the same dump file so they can
        safely run in parallel via asyncio.create_subprocess_exec.

        Returns:
            ProcessTree with all processes enriched with command lines.

        Raises:
            MissingPluginOutputError: If pslist returns no processes.
        """
        import asyncio

        from forensiq.utils.exceptions import MissingPluginOutputError

        pslist_plugin = "linux.pslist" if self._runner.is_linux else "windows.pslist"
        cmdline_plugin = "linux.psaux" if self._runner.is_linux else "windows.cmdline"
        log.info(
            "Extracting process list (async — pslist + cmdline parallel)",
            pslist=pslist_plugin,
            cmdline=cmdline_plugin,
        )

        # Run both plugins concurrently — no shared state, safe
        try:
            pslist_rows, cmdline_rows = await asyncio.gather(
                self._runner.run_plugin_async(pslist_plugin),
                self._runner.run_plugin_async(cmdline_plugin),
                return_exceptions=False,
            )
        except Exception as exc:
            # If pslist fails, we cannot continue
            raise MissingPluginOutputError(
                plugin=pslist_plugin,
                dump_path=str(self._runner.dump_path),
            ) from exc

        if not pslist_rows:
            raise MissingPluginOutputError(
                plugin=pslist_plugin,
                dump_path=str(self._runner.dump_path),
            )

        # Parse pslist rows into ProcessArtifacts (sync — CPU only, no blocking I/O)
        processes: list[ProcessArtifact] = []
        for row in pslist_rows:
            artifact = self._build_artifact_from_row(row)
            if artifact is not None:
                processes.append(artifact)

        log.info("Processes extracted from pslist (async)", count=len(processes))

        # Build cmdline map from async rows
        cmdline_map: dict[int, str] = {}
        for row in cmdline_rows if isinstance(cmdline_rows, list) else []:
            pid_raw = _find_col(row, _PID_COLS)
            # Linux psaux uses "ARGS"; Windows uses "Args" / "Cmdline" / "CommandLine"
            cmdline_raw = _find_col(row, ("ARGS", "Args", "Cmdline", "CommandLine", "cmdline"))
            if pid_raw is not None and cmdline_raw is not None:
                pid = _parse_int(pid_raw)
                cmdline = str(cmdline_raw).strip()
                if cmdline and cmdline not in ("N/A", "-", "???"):
                    cmdline_map[pid] = cmdline

        log.debug("Command lines extracted (async)", count=len(cmdline_map))

        # If psaux returned nothing and we're on a live Linux system, fall back
        # to reading /proc/PID/cmdline directly.  This works for live analysis;
        # historical dumps cannot use this path.
        if not cmdline_map and self._runner.is_linux:
            pids = [p.pid for p in processes]
            cmdline_map = self._cmdlines_from_proc(pids)

        # Enrich processes with cmdlines and build tree
        enriched: list[ProcessArtifact] = []
        for proc in processes:
            if proc.pid in cmdline_map:
                enriched.append(proc.model_copy(update={"cmdline": cmdline_map[proc.pid]}))
            else:
                enriched.append(proc)

        # For Linux: enrich image_file_name from /proc/PID/exe (same as sync path).
        if self._runner.is_linux:
            exe_paths = self._exe_paths_from_proc([p.pid for p in enriched])
            if exe_paths:
                enriched = [
                    proc.model_copy(update={"image_file_name": exe_paths[proc.pid]})
                    if proc.pid in exe_paths and not proc.image_file_name
                    else proc
                    for proc in enriched
                ]
                log.info("Enriched exe paths from /proc (async)", count=len(exe_paths))

        tree = self._build_tree(enriched)
        log.info("Process tree built (async)", total=len(tree.flat_map), roots=len(tree.roots))
        return tree
