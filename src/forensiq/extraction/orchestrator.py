# FILE: src/forensiq/extraction/orchestrator.py
"""Extraction orchestrator: runs all Volatility 3 plugins sequentially.

Volatility 3 is NOT thread-safe when running multiple plugins against
the same dump file simultaneously. All plugins must be run sequentially.

The orchestrator:
    1. Validates the dump file exists and is readable
    2. Runs all plugins with Rich progress bar
    3. Continues past plugin failures (fault-tolerant)
    4. Returns a combined ExtractionResult with all artifacts

Usage:
    from forensiq.extraction.orchestrator import ExtractionOrchestrator
    from pathlib import Path

    orchestrator = ExtractionOrchestrator(dump_path=Path("/dumps/memory.raw"))
    result = orchestrator.run()
    # result.process_tree → ProcessTree
    # result.connections  → dict[int, list[NetworkConnection]]
    # result.dlls         → dict[int, list[DLLEntry]]
    # result.vads         → dict[int, list[VADEntry]]
    # result.malfind      → dict[int, list[MalfindRegion]]
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.config.settings import get_settings
from forensiq.extraction.dll_extractor import DLLExtractor
from forensiq.extraction.network_extractor import NetworkExtractor
from forensiq.extraction.process_extractor import ProcessExtractor
from forensiq.extraction.vad_extractor import VADExtractor
from forensiq.utils.exceptions import AcquisitionError
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.models.artifact import DLLEntry, MalfindRegion, VADEntry
    from forensiq.models.network import NetworkConnection
    from forensiq.models.process import ProcessTree

log = get_logger(__name__)
_console = Console(stderr=True)


@dataclass
class ExtractionResult:
    """All forensic artifacts extracted from a single memory dump.

    All fields default to empty/None so callers can check which plugins
    succeeded and which failed (fault-tolerant mode).
    """

    dump_path: Path
    dump_sha256: str = ""
    dump_size_bytes: int = 0
    is_linux: bool = False
    process_tree: ProcessTree | None = None
    connections: dict[int, list[NetworkConnection]] = field(default_factory=dict)
    dlls: dict[int, list[DLLEntry]] = field(default_factory=dict)
    vads: dict[int, list[VADEntry]] = field(default_factory=dict)
    malfind: dict[int, list[MalfindRegion]] = field(default_factory=dict)
    volatility_version: str = ""
    failed_plugins: list[str] = field(default_factory=list)

    @property
    def total_processes(self) -> int:
        """Total number of processes found in the dump."""
        if self.process_tree is None:
            return 0
        return len(self.process_tree.flat_map)

    @property
    def is_usable(self) -> bool:
        """True if at minimum the process list was extracted successfully."""
        return self.process_tree is not None and self.total_processes > 0


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file.

    Uses chunked reading for large memory dump files (typically 1-64 GB).

    Args:
        path: Path to the file to hash.

    Returns:
        Lowercase hex SHA-256 digest string.
    """
    sha256 = hashlib.sha256()
    chunk_size = 64 * 1024 * 1024  # 64 MB chunks
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()


class ExtractionOrchestrator:
    """Runs all Volatility 3 extraction plugins against a memory dump.

    Design:
        - run()          : Sequential execution (safe, original behavior)
        - run_parallel() : Parallel execution via ThreadPoolExecutor
                           pslist runs first (required), then netscan/dlllist/malfind
                           run in parallel, then vadinfo runs selectively for
                           only suspicious PIDs (those with malfind hits).
        - Fault-tolerant: individual plugin failures are logged but don't abort
        - Rich progress bar for interactive use
        - Returns ExtractionResult with all artifacts and failure metadata

    Args:
        dump_path: Path to the Windows memory dump file to analyze.
        compute_hash: Whether to compute SHA-256 of the dump (slow for large files).
        show_progress: Whether to show Rich progress bar (disable for tests/CI).
        parallel: Whether to use parallel execution (default: True).
        max_vad_pids: Max PIDs for selective VAD (0 = all PIDs with malfind hits).
    """

    def __init__(
        self,
        dump_path: Path,
        compute_hash: bool = True,
        show_progress: bool = True,
        parallel: bool = True,
        max_vad_pids: int = 0,
        is_linux: bool | None = None,
    ) -> None:
        self.dump_path = dump_path.resolve()
        self.compute_hash = compute_hash
        self.show_progress = show_progress
        self.parallel = parallel
        self.max_vad_pids = max_vad_pids
        self._settings = get_settings()
        # Auto-detect Linux from file extension if not explicitly set.
        #   .lime  → LiME (Linux Memory Extractor)
        #   .kcore → /proc/kcore ELF core dump
        #   /proc/kcore directly → live Linux kernel memory
        if is_linux is None:
            _linux_suffixes = {".lime", ".kcore"}
            self.is_linux = (
                self.dump_path.suffix.lower() in _linux_suffixes
                or self.dump_path == Path("/proc/kcore")
            )
        else:
            self.is_linux = is_linux

    def _validate_dump(self) -> None:
        """Validate the dump file exists and is readable.

        Raises:
            AcquisitionError: If the file does not exist or is not readable.
        """
        if not self.dump_path.exists():
            raise AcquisitionError(
                message=f"Memory dump file not found: {self.dump_path}",
                context={"dump_path": str(self.dump_path)},
            )
        if not self.dump_path.is_file():
            raise AcquisitionError(
                message=f"Path is not a file: {self.dump_path}",
                context={"dump_path": str(self.dump_path)},
            )
        if self.dump_path.stat().st_size == 0:
            raise AcquisitionError(
                message=f"Memory dump file is empty: {self.dump_path}",
                context={"dump_path": str(self.dump_path)},
            )

    def run(self) -> ExtractionResult:
        """Run all extraction plugins and return a combined result.

        Delegates to run_parallel() if self.parallel=True (default),
        otherwise runs sequentially (original behavior).

        Returns:
            ExtractionResult with all available artifacts.

        Raises:
            AcquisitionError: If the dump file is invalid or unreadable.
        """
        if self.parallel:
            return self.run_parallel()
        return self._run_sequential()

    async def run_async(self) -> ExtractionResult:
        """Run all extraction plugins using asyncio.gather for true concurrency.

        Replaces the ThreadPoolExecutor approach with native asyncio subprocess
        management. Each Volatility plugin is an independent OS subprocess —
        running them with asyncio.gather is safe and eliminates GIL overhead.

        Execution plan:
            Stage 1 (concurrent): SHA-256 hash (executor) + pslist + cmdline
            Stage 2 (concurrent): netscan + dlllist + malfind
            Stage 3 (conditional): vadinfo for suspicious PIDs only

        Returns:
            ExtractionResult with all available artifacts.

        Raises:
            AcquisitionError: If dump is invalid or pslist returns nothing.
        """
        import asyncio

        self._validate_dump()
        dump_size = self.dump_path.stat().st_size
        log.info(
            "Starting async extraction",
            dump=self.dump_path.name,
            size_mb=round(dump_size / (1024 * 1024), 1),
        )

        result = ExtractionResult(
            dump_path=self.dump_path,
            dump_size_bytes=dump_size,
            is_linux=self.is_linux,
        )

        runner = VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
        result.volatility_version = runner.get_volatility_version()

        # ── Stage 1: SHA-256 (thread pool) + pslist+cmdline (asyncio) ────────
        if self.show_progress:
            _console.print("[cyan]Stage 1/3:[/cyan] Hash + process list (async, parallel)...")

        loop = asyncio.get_event_loop()
        process_extractor = ProcessExtractor(runner)

        if self.compute_hash:
            hash_task = loop.run_in_executor(None, _compute_sha256, self.dump_path)
            processes_task = process_extractor.extract_async()
            try:
                sha256, process_tree = await asyncio.gather(hash_task, processes_task)
                result.dump_sha256 = sha256
                result.process_tree = process_tree
                # Wire SHA-256 into runner so Stage 2/3 plugins can use the cache
                runner.dump_sha256 = sha256
            except Exception as exc:
                log.error("Stage 1 (async) failed", error=str(exc))
                raise AcquisitionError(
                    message=f"Process extraction failed (async): {exc}",
                    context={"dump_path": str(self.dump_path)},
                ) from exc
        else:
            try:
                result.process_tree = await process_extractor.extract_async()
            except Exception as exc:
                log.error("Stage 1 (async) process extraction failed", error=str(exc))
                raise AcquisitionError(
                    message=f"Process extraction failed (async): {exc}",
                    context={"dump_path": str(self.dump_path)},
                ) from exc

        if result.process_tree is None or result.total_processes == 0:
            raise AcquisitionError(
                message=f"No processes found in dump: {self.dump_path.name}",
                context={"dump_path": str(self.dump_path)},
            )

        # ── Stage 2: netscan + dlllist + malfind (fully concurrent) ──────────
        if self.show_progress:
            _console.print("[cyan]Stage 2/3:[/cyan] Network + DLLs + malfind (async, parallel)...")

        net_extractor = NetworkExtractor(runner)
        dll_extractor = DLLExtractor(runner)
        vad_extractor = VADExtractor(runner)

        try:
            connections, dlls, malfind = await asyncio.gather(
                net_extractor.extract_async(),
                dll_extractor.extract_async(),
                vad_extractor.extract_malfind_async(),
                return_exceptions=True,
            )
        except Exception as exc:
            log.warning("Stage 2 partially failed", error=str(exc))
            connections, dlls, malfind = {}, {}, {}

        # Handle return_exceptions=True results gracefully
        result.connections = connections if isinstance(connections, dict) else {}
        result.dlls = dlls if isinstance(dlls, dict) else {}
        result.malfind = malfind if isinstance(malfind, dict) else {}

        if isinstance(connections, Exception):
            log.warning("netscan async failed", error=str(connections))
            result.failed_plugins.append("netscan")
        if isinstance(dlls, Exception):
            log.warning("dlllist async failed", error=str(dlls))
            result.failed_plugins.append("dlllist")
        if isinstance(malfind, Exception):
            log.warning("malfind async failed", error=str(malfind))
            result.failed_plugins.append("malfind")

        # ── Stage 3: vadinfo (selective — only suspicious PIDs) ───────────────
        suspicious_pids = self._get_suspicious_pids(result)

        if suspicious_pids:
            if self.show_progress:
                _console.print(
                    f"[cyan]Stage 3/3:[/cyan] VAD analysis for {len(suspicious_pids)} "
                    f"suspicious PID(s) (async, selective)..."
                )
            try:
                result.vads = await vad_extractor.extract_vad_for_pids_async(suspicious_pids)
            except Exception as exc:
                log.warning("Selective VAD async extraction failed", error=str(exc))
                result.failed_plugins.append("vadinfo_selective")
        else:
            log.info("No suspicious PIDs found — skipping VAD extraction (async)")

        self._log_completion(result)
        return result

    def run_parallel(self) -> ExtractionResult:
        """Run extraction plugins in parallel using ThreadPoolExecutor.

        Execution order:
            Stage 1 (parallel): SHA-256 + pslist  [blocking: required first]
            Stage 2 (parallel): netscan + dlllist + malfind  [independent]
            Stage 3 (selective): vadinfo for PIDs with malfind hits only

        Each plugin is a separate subprocess, so parallel execution is safe.
        The dump file is opened read-only by each subprocess independently.

        Returns:
            ExtractionResult with all artifacts.
        """
        self._validate_dump()
        dump_size = self.dump_path.stat().st_size
        log.info(
            "Starting parallel extraction",
            dump=self.dump_path.name,
            size_mb=round(dump_size / (1024 * 1024), 1),
        )

        result = ExtractionResult(
            dump_path=self.dump_path,
            dump_size_bytes=dump_size,
            is_linux=self.is_linux,
        )

        runner = VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
        result.volatility_version = runner.get_volatility_version()

        # ── Stage 1: SHA-256 + processes (required before anything else) ─────
        def _hash() -> None:
            if self.compute_hash:
                result.dump_sha256 = _compute_sha256(self.dump_path)

        def _processes() -> None:
            extractor = ProcessExtractor(
                VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
            )
            result.process_tree = extractor.extract()

        if self.show_progress:
            _console.print("[cyan]Stage 1/3:[/cyan] Computing hash + process list...")

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(_hash): "sha256",
                pool.submit(_processes): "processes",
            }
            for future in as_completed(futures):
                step_name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    log.warning("Stage 1 step failed", step=step_name, error=str(exc))
                    result.failed_plugins.append(step_name)

        if result.process_tree is None:
            raise AcquisitionError(
                message=f"Process extraction failed — cannot continue analysis of {self.dump_path.name}",
                context={"dump_path": str(self.dump_path), "failed": result.failed_plugins},
            )

        # ── Stage 2: netscan + dlllist + malfind (parallel, independent) ─────
        def _network() -> None:
            extractor = NetworkExtractor(
                VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
            )
            result.connections = extractor.extract()

        def _dlls() -> None:
            extractor = DLLExtractor(
                VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
            )
            result.dlls = extractor.extract()

        def _malfind() -> None:
            extractor = VADExtractor(
                VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
            )
            result.malfind = extractor.extract_malfind()

        if self.show_progress:
            _console.print(
                "[cyan]Stage 2/3:[/cyan] Extracting network, DLLs, malfind (parallel)..."
            )

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(_network): "netscan",
                pool.submit(_dlls): "dlllist",
                pool.submit(_malfind): "malfind",
            }
            for future in as_completed(futures):
                step_name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    log.warning("Stage 2 step failed", step=step_name, error=str(exc))
                    result.failed_plugins.append(step_name)

        # ── Stage 3: vadinfo (selective — only suspicious PIDs) ───────────────
        # Only run vadinfo for PIDs that have malfind hits or suspicious DLLs.
        # This is the slowest plugin and produces the most data — being selective
        # reduces runtime by 60-80% on typical dumps.
        suspicious_pids = self._get_suspicious_pids(result)

        if suspicious_pids:
            if self.show_progress:
                _console.print(
                    f"[cyan]Stage 3/3:[/cyan] VAD analysis for {len(suspicious_pids)} "
                    f"suspicious PID(s) (selective)..."
                )
            try:
                extractor = VADExtractor(
                    VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
                )
                # Extract VAD only for suspicious PIDs
                result.vads = extractor.extract_vad_for_pids(suspicious_pids)
            except Exception as exc:
                log.warning("Selective VAD extraction failed", error=str(exc))
                result.failed_plugins.append("vadinfo_selective")
        else:
            log.info("No suspicious PIDs found — skipping VAD extraction")

        self._log_completion(result)
        return result

    def _get_suspicious_pids(self, result: ExtractionResult) -> set[int]:
        """Return PIDs that warrant VAD analysis.

        A PID is suspicious if:
            - It has malfind hits (execute-permission regions)
            - OR it has >0 suspicious DLLs (from DLL extractor)

        Args:
            result: Partial ExtractionResult (stage 2 complete).

        Returns:
            Set of PIDs to run vadinfo against.
        """
        suspicious: set[int] = set()

        # PIDs with malfind hits
        suspicious.update(result.malfind.keys())

        # PIDs with suspicious DLLs (loaded from Temp, AppData, etc.)
        for pid, dlls in result.dlls.items():
            if any(dll.is_suspicious for dll in dlls):
                suspicious.add(pid)

        log.info(
            "Suspicious PID detection",
            malfind_pids=len(result.malfind),
            suspicious_dll_pids=sum(
                1 for pid, dlls in result.dlls.items() if any(dll.is_suspicious for dll in dlls)
            ),
            total_suspicious=len(suspicious),
        )

        # Cap at max_vad_pids if set
        if self.max_vad_pids > 0 and len(suspicious) > self.max_vad_pids:
            # Prioritize malfind PIDs if we need to cap
            prioritized = list(result.malfind.keys())[: self.max_vad_pids]
            return set(prioritized)

        return suspicious

    def _log_completion(self, result: ExtractionResult) -> None:
        """Log extraction summary statistics."""
        if not result.is_usable:
            raise AcquisitionError(
                message=(
                    f"Could not extract any processes from dump: {self.dump_path.name}\n"
                    "Possible causes:\n"
                    "  • Not a Windows memory dump (only Windows is supported)\n"
                    "  • Volatility 3 symbol tables not available for this OS version\n"
                    "  • Corrupted or truncated dump file\n"
                    f"  • Failed plugins: {result.failed_plugins}"
                ),
                context={
                    "dump_path": str(self.dump_path),
                    "failed_plugins": result.failed_plugins,
                },
            )

        log.info(
            "Extraction complete",
            processes=result.total_processes,
            connections=sum(len(v) for v in result.connections.values()),
            dlls=sum(len(v) for v in result.dlls.values()),
            vads=sum(len(v) for v in result.vads.values()),
            malfind_hits=sum(len(v) for v in result.malfind.values()),
            failed_plugins=result.failed_plugins,
        )

    def _run_sequential(self) -> ExtractionResult:
        """Run all extraction steps sequentially (original behavior).

        Plugins are run in this order:
            1. Process list (pslist + cmdline) — required
            2. Network connections (netscan) — optional
            3. DLL list (dlllist) — optional
            4. VAD info (vadinfo) — optional, slowest
            5. Malfind (malfind) — optional

        Returns:
            ExtractionResult with all available artifacts.

        Raises:
            AcquisitionError: If the dump file is invalid or unreadable.
        """
        self._validate_dump()

        dump_size = self.dump_path.stat().st_size
        log.info(
            "Starting sequential extraction",
            dump=self.dump_path.name,
            size_mb=round(dump_size / (1024 * 1024), 1),
        )

        result = ExtractionResult(
            dump_path=self.dump_path,
            dump_size_bytes=dump_size,
            is_linux=self.is_linux,
        )

        runner = VolatilityRunner(dump_path=self.dump_path, is_linux=self.is_linux)
        result.volatility_version = runner.get_volatility_version()

        def run_processes() -> None:
            extractor = ProcessExtractor(runner)
            result.process_tree = extractor.extract()

        def run_network() -> None:
            extractor = NetworkExtractor(runner)
            result.connections = extractor.extract()

        def run_dlls() -> None:
            extractor = DLLExtractor(runner)
            result.dlls = extractor.extract()

        def run_vads() -> None:
            extractor = VADExtractor(runner)
            result.vads = extractor.extract_vad()

        def run_malfind() -> None:
            extractor = VADExtractor(runner)
            result.malfind = extractor.extract_malfind()

        def run_hash() -> None:
            if self.compute_hash:
                log.info("Computing SHA-256 digest", dump=self.dump_path.name)
                result.dump_sha256 = _compute_sha256(self.dump_path)

        steps = [
            ("Computing SHA-256", run_hash),
            ("Extracting processes (pslist + cmdline)", run_processes),
            ("Extracting network connections (netscan)", run_network),
            ("Extracting DLL lists (dlllist)", run_dlls),
            ("Extracting VAD entries (vadinfo)", run_vads),
            ("Extracting malfind regions (malfind)", run_malfind),
        ]

        if self.show_progress:
            self._run_with_progress(steps, result)
        else:
            self._run_without_progress(steps, result)

        self._log_completion(result)
        return result

    def _run_with_progress(
        self,
        steps: list[tuple[str, object]],
        result: ExtractionResult,
    ) -> None:
        """Run all extraction steps with a Rich progress bar."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=_console,
            transient=False,
        ) as progress:
            task = progress.add_task("Extracting...", total=len(steps))
            for step_name, step_fn in steps:
                progress.update(task, description=f"[cyan]{step_name}[/cyan]")
                try:
                    step_fn()  # type: ignore[operator]
                except Exception as exc:
                    log.warning("Extraction step failed", step=step_name, error=str(exc))
                    result.failed_plugins.append(step_name)
                finally:
                    progress.advance(task)

    def _run_without_progress(
        self,
        steps: list[tuple[str, object]],
        result: ExtractionResult,
    ) -> None:
        """Run all extraction steps without progress bar (for tests/CI)."""
        for step_name, step_fn in steps:
            log.info("Running extraction step", step=step_name)
            try:
                step_fn()  # type: ignore[operator]
            except Exception as exc:
                log.warning("Extraction step failed", step=step_name, error=str(exc))
                result.failed_plugins.append(step_name)
