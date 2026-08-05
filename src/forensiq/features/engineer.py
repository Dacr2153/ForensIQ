# FILE: src/forensiq/features/engineer.py
"""Feature engineering: computes per-process feature vectors from extracted artifacts.

Takes ExtractionResult (raw Volatility 3 data) and produces a list of
ProcessFeatureVector objects ready for the XGBoost classifier.

The 20 features computed here correspond exactly to ProcessFeatureVector.FEATURE_NAMES.
Any modification to feature computation must be accompanied by model retraining.

Usage:
    from forensiq.features.engineer import FeatureEngineer
    from forensiq.extraction.orchestrator import ExtractionResult

    engineer = FeatureEngineer()
    vectors = engineer.compute(extraction_result)
    # vectors: list[ProcessFeatureVector], one per analyzed process
"""

from __future__ import annotations

import math
from pathlib import Path

from forensiq.config.settings import get_settings
from forensiq.extraction.orchestrator import ExtractionResult
from forensiq.features.entropy import (
    compute_name_entropy,
    compute_path_depth,
    compute_path_entropy,
)
from forensiq.features.heuristics import (
    has_encoded_cmdline,
    is_system_path,
    parent_child_legit,
)
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.process import ProcessArtifact
from forensiq.utils.exceptions import FeatureEngineeringError
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# ─── Expected parent-child process relationships (Windows) ────────────────────
# Maps child process name (lowercase) → set of allowed parent names (lowercase).
# Constructed once at module load to avoid repeated allocation per process.
_EXPECTED_PARENTS: dict[str, set[str]] = {
    "smss.exe": {"system"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe"},
    "taskhost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe", "winlogon.exe"},
    "userinit.exe": {"winlogon.exe"},
}


class FeatureEngineer:
    """Computes ProcessFeatureVector for each process in an ExtractionResult.

    Each process is evaluated independently using:
        - Its own process metadata (name, path, cmdline)
        - Its parent's metadata (for parent-child heuristic)
        - Its network connections (from netscan)
        - Its loaded DLLs (from dlllist)
        - Its VAD entries (from vadinfo)
        - Its malfind hits (from malfind)
    """

    def __init__(self) -> None:
        self._settings = get_settings()

    def _compute_for_process(
        self,
        process: ProcessArtifact,
        extraction: ExtractionResult,
    ) -> ProcessFeatureVector | None:
        """Compute a feature vector for a single process.

        Args:
            process: The ProcessArtifact to compute features for.
            extraction: Full ExtractionResult for cross-referencing.

        Returns:
            ProcessFeatureVector or None if computation fails critically.
        """
        pid = process.pid
        name = process.name

        try:
            # ─── Feature 1: Process name entropy ───────────────────────────
            f_name_entropy = compute_name_entropy(name)

            # ─── Feature 2: Path entropy ────────────────────────────────────
            f_path_entropy = compute_path_entropy(process.image_file_name)

            # ─── Feature 3: Path depth ──────────────────────────────────────
            f_path_depth = compute_path_depth(process.image_file_name)

            # ─── Feature 4: Is system path ──────────────────────────────────
            f_is_system = is_system_path(process.image_file_name)

            # ─── Feature 5: Parent-child legitimacy ─────────────────────────
            parent_artifact = None
            if extraction.process_tree is not None:
                parent_artifact = extraction.process_tree.flat_map.get(process.ppid)
            parent_name = parent_artifact.name if parent_artifact else ""
            f_parent_child = parent_child_legit(parent_name, name)

            # ─── Features 6 & 7: DLL counts ─────────────────────────────────
            process_dlls = extraction.dlls.get(pid, [])
            f_dll_count = len(process_dlls)
            f_suspicious_dlls = sum(1 for d in process_dlls if d.is_suspicious)

            # ─── Features 8, 9, 10: Network connections ───────────────────
            process_connections = extraction.connections.get(pid, [])
            f_has_network = len(process_connections) > 0
            f_conn_count = len(process_connections)
            f_ext_count = sum(1 for c in process_connections if c.is_external)

            # ─── Feature 11: Malfind hits ───────────────────────────────────
            f_malfind_hits = len(extraction.malfind.get(pid, []))

            # ─── Feature 12: VAD RWX count ──────────────────────────────────
            process_vads = extraction.vads.get(pid, [])
            f_vad_rwx = sum(1 for v in process_vads if v.is_rwx)

            # ─── Feature 13: Thread count ────────────────────────────────────
            f_threads = process.threads

            # ─── Feature 14: Handle count ────────────────────────────────────
            f_handles = process.handles

            # ─── Feature 15: Encoded command line ────────────────────────────
            f_encoded_cmdline = has_encoded_cmdline(process.cmdline)

            # ─── Feature 16 (new): VAD execute-write page count ─────────────
            # Count total PAGES across all RWX VAD regions for this process.
            # Each VAD region may span many 4 KB pages; more pages = stronger signal.
            f_vad_rwx_pages = 0
            for v in process_vads:
                if v.is_rwx:
                    region_size = max(0, v.end - v.start)
                    f_vad_rwx_pages += max(1, region_size // 4096)

            # ─── Feature 17 (new): Parent name mismatch ─────────────────────
            # True if PPID resolves to a process name inconsistent with expectations.
            f_parent_mismatch = False
            if extraction.process_tree is not None and parent_artifact is not None:
                lname = name.lower()
                if lname in _EXPECTED_PARENTS:
                    pname = parent_artifact.name.lower()
                    if pname not in _EXPECTED_PARENTS[lname]:
                        f_parent_mismatch = True

            # ─── Feature 18 (new): Thread start address in heap ─────────────
            # Heuristic: if a process has malfind hits, its threads may start
            # in injected private memory. We approximate via malfind start addrs.
            f_thread_in_heap = False
            if f_malfind_hits > 0 and f_threads > 0:
                # If malfind found more regions than threads, some threads likely
                # start in injected memory (ratio heuristic — avoids needing
                # windows.threads plugin which is very slow)
                f_thread_in_heap = f_malfind_hits >= f_threads

            # ─── Feature 19 (new): Import table entropy ──────────────────────
            # Approximated from DLL names: packed processes load few or unusual DLLs.
            # If pefile data is available via the PE header detector, use it;
            # otherwise estimate from the DLL name distribution.
            f_import_entropy = 0.0
            if process_dlls:
                # os.path.basename handles both forward and backslash separators.
                # Replacing \ first makes basename work correctly on Linux paths
                # that happen to contain a backslash (Windows paths in a Linux dump).
                dll_names = [
                    Path(d.full_dll_name.replace("\\", "/")).name.lower()
                    for d in process_dlls
                    if d.full_dll_name
                ]
                if dll_names:
                    total = len(dll_names)
                    freq = {}
                    for n in dll_names:
                        freq[n] = freq.get(n, 0) + 1
                    f_import_entropy = -sum(
                        (c / total) * math.log2(c / total) for c in freq.values() if c > 0
                    )

                # On Linux, DLL count can be very large (hundreds of .so files per
                # KDE/Qt process), pushing log2(unique_names) above 8.
                # Clamp to 8.0 to stay within the model field's [0, 8] bound.
                f_import_entropy = min(f_import_entropy, 8.0)

            # ─── Feature 20 (new): Time delta from parent ────────────────────
            f_time_delta = 0.0
            if (
                parent_artifact is not None
                and process.create_time is not None
                and parent_artifact.create_time is not None
            ):
                delta = abs((process.create_time - parent_artifact.create_time).total_seconds())
                f_time_delta = min(delta, 3600.0)

            return ProcessFeatureVector(
                pid=pid,
                name=name,
                ppid=process.ppid,
                process_name_entropy=f_name_entropy,
                path_entropy=f_path_entropy,
                path_depth=f_path_depth,
                is_system_path=f_is_system,
                parent_child_legit=f_parent_child,
                dll_count=f_dll_count,
                suspicious_dll_count=f_suspicious_dlls,
                has_network_connection=f_has_network,
                network_connection_count=f_conn_count,
                external_connection_count=f_ext_count,
                malfind_hits=f_malfind_hits,
                vad_rwx_count=f_vad_rwx,
                thread_count=f_threads,
                handle_count=f_handles,
                has_encoded_cmdline=f_encoded_cmdline,
                # New v2 features
                vad_execute_write_page_count=f_vad_rwx_pages,
                parent_name_mismatch=f_parent_mismatch,
                thread_start_in_heap=f_thread_in_heap,
                import_table_entropy=round(f_import_entropy, 4),
                time_delta_from_parent_seconds=f_time_delta,
            )

        except Exception as exc:
            log.warning(
                "Feature engineering failed for process",
                pid=pid,
                name=name,
                error=str(exc),
            )
            raise FeatureEngineeringError(
                pid=pid,
                process_name=name,
                reason=str(exc),
            ) from exc

    def compute(self, extraction: ExtractionResult) -> list[ProcessFeatureVector]:
        """Compute feature vectors for all processes in the extraction result.

        Applies MAX_PROCESSES_ANALYZE limit if configured (0 = unlimited).
        Processes are sorted by PID before the limit is applied.

        Args:
            extraction: ExtractionResult from ExtractionOrchestrator.run().

        Returns:
            List of ProcessFeatureVectors, one per successfully analyzed process.
            Processes that fail feature computation are skipped with a warning.
        """
        if extraction.process_tree is None:
            log.warning("No process tree available, returning empty feature list")
            return []

        processes = extraction.process_tree.get_all_processes()

        # Apply process limit
        max_procs = self._settings.MAX_PROCESSES_ANALYZE
        if max_procs > 0 and len(processes) > max_procs:
            log.info(
                "Limiting analysis to top N processes",
                total=len(processes),
                limit=max_procs,
            )
            processes = processes[:max_procs]

        log.info("Computing features for processes", count=len(processes))

        vectors: list[ProcessFeatureVector] = []
        failed = 0

        for process in processes:
            try:
                vector = self._compute_for_process(process, extraction)
                if vector is not None:
                    vectors.append(vector)
            except FeatureEngineeringError:
                failed += 1
                continue

        log.info(
            "Feature engineering complete",
            computed=len(vectors),
            failed=failed,
        )
        return vectors
