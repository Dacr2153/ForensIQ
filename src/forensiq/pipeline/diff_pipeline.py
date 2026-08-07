# FILE: src/forensiq/pipeline/diff_pipeline.py
"""Memory dump diff pipeline.

Compares two memory dumps (before/after) and produces a structured diff
showing:
  - New processes (appeared in 'after' dump)
  - Disappeared processes (present in 'before', gone from 'after')
  - New network connections per PID
  - New DLLs loaded per PID
  - New malfind regions per PID
  - New/removed VAD RWX regions

The diff is produced as a JSON file and optionally as a Rich console table.

Usage:
    from forensiq.pipeline.diff_pipeline import DiffPipeline
    result = asyncio.run(DiffPipeline().run(
        before_path=Path("before.raw"),
        after_path=Path("after.raw"),
        output_dir=Path("reports/"),
    ))
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from forensiq.extraction.orchestrator import ExtractionOrchestrator, ExtractionResult
from forensiq.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ProcessDiff:
    """Differences for a single process across two dumps."""

    pid: int
    name: str
    status: str  # "new", "disappeared", "changed"
    new_connections: list[dict[str, Any]] = field(default_factory=list)
    disappeared_connections: list[dict[str, Any]] = field(default_factory=list)
    new_dlls: list[str] = field(default_factory=list)
    disappeared_dlls: list[str] = field(default_factory=list)
    new_malfind_regions: int = 0
    new_rwx_vads: int = 0


@dataclass
class DiffResult:
    """Full comparison result between two memory dumps."""

    before_path: Path
    after_path: Path
    before_sha256: str
    after_sha256: str
    new_processes: list[ProcessDiff] = field(default_factory=list)
    disappeared_processes: list[ProcessDiff] = field(default_factory=list)
    changed_processes: list[ProcessDiff] = field(default_factory=list)
    analysis_ts: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    output_json: Path | None = None
    error: str = ""
    exit_code: int = 0

    @property
    def total_changes(self) -> int:
        return (
            len(self.new_processes) + len(self.disappeared_processes) + len(self.changed_processes)
        )

    def to_dict(self) -> dict[str, Any]:
        def _pdiff(pd: ProcessDiff) -> dict[str, Any]:
            return {
                "pid": pd.pid,
                "name": pd.name,
                "status": pd.status,
                "new_connections": pd.new_connections,
                "disappeared_connections": pd.disappeared_connections,
                "new_dlls": pd.new_dlls,
                "disappeared_dlls": pd.disappeared_dlls,
                "new_malfind_regions": pd.new_malfind_regions,
                "new_rwx_vads": pd.new_rwx_vads,
            }

        return {
            "before_path": str(self.before_path),
            "after_path": str(self.after_path),
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "analysis_ts": self.analysis_ts,
            "summary": {
                "new_processes": len(self.new_processes),
                "disappeared_processes": len(self.disappeared_processes),
                "changed_processes": len(self.changed_processes),
                "total_changes": self.total_changes,
            },
            "new_processes": [_pdiff(p) for p in self.new_processes],
            "disappeared_processes": [_pdiff(p) for p in self.disappeared_processes],
            "changed_processes": [_pdiff(p) for p in self.changed_processes],
        }


class DiffPipeline:
    """Pipeline that compares two memory dumps and produces a structured diff."""

    async def run(
        self,
        before_path: Path,
        after_path: Path,
        output_dir: Path,
    ) -> DiffResult:
        """Run the diff pipeline on two dump files.

        Both dumps are extracted concurrently using asyncio.gather.

        Args:
            before_path: Path to the 'before' dump file.
            after_path:  Path to the 'after' dump file.
            output_dir:  Directory to write the JSON diff report.

        Returns:
            DiffResult with all detected changes.
        """
        log.info("Starting diff pipeline", before=str(before_path), after=str(after_path))

        # ── Validate inputs ────────────────────────────────────────────────────
        for p, label in [(before_path, "before"), (after_path, "after")]:
            if not p.exists():
                return DiffResult(
                    before_path=before_path,
                    after_path=after_path,
                    before_sha256="",
                    after_sha256="",
                    error=f"Dump file not found: {p} ({label})",
                    exit_code=2,
                )

        # ── Extract both dumps concurrently ────────────────────────────────────
        before_orch = ExtractionOrchestrator(dump_path=before_path, show_progress=False)
        after_orch = ExtractionOrchestrator(dump_path=after_path, show_progress=False)

        log.info("Extracting both dumps concurrently...")
        before_result, after_result = await asyncio.gather(
            before_orch.run_async(),
            after_orch.run_async(),
            return_exceptions=True,
        )

        # A failed extraction must surface in the DiffResult, not crash the run.
        for label, res in (("before", before_result), ("after", after_result)):
            if isinstance(res, BaseException):
                log.warning("Diff extraction failed", label=label, error=str(res))
                return DiffResult(
                    before_path=before_path,
                    after_path=after_path,
                    error=f"Extraction failed ({label}): {res}",
                    exit_code=2,
                )
            if res is None:
                return DiffResult(
                    before_path=before_path,
                    after_path=after_path,
                    error=f"Extraction produced no result ({label})",
                    exit_code=2,
                )

        # ── Build diff ────────────────────────────────────────────────────────
        result = DiffResult(
            before_path=before_path,
            after_path=after_path,
            before_sha256=before_result.dump_sha256,
            after_sha256=after_result.dump_sha256,
        )

        result.new_processes = self._find_new_processes(before_result, after_result)
        result.disappeared_processes = self._find_disappeared_processes(before_result, after_result)
        result.changed_processes = self._find_changed_processes(before_result, after_result)

        # ── Write JSON output ─────────────────────────────────────────────────
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
        json_path = output_dir / f"forensiq_diff_{ts}.json"
        json_path.write_text(json.dumps(result.to_dict(), indent=2))
        result.output_json = json_path

        log.info(
            "Diff complete",
            new=len(result.new_processes),
            disappeared=len(result.disappeared_processes),
            changed=len(result.changed_processes),
            output=str(json_path),
        )
        return result

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _find_new_processes(
        self, before: ExtractionResult, after: ExtractionResult
    ) -> list[ProcessDiff]:
        """Processes present in 'after' but not in 'before'."""
        before_pids = set(before.process_tree.flat_map.keys()) if before.process_tree else set()
        after_pids = set(after.process_tree.flat_map.keys()) if after.process_tree else set()
        new_pids = after_pids - before_pids

        diffs = []
        for pid in sorted(new_pids):
            proc = after.process_tree.flat_map[pid]  # type: ignore[union-attr]
            diffs.append(
                ProcessDiff(
                    pid=pid,
                    name=proc.name,
                    status="new",
                    new_connections=[self._conn_to_dict(c) for c in after.connections.get(pid, [])],
                    new_dlls=[d.full_dll_name for d in after.dlls.get(pid, [])],
                    new_malfind_regions=len(after.malfind.get(pid, [])),
                    new_rwx_vads=sum(1 for v in after.vads.get(pid, []) if v.is_rwx),
                )
            )
        return diffs

    def _find_disappeared_processes(
        self, before: ExtractionResult, after: ExtractionResult
    ) -> list[ProcessDiff]:
        """Processes present in 'before' but absent in 'after'."""
        before_pids = set(before.process_tree.flat_map.keys()) if before.process_tree else set()
        after_pids = set(after.process_tree.flat_map.keys()) if after.process_tree else set()
        gone_pids = before_pids - after_pids

        diffs = []
        for pid in sorted(gone_pids):
            proc = before.process_tree.flat_map[pid]  # type: ignore[union-attr]
            diffs.append(ProcessDiff(pid=pid, name=proc.name, status="disappeared"))
        return diffs

    def _find_changed_processes(
        self, before: ExtractionResult, after: ExtractionResult
    ) -> list[ProcessDiff]:
        """Processes present in BOTH dumps with notable changes."""
        before_pids = set(before.process_tree.flat_map.keys()) if before.process_tree else set()
        after_pids = set(after.process_tree.flat_map.keys()) if after.process_tree else set()
        common_pids = before_pids & after_pids

        diffs = []
        for pid in sorted(common_pids):
            proc_name = after.process_tree.flat_map[pid].name  # type: ignore[union-attr]

            # Network connections diff
            before_conns = {self._conn_key(c) for c in before.connections.get(pid, [])}
            after_conns_list = after.connections.get(pid, [])
            after_conns = {self._conn_key(c) for c in after_conns_list}
            new_conns = [
                self._conn_to_dict(c)
                for c in after_conns_list
                if self._conn_key(c) not in before_conns
            ]
            disappeared_conns = [{"key": k} for k in (before_conns - after_conns)]

            # DLLs diff
            before_dlls = {d.full_dll_name.lower() for d in before.dlls.get(pid, [])}
            after_dlls_list = after.dlls.get(pid, [])
            after_dlls = {d.full_dll_name.lower() for d in after_dlls_list}
            new_dlls = [
                d.full_dll_name
                for d in after_dlls_list
                if d.full_dll_name.lower() not in before_dlls
            ]
            gone_dlls = list(before_dlls - after_dlls)

            # Malfind: new injected regions
            before_malfind = len(before.malfind.get(pid, []))
            after_malfind = len(after.malfind.get(pid, []))
            new_malfind = max(0, after_malfind - before_malfind)

            # VAD RWX count change
            before_rwx = sum(1 for v in before.vads.get(pid, []) if v.is_rwx)
            after_rwx = sum(1 for v in after.vads.get(pid, []) if v.is_rwx)
            new_rwx = max(0, after_rwx - before_rwx)

            # Only emit if there are actual changes
            if new_conns or disappeared_conns or new_dlls or gone_dlls or new_malfind or new_rwx:
                diffs.append(
                    ProcessDiff(
                        pid=pid,
                        name=proc_name,
                        status="changed",
                        new_connections=new_conns,
                        disappeared_connections=disappeared_conns,
                        new_dlls=new_dlls,
                        disappeared_dlls=gone_dlls,
                        new_malfind_regions=new_malfind,
                        new_rwx_vads=new_rwx,
                    )
                )
        return diffs

    @staticmethod
    def _conn_key(conn: Any) -> str:
        return (
            f"{conn.proto}:{conn.local_addr}:{conn.local_port}"
            f"-{conn.remote_addr}:{conn.remote_port}"
        )

    @staticmethod
    def _conn_to_dict(conn: Any) -> dict[str, Any]:
        return {
            "proto": conn.proto,
            "local": f"{conn.local_addr}:{conn.local_port}",
            "remote": f"{conn.remote_addr}:{conn.remote_port}",
            "state": str(conn.state),
        }
