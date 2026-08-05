# FILE: tests/unit/test_diff_pipeline.py
"""Unit tests for DiffResult, ProcessDiff and DiffPipeline.run error paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from forensiq.pipeline.diff_pipeline import DiffPipeline, DiffResult, ProcessDiff

# ── ProcessDiff dataclass ─────────────────────────────────────────────────────


class TestProcessDiff:
    def test_defaults(self):
        pd = ProcessDiff(pid=1234, name="svchost.exe", status="new")
        assert pd.new_connections == []
        assert pd.disappeared_connections == []
        assert pd.new_dlls == []
        assert pd.disappeared_dlls == []
        assert pd.new_malfind_regions == 0
        assert pd.new_rwx_vads == 0

    def test_set_fields(self):
        pd = ProcessDiff(
            pid=999,
            name="evil.exe",
            status="changed",
            new_connections=[{"src": "1.2.3.4"}],
            new_dlls=["inject.dll"],
            new_malfind_regions=3,
            new_rwx_vads=1,
        )
        assert pd.new_connections == [{"src": "1.2.3.4"}]
        assert pd.new_dlls == ["inject.dll"]
        assert pd.new_malfind_regions == 3
        assert pd.new_rwx_vads == 1


# ── DiffResult dataclass ──────────────────────────────────────────────────────


class TestDiffResult:
    def _make(self, **kwargs) -> DiffResult:
        defaults = {
            "before_path": Path("a.raw"),
            "after_path": Path("b.raw"),
            "before_sha256": "aaa",
            "after_sha256": "bbb",
        }
        defaults.update(kwargs)
        return DiffResult(**defaults)

    def test_total_changes_zero(self):
        r = self._make()
        assert r.total_changes == 0

    def test_total_changes_counts_all(self):
        pd = ProcessDiff(pid=1, name="x", status="new")
        r = self._make(
            new_processes=[pd, pd],
            disappeared_processes=[pd],
            changed_processes=[pd, pd, pd],
        )
        assert r.total_changes == 6

    def test_to_dict_structure(self):
        r = self._make()
        d = r.to_dict()
        assert "before_path" in d
        assert "after_path" in d
        assert "summary" in d
        assert d["summary"]["total_changes"] == 0
        assert d["new_processes"] == []
        assert d["disappeared_processes"] == []
        assert d["changed_processes"] == []

    def test_to_dict_with_processes(self):
        pd = ProcessDiff(
            pid=4321,
            name="malware.exe",
            status="new",
            new_dlls=["bad.dll"],
        )
        r = self._make(new_processes=[pd])
        d = r.to_dict()
        assert d["summary"]["new_processes"] == 1
        assert d["new_processes"][0]["pid"] == 4321
        assert d["new_processes"][0]["new_dlls"] == ["bad.dll"]

    def test_exit_code_default_zero(self):
        r = self._make()
        assert r.exit_code == 0

    def test_error_default_empty(self):
        r = self._make()
        assert r.error == ""

    def test_output_json_default_none(self):
        r = self._make()
        assert r.output_json is None

    def test_analysis_ts_is_string(self):
        r = self._make()
        assert isinstance(r.analysis_ts, str)
        assert "T" in r.analysis_ts  # ISO format contains T


# ── DiffPipeline.run — file-not-found paths ───────────────────────────────────


class TestDiffPipelineRun:
    @pytest.mark.asyncio
    async def test_before_not_found_returns_error(self, tmp_path: Path):
        pipeline = DiffPipeline()
        after = tmp_path / "after.raw"
        after.write_bytes(b"\x00" * 10)

        result = await pipeline.run(
            before_path=tmp_path / "nonexistent.raw",
            after_path=after,
            output_dir=tmp_path,
        )
        assert result.exit_code == 2
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_after_not_found_returns_error(self, tmp_path: Path):
        pipeline = DiffPipeline()
        before = tmp_path / "before.raw"
        before.write_bytes(b"\x00" * 10)

        result = await pipeline.run(
            before_path=before,
            after_path=tmp_path / "nonexistent.raw",
            output_dir=tmp_path,
        )
        assert result.exit_code == 2
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_both_not_found_returns_error(self, tmp_path: Path):
        pipeline = DiffPipeline()

        result = await pipeline.run(
            before_path=tmp_path / "a.raw",
            after_path=tmp_path / "b.raw",
            output_dir=tmp_path,
        )
        assert result.exit_code == 2
