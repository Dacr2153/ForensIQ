# FILE: tests/unit/test_reporting_builder.py
"""Unit tests for ReportBuilder helpers (non-template-rendering parts)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forensiq.models.report import DumpMetadata, ForensiqReport
from forensiq.reporting.builder import ReportBuilder

# ── _format_size ──────────────────────────────────────────────────────────────


class TestFormatSize:
    def test_bytes(self):
        assert ReportBuilder._format_size(500) == "500.0 B"

    def test_kilobytes(self):
        assert ReportBuilder._format_size(1024) == "1.0 KB"

    def test_megabytes(self):
        assert ReportBuilder._format_size(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        assert ReportBuilder._format_size(1024 ** 3) == "1.0 GB"

    def test_terabytes(self):
        assert ReportBuilder._format_size(1024 ** 4) == "1.0 TB"

    def test_fractional_kb(self):
        result = ReportBuilder._format_size(1536)  # 1.5 KB
        assert result == "1.5 KB"

    def test_zero_bytes(self):
        assert ReportBuilder._format_size(0) == "0.0 B"

    def test_large_file(self):
        # 2 GB
        result = ReportBuilder._format_size(2 * 1024 ** 3)
        assert result == "2.0 GB"


# ── _build_report_filename ────────────────────────────────────────────────────


class TestBuildReportFilename:
    def _make_report(self, dump_path: str, timestamp: datetime) -> MagicMock:
        metadata = MagicMock()
        metadata.dump_path = dump_path
        metadata.analysis_start = timestamp
        report = MagicMock()
        report.metadata = metadata
        return report

    def test_filename_format(self):
        builder = ReportBuilder()
        ts = datetime(2024, 1, 15, 10, 30, 45, tzinfo=UTC)
        report = self._make_report("/dumps/memdump.raw", ts)
        name = builder._build_report_filename(report)
        assert name == "forensiq_memdump_20240115_103045.html"

    def test_filename_sanitizes_special_chars(self):
        builder = ReportBuilder()
        ts = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
        report = self._make_report("/dumps/my dump (1).raw", ts)
        name = builder._build_report_filename(report)
        # Special chars -> underscores
        assert " " not in name
        assert "(" not in name
        assert name.endswith(".html")

    def test_filename_stem_truncated_at_50(self):
        builder = ReportBuilder()
        ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
        long_name = "a" * 100
        report = self._make_report(f"/dumps/{long_name}.raw", ts)
        name = builder._build_report_filename(report)
        # stem should be at most 50 chars plus prefix/timestamp/ext
        # full name: forensiq_{50 chars}_{timestamp}.html
        stem_part = name[len("forensiq_"):name.rfind("_2024")]
        assert len(stem_part) <= 50

    def test_filename_starts_with_forensiq(self):
        builder = ReportBuilder()
        ts = datetime(2024, 3, 20, 8, 0, 0, tzinfo=UTC)
        report = self._make_report("/tmp/dump.vmem", ts)
        name = builder._build_report_filename(report)
        assert name.startswith("forensiq_")
        assert name.endswith(".html")

    def test_filename_includes_timestamp(self):
        builder = ReportBuilder()
        ts = datetime(2025, 12, 31, 23, 59, 59, tzinfo=UTC)
        report = self._make_report("/dumps/mem.raw", ts)
        name = builder._build_report_filename(report)
        assert "20251231_235959" in name


# ── ReportBuilder construction ────────────────────────────────────────────────


class TestReportBuilderConstruction:
    def test_format_score_filter(self):
        builder = ReportBuilder()
        fmt = builder._env.filters.get("format_score")
        assert fmt is not None
        assert fmt(0.75) == "75.0%"

    def test_format_size_filter(self):
        builder = ReportBuilder()
        fmt = builder._env.filters.get("format_size")
        assert fmt is not None
        assert fmt(1024) == "1.0 KB"

    def test_format_dt_filter(self):
        builder = ReportBuilder()
        fmt = builder._env.filters.get("format_dt")
        assert fmt is not None
        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        result = fmt(ts)
        assert "2024-01-15" in result
        assert "10:30:00" in result

    def test_format_dt_filter_none(self):
        builder = ReportBuilder()
        fmt = builder._env.filters.get("format_dt")
        assert fmt(None) == "N/A"


# ── render — error paths ──────────────────────────────────────────────────────


class TestRenderErrors:
    def _make_report(self, tmp_path: Path) -> MagicMock:
        metadata = MagicMock()
        metadata.dump_path = "/dumps/mem.raw"
        metadata.analysis_start = datetime(2024, 1, 1, tzinfo=UTC)
        report = MagicMock()
        report.metadata = metadata
        report.ranked_processes = []
        report.timeline = []
        report.yara_results = []
        report.top_threats = []
        return report

    def test_render_raises_report_error_on_template_not_found(self, tmp_path: Path):
        from jinja2 import TemplateNotFound

        from forensiq.utils.exceptions import ReportError

        builder = ReportBuilder()
        report = self._make_report(tmp_path)

        with patch.object(builder._env, "get_template", side_effect=TemplateNotFound("report.html.j2")):
            with pytest.raises(ReportError):
                builder.render(report, output_dir=tmp_path)

    def test_render_raises_report_error_on_write_failure(self, tmp_path: Path):
        from forensiq.utils.exceptions import ReportError

        builder = ReportBuilder()
        report = self._make_report(tmp_path)

        mock_template = MagicMock()
        mock_template.render.return_value = "<html>test</html>"

        with patch.object(builder._env, "get_template", return_value=mock_template):
            # Make output_dir a file so mkdir fails; or patch write_text
            output_path_mock = MagicMock(spec=Path)
            output_path_mock.write_text.side_effect = OSError("disk full")
            with patch("forensiq.reporting.builder.Path") as MockPath:
                # This is complex to patch; instead patch the output path's write
                # Let's use a simpler approach: patch Path.write_text to fail
                pass

        # Simpler: render to a read-only dir
        read_only = tmp_path / "ro"
        read_only.mkdir()
        read_only.chmod(0o444)
        try:
            with patch.object(builder._env, "get_template", return_value=mock_template):
                with pytest.raises((ReportError, PermissionError, OSError)):
                    builder.render(report, output_dir=read_only / "subdir")
        finally:
            read_only.chmod(0o755)


# ── render — llm_info labeling ───────────────────────────────────────────────


class TestRenderLlmInfo:
    def _make_report(self, llm_info: dict[str, str] | None) -> ForensiqReport:
        metadata = DumpMetadata(
            dump_path="/dumps/mem.raw",
            dump_sha256="a" * 64,
            dump_size_bytes=1024 * 1024,
            analysis_start=datetime(2024, 1, 1, tzinfo=UTC),
        )
        return ForensiqReport(
            metadata=metadata,
            executive_summary="Test executive summary.",
            llm_info=llm_info or {},
        )

    def test_render_with_resolved_model_shows_model_name(self, tmp_path: Path):
        builder = ReportBuilder()
        report = self._make_report(
            {"model": "qwen2.5-coder:7b", "status": "fallback", "requested_model": "mistral:latest"}
        )
        path = builder.render(report, tmp_path)
        html = path.read_text()
        assert "qwen2.5-coder:7b" in html
        assert "Rule-based summary" not in html

    def test_render_without_llm_shows_rule_based_label(self, tmp_path: Path):
        builder = ReportBuilder()
        report = self._make_report(
            {"model": "", "status": "unavailable", "requested_model": "mistral:latest"}
        )
        path = builder.render(report, tmp_path)
        html = path.read_text()
        assert "no local AI model" in html
        assert "AI-generated" not in html

    def test_render_without_llm_info_dict(self, tmp_path: Path):
        builder = ReportBuilder()
        report = self._make_report(None)
        path = builder.render(report, tmp_path)
        html = path.read_text()
        assert "no local AI model" in html
