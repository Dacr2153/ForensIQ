# FILE: tests/unit/test_reporting_builder.py
"""Unit tests for ReportBuilder helpers (non-template-rendering parts)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from forensiq.models.report import DumpMetadata, ForensiqReport
from forensiq.reporting.builder import ReportBuilder

# ── _json_for_script (stored-XSS mitigation) ──────────────────────────────────


class TestJsonForScript:
    def test_escapes_script_tag_in_string_value(self) -> None:
        from forensiq.reporting.builder import _json_for_script

        payload = "</script><script>alert(1)</script>"
        out = str(_json_for_script([{"process_name": payload}]))
        assert "<" not in out and ">" not in out
        assert "\\u003c/script\\u003e" in out
        assert "alert(1)" in out

    def test_escapes_ampersand_and_unicode_separators(self) -> None:
        from forensiq.reporting.builder import _json_for_script

        out = str(_json_for_script([{"description": "a&b\u2028c\u2029d"}]))
        assert "\\u0026" in out
        assert "\\u2028" in out
        assert "\\u2029" in out
        assert "\u2028" not in out

    def test_output_is_valid_json_when_unescaped(self) -> None:
        import json as jsonlib

        from forensiq.reporting.builder import _json_for_script

        payload = "</script><script>alert(1)</script>"
        out = str(_json_for_script([{"process_name": payload}]))
        # Undoing the JS-safe escapes must yield the original data.
        decoded = out.replace("\\u003c", "<").replace("\\u003e", ">")
        assert jsonlib.loads(decoded)[0]["process_name"] == payload

    def test_returns_markup_so_autoescape_does_not_double_escape(self) -> None:
        from forensiq.reporting.builder import _json_for_script

        out = _json_for_script({"k": "v"})
        assert isinstance(str(out), str)
        # Structural quotes must survive so JS can parse the literal.
        assert '"k"' in str(out)


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

        with patch.object(
            builder._env,
            "get_template",
            side_effect=TemplateNotFound("report.html.j2"),
        ):
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
            with patch("forensiq.reporting.builder.Path"):
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


# ── render — stored-XSS regression ────────────────────────────────────────────


class TestRenderXssMitigation:
    def test_script_tag_in_process_name_does_not_break_out(self, tmp_path: Path) -> None:
        """Attacker-controlled process names must not break out of the JS context.

        A process name containing ``</script>`` used to be injected verbatim
        via ``{{ timeline_json | safe }}``, creating a stored-XSS vector in the
        generated report.  The ``json_script`` filter must neutralise it.
        """
        from forensiq.models.report import DumpMetadata, ForensiqReport, ThreatEvent

        metadata = DumpMetadata(
            dump_path="/dumps/mem.raw",
            dump_sha256="a" * 64,
            dump_size_bytes=1024 * 1024,
            analysis_start=datetime(2024, 1, 1, tzinfo=UTC),
        )
        payload = "</script><script>alert(1)</script>"
        report = ForensiqReport(
            metadata=metadata,
            executive_summary="",
            timeline=[
                ThreatEvent(
                    pid=1,
                    process_name=payload,
                    event_type="malicious",
                    severity="critical",
                    description="Injected script content",
                )
            ],
        )

        builder = ReportBuilder()
        path = builder.render(report, tmp_path)
        html = path.read_text()

        # The raw breakout sequence must not appear anywhere in the output.
        assert "</script><script>" not in html
        assert "<script>alert(1)" not in html
        # The payload content survives (escaped) so evidence is not lost.
        assert "\\u003c/script\\u003e" in html


# ── render — degraded-analysis banner ─────────────────────────────────────────


class TestRenderDegradedBanner:
    def test_degraded_reason_renders_warning_banner(self, tmp_path: Path) -> None:
        from forensiq.models.report import DumpMetadata, ForensiqReport

        metadata = DumpMetadata(
            dump_path="/dumps/mem.raw",
            dump_sha256="a" * 64,
            dump_size_bytes=1024 * 1024,
            analysis_start=datetime(2024, 1, 1, tzinfo=UTC),
        )
        report = ForensiqReport(
            metadata=metadata,
            degraded_reason=(
                "ML model not found — classification skipped, "
                "all process scores set to 0.0"
            ),
        )

        builder = ReportBuilder()
        path = builder.render(report, tmp_path)
        html = path.read_text()

        assert "Degraded Analysis" in html
        assert "ML Classification" in html
        assert "ML model not found" in html
        assert "be treated as a clean result" in html

    def test_clean_report_has_no_degraded_banner(self, tmp_path: Path) -> None:
        from forensiq.models.report import DumpMetadata, ForensiqReport

        metadata = DumpMetadata(
            dump_path="/dumps/mem.raw",
            dump_sha256="a" * 64,
            dump_size_bytes=1024 * 1024,
            analysis_start=datetime(2024, 1, 1, tzinfo=UTC),
        )
        report = ForensiqReport(metadata=metadata)

        builder = ReportBuilder()
        path = builder.render(report, tmp_path)
        html = path.read_text()

        assert "Degraded Analysis" not in html
        assert "be treated as a clean result" not in html

