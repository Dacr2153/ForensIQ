# FILE: tests/unit/test_report_models.py
"""Unit tests for ForensiqReport and DumpMetadata computed fields."""

from __future__ import annotations

from datetime import UTC, datetime

from forensiq.models.features import ProcessFeatureVector
from forensiq.models.report import DumpMetadata, ForensiqReport, ThreatEvent, YARAResult

# ── DumpMetadata ──────────────────────────────────────────────────────────────


def _make_metadata(**kwargs) -> DumpMetadata:
    defaults = {
        "dump_path": "/dumps/mem.raw",
        "dump_sha256": "a" * 64,
        "dump_size_bytes": 1024 * 1024 * 1024,  # 1 GB
        "analysis_start": datetime(2024, 1, 1, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return DumpMetadata(**defaults)


class TestDumpMetadata:
    def test_dump_size_mb(self):
        meta = _make_metadata(dump_size_bytes=2 * 1024 * 1024)
        assert meta.dump_size_mb == 2.0

    def test_dump_filename(self):
        meta = _make_metadata(dump_path="/dumps/memory.raw")
        assert meta.dump_filename == "memory.raw"

    def test_dump_filename_windows_path(self):
        meta = _make_metadata(dump_path="C:\\dumps\\dump.vmem")
        # Path() will handle the path
        assert "dump.vmem" in meta.dump_filename

    def test_analysis_duration_none_when_no_end(self):
        meta = _make_metadata(analysis_end=None)
        assert meta.analysis_duration_seconds is None

    def test_analysis_duration_seconds(self):
        start = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        end = datetime(2024, 1, 1, 10, 1, 30, tzinfo=UTC)
        meta = _make_metadata(analysis_start=start, analysis_end=end)
        assert meta.analysis_duration_seconds == 90.0

    def test_coerce_os_profile_none_to_empty(self):
        meta = _make_metadata(os_profile=None)
        assert meta.os_profile == ""

    def test_coerce_os_profile_string_unchanged(self):
        meta = _make_metadata(os_profile="Windows 10")
        assert meta.os_profile == "Windows 10"

    def test_repr_contains_filename(self):
        meta = _make_metadata(dump_path="/tmp/mem.raw")
        r = repr(meta)
        assert "mem.raw" in r


# ── ForensiqReport computed fields ────────────────────────────────────────────


def _make_pvec(
    is_malicious: bool = False,
    threat_score: float = 0.5,
    pid: int = 1,
) -> ProcessFeatureVector:
    return ProcessFeatureVector(
        pid=pid,
        name="evil.exe",
        ppid=4,
        is_malicious=is_malicious,
        threat_score=threat_score,
    )


def _make_event(severity: str = "low") -> ThreatEvent:
    return ThreatEvent(
        pid=1,
        process_name="evil.exe",
        event_type="test",
        severity=severity,
        description="test event",
    )


def _make_yara_result(is_valid: bool = True) -> YARAResult:
    return YARAResult(
        rule_name="forensiq_evil_1234",
        process_name="evil.exe",
        pid=1234,
        rule_text='rule forensiq_evil_1234 { strings: $s = "x" condition: $s }',
        is_valid=is_valid,
    )


def _make_report(**kwargs) -> ForensiqReport:
    defaults = {
        "metadata": _make_metadata(),
    }
    defaults.update(kwargs)
    return ForensiqReport(**defaults)


class TestForensiqReportThreatLevel:
    def test_no_processes_returns_low(self):
        report = _make_report()
        assert report.threat_level == "low"

    def test_no_malicious_suspicious_returns_medium(self):
        proc = _make_pvec(is_malicious=False)
        report = _make_report(ranked_processes=[proc], suspicious_count=1)
        assert report.threat_level == "medium"

    def test_one_malicious_returns_high(self):
        proc = _make_pvec(is_malicious=True)
        report = _make_report(ranked_processes=[proc], malicious_count=1)
        assert report.threat_level == "high"

    def test_three_malicious_returns_critical(self):
        procs = [_make_pvec(is_malicious=True) for _ in range(3)]
        report = _make_report(ranked_processes=procs, malicious_count=3)
        assert report.threat_level == "critical"

    def test_one_malicious_plus_critical_event_returns_critical(self):
        proc = _make_pvec(is_malicious=True)
        event = _make_event("critical")
        report = _make_report(
            ranked_processes=[proc],
            malicious_count=1,
            timeline=[event],
        )
        assert report.threat_level == "critical"

    def test_no_findings_clean(self):
        proc = _make_pvec(is_malicious=False)
        report = _make_report(ranked_processes=[proc], suspicious_count=0)
        assert report.threat_level == "low"


class TestForensiqReportValidYaraCount:
    def test_no_results_returns_zero(self):
        report = _make_report()
        assert report.valid_yara_count == 0

    def test_counts_valid_only(self):
        results = [
            _make_yara_result(is_valid=True),
            _make_yara_result(is_valid=False),
            _make_yara_result(is_valid=True),
        ]
        report = _make_report(yara_results=results)
        assert report.valid_yara_count == 2


class TestForensiqReportTopThreats:
    def test_empty_ranked_returns_empty_top_threats(self):
        report = _make_report()
        assert report.top_threats == []

    def test_only_malicious_processes_included(self):
        good = _make_pvec(is_malicious=False)
        bad = _make_pvec(is_malicious=True)
        report = _make_report(ranked_processes=[good, bad])
        assert bad in report.top_threats
        assert good not in report.top_threats

    def test_top_threats_capped_at_10(self):
        procs = [_make_pvec(is_malicious=True) for _ in range(15)]
        report = _make_report(ranked_processes=procs)
        assert len(report.top_threats) == 10


class TestForensiqReportRepr:
    def test_repr_contains_dump_filename(self):
        report = _make_report()
        r = repr(report)
        assert "mem.raw" in r

    def test_repr_contains_threat_level(self):
        report = _make_report()
        r = repr(report)
        assert "threat_level" in r


class TestForensiqReportLlmInfo:
    def test_default_empty(self):
        report = _make_report()
        assert report.llm_info == {}

    def test_serialized_into_json(self):
        report = _make_report(
            llm_info={
                "model": "qwen2.5-coder:7b",
                "status": "fallback",
                "requested_model": "mistral:latest",
            }
        )
        data = report.model_dump()
        assert data["llm_info"]["model"] == "qwen2.5-coder:7b"
        assert data["llm_info"]["status"] == "fallback"

    def test_roundtrip_through_json(self):
        report = _make_report(
            llm_info={"model": "", "status": "unavailable", "requested_model": "mistral:latest"}
        )
        json_str = report.model_dump_json()
        loaded = ForensiqReport.model_validate_json(json_str)
        assert loaded.llm_info["status"] == "unavailable"
