# FILE: tests/unit/test_executive_report.py
"""Unit tests for ExecutiveReportGenerator._build_prompt and _build_fallback_summary."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from forensiq.reporting.executive import ExecutiveReportGenerator


def _make_event(severity: str = "critical", pid: int = 1234, description: str = "test"):
    e = MagicMock()
    e.severity = severity
    e.pid = pid
    e.process_name = "evil.exe"
    e.description = description
    return e


def _make_proc(name: str = "evil.exe", pid: int = 1234, score: float = 0.99):
    p = MagicMock()
    p.name = name
    p.pid = pid
    p.threat_score = score
    p.malfind_hits = 3
    p.external_connection_count = 2
    return p


def _make_technique(
    tech_id: str = "T1055",
    name: str = "Process Injection",
    tactic: str = "defense-evasion",
    count: int = 2,
):
    return {"technique_id": tech_id, "name": name, "tactic": tactic, "observation_count": count}


def _make_report(
    dump_path: str = "C:\\dumps\\mem.raw",
    dump_filename: str = "mem.raw",
    total: int = 50,
    malicious: int = 3,
    suspicious: int = 5,
    threat_level: str = "high",
    timeline_events=None,
    mitre_techniques=None,
    top_threats=None,
):
    metadata = MagicMock()
    metadata.dump_path = dump_path
    metadata.dump_filename = dump_filename

    report = MagicMock()
    report.metadata = metadata
    report.total_processes = total
    report.malicious_count = malicious
    report.suspicious_count = suspicious
    report.threat_level = threat_level
    report.timeline = timeline_events or []
    report.mitre_techniques = mitre_techniques or []
    report.top_threats = top_threats or []
    return report


# ── _build_prompt ─────────────────────────────────────────────────────────────


class TestBuildPrompt:
    def setup_method(self):
        self.gen = ExecutiveReportGenerator(client=MagicMock())

    def test_prompt_contains_dump_filename(self):
        report = _make_report(dump_filename="memory.raw")
        prompt = self.gen._build_prompt(report)
        assert "memory.raw" in prompt

    def test_prompt_detects_windows(self):
        report = _make_report(dump_path="C:\\dumps\\mem.raw")
        prompt = self.gen._build_prompt(report)
        assert "Windows" in prompt

    def test_prompt_detects_linux_lime(self):
        report = _make_report(dump_path="/tmp/mem.lime")
        prompt = self.gen._build_prompt(report)
        assert "Linux" in prompt

    def test_prompt_detects_linux_kcore(self):
        report = _make_report(dump_path="/proc/kcore")
        prompt = self.gen._build_prompt(report)
        assert "Linux" in prompt

    def test_prompt_includes_critical_events(self):
        events = [_make_event("critical", description="critical event found")]
        report = _make_report(timeline_events=events)
        prompt = self.gen._build_prompt(report)
        assert "critical event found" in prompt.lower() or "CRITICAL" in prompt

    def test_prompt_includes_mitre_techniques(self):
        techniques = [_make_technique("T1059", "Command-Line Interface", "execution")]
        report = _make_report(mitre_techniques=techniques)
        prompt = self.gen._build_prompt(report)
        assert "T1059" in prompt

    def test_prompt_includes_top_threats(self):
        procs = [_make_proc("evil.exe", 999, 0.98)]
        report = _make_report(top_threats=procs)
        prompt = self.gen._build_prompt(report)
        assert "evil.exe" in prompt

    def test_no_events_shows_placeholder(self):
        report = _make_report(timeline_events=[])
        prompt = self.gen._build_prompt(report)
        assert "No critical findings" in prompt

    def test_no_mitre_shows_placeholder(self):
        report = _make_report(mitre_techniques=[])
        prompt = self.gen._build_prompt(report)
        assert "No MITRE" in prompt

    def test_no_top_threats_shows_placeholder(self):
        report = _make_report(top_threats=[])
        prompt = self.gen._build_prompt(report)
        assert "No malicious processes" in prompt


# ── _build_fallback_summary ───────────────────────────────────────────────────


class TestBuildFallbackSummary:
    def setup_method(self):
        self.gen = ExecutiveReportGenerator(client=MagicMock())

    def test_no_findings_clean_report(self):
        report = _make_report(malicious=0, suspicious=0, threat_level="low")
        summary = self.gen._build_fallback_summary(report)
        assert "no processes" in summary.lower()
        assert "LOW" in summary

    def test_linux_clean_report_mentions_xgboost(self):
        report = _make_report(
            dump_path="/tmp/dump.lime", malicious=0, suspicious=0, threat_level="low"
        )
        summary = self.gen._build_fallback_summary(report)
        assert "XGBoost" in summary

    def test_windows_clean_report_no_xgboost_note(self):
        report = _make_report(
            dump_path="C:\\dumps\\mem.raw", malicious=0, suspicious=0, threat_level="low"
        )
        summary = self.gen._build_fallback_summary(report)
        assert "XGBoost" not in summary

    def test_malicious_found_includes_count(self):
        report = _make_report(malicious=5, total=100, threat_level="critical")
        summary = self.gen._build_fallback_summary(report)
        assert "5 malicious" in summary
        assert "100 total" in summary

    def test_malicious_includes_top_process(self):
        procs = [_make_proc("malware.exe", 1234, 0.99)]
        report = _make_report(malicious=1, top_threats=procs)
        summary = self.gen._build_fallback_summary(report)
        assert "malware.exe" in summary

    def test_malicious_includes_mitre_techniques(self):
        report = _make_report(
            malicious=2,
            mitre_techniques=[_make_technique("T1055"), _make_technique("T1059")],
        )
        summary = self.gen._build_fallback_summary(report)
        assert "T1055" in summary
        assert "T1059" in summary

    def test_malicious_threat_level_uppercase(self):
        report = _make_report(malicious=1, threat_level="critical")
        summary = self.gen._build_fallback_summary(report)
        assert "CRITICAL" in summary

    def test_includes_remediation_guidance(self):
        report = _make_report(malicious=1)
        summary = self.gen._build_fallback_summary(report)
        assert "isolate" in summary.lower() or "incident response" in summary.lower()


# ── generate() — async ───────────────────────────────────────────────────────


class TestGenerate:
    @pytest.mark.asyncio
    async def test_generate_uses_client_response(self):
        client = AsyncMock()
        client.generate = AsyncMock(return_value="Executive summary from LLM.")
        gen = ExecutiveReportGenerator(client=client)
        report = _make_report()
        result = await gen.generate(report)
        assert result == "Executive summary from LLM."

    @pytest.mark.asyncio
    async def test_generate_fallback_on_client_error(self):
        client = AsyncMock()
        client.generate = AsyncMock(side_effect=Exception("LLM unavailable"))
        gen = ExecutiveReportGenerator(client=client)
        report = _make_report(malicious=0, suspicious=0, threat_level="low")
        result = await gen.generate(report)
        # Should return fallback summary (non-empty string)
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_generate_fallback_when_empty_response(self):
        client = AsyncMock()
        client.generate = AsyncMock(return_value="   ")  # whitespace only
        gen = ExecutiveReportGenerator(client=client)
        report = _make_report(malicious=0, suspicious=0, threat_level="low")
        result = await gen.generate(report)
        assert isinstance(result, str)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_generate_never_returns_empty_when_llm_unavailable(self):
        # The generator must always produce a non-empty summary (deterministic
        # fallback) even when the LLM is entirely unavailable.
        client = AsyncMock()
        client.generate = AsyncMock(side_effect=Exception("connection refused"))
        gen = ExecutiveReportGenerator(client=client)
        report = _make_report(malicious=2, total=100, threat_level="critical")
        result = await gen.generate(report)
        assert isinstance(result, str)
        assert len(result.strip()) > 0
        assert "2 malicious" in result
