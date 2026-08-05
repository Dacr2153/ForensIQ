# FILE: tests/unit/test_pipeline_utils.py
"""Unit tests for DumpContext and build_timeline."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from forensiq.models.features import ProcessFeatureVector
from forensiq.pipeline.dump_context import DumpContext
from forensiq.pipeline.timeline import (
    C2ConnectionRule,
    EncodedCmdlineRule,
    LsasDumpingRule,
    MalfindHitsRule,
    MasqueradingRule,
    SuspiciousDLLRule,
    VADRWXRule,
    TimelineRule,
    build_timeline,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _vec(**kwargs) -> ProcessFeatureVector:
    """Build a minimal ProcessFeatureVector with sane defaults."""
    defaults = dict(
        pid=100,
        ppid=4,
        name="test.exe",
        image_file_name=r"\Windows\System32\test.exe",
        process_name_entropy=2.5,
        path_entropy=3.0,
        path_depth=4,
        is_system_path=True,
        parent_child_legit=True,
        dll_count=5,
        suspicious_dll_count=0,
        has_network_connection=False,
        network_connection_count=0,
        external_connection_count=0,
        malfind_hits=0,
        vad_rwx_count=0,
        thread_count=5,
        handle_count=100,
        has_encoded_cmdline=False,
        threat_score=0.05,
        is_malicious=False,
        shap_values={},
    )
    defaults.update(kwargs)
    return ProcessFeatureVector(**defaults)


# ── DumpContext ───────────────────────────────────────────────────────────────


class TestDumpContext:
    def test_lime_extension_is_linux(self):
        ctx = DumpContext.from_path(Path("/dumps/memory.lime"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is True
        assert ctx.os_label == "linux"

    def test_kcore_extension_is_linux(self):
        ctx = DumpContext.from_path(Path("/proc/x.kcore"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is True

    def test_proc_kcore_path_is_linux(self):
        ctx = DumpContext.from_path(Path("/proc/kcore"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is True

    def test_raw_extension_is_windows(self):
        ctx = DumpContext.from_path(Path("/dumps/memory.raw"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is False
        assert ctx.os_label == "windows"

    def test_vmem_extension_is_windows(self):
        ctx = DumpContext.from_path(Path("/dumps/mem.vmem"), threshold=0.5, correlation_id="abc")
        assert ctx.is_linux is False

    def test_dmp_extension_is_windows(self):
        ctx = DumpContext.from_path(Path("/dumps/crash.dmp"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is False

    def test_threshold_stored(self):
        ctx = DumpContext.from_path(Path("/a.raw"), threshold=0.75, correlation_id="abc")
        assert ctx.threshold == 0.75

    def test_correlation_id_stored(self):
        ctx = DumpContext.from_path(Path("/a.raw"), threshold=0.65, correlation_id="my-run-id")
        assert ctx.correlation_id == "my-run-id"

    def test_dump_path_stored(self):
        p = Path("/dumps/memory.raw")
        ctx = DumpContext.from_path(p, threshold=0.65, correlation_id="x")
        assert ctx.dump_path == p

    def test_context_is_immutable(self):
        ctx = DumpContext.from_path(Path("/a.raw"), threshold=0.65, correlation_id="x")
        with pytest.raises((AttributeError, TypeError)):
            ctx.is_linux = True  # type: ignore[misc]

    def test_case_insensitive_lime(self):
        ctx = DumpContext.from_path(Path("/dumps/memory.LIME"), threshold=0.65, correlation_id="x")
        assert ctx.is_linux is True


# ── build_timeline ────────────────────────────────────────────────────────────


class TestBuildTimeline:
    def test_empty_vectors_returns_empty(self):
        assert build_timeline([]) == []

    def test_clean_process_not_included(self):
        v = _vec(threat_score=0.05, is_malicious=False)
        assert build_timeline([v]) == []

    def test_low_score_below_threshold_excluded(self):
        v = _vec(threat_score=0.34, is_malicious=False)
        assert build_timeline([v]) == []

    def test_suspicious_process_included_at_threshold(self):
        v = _vec(threat_score=0.35, is_malicious=False, malfind_hits=2)
        events = build_timeline([v])
        assert len(events) >= 1

    def test_malicious_process_included(self):
        v = _vec(threat_score=0.92, is_malicious=True, malfind_hits=1)
        events = build_timeline([v])
        assert len(events) >= 1

    def test_malfind_hits_rule_fires(self):
        v = _vec(is_malicious=True, threat_score=0.9, malfind_hits=3)
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "process_injection" in types

    def test_vad_rwx_rule_fires(self):
        v = _vec(is_malicious=True, threat_score=0.9, vad_rwx_count=5)
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "vad_rwx" in types

    def test_vad_rwx_rule_not_fires_below_threshold(self):
        v = _vec(is_malicious=True, threat_score=0.9, vad_rwx_count=2)
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "vad_rwx" not in types

    def test_encoded_cmdline_windows_fires(self):
        v = _vec(is_malicious=True, threat_score=0.9, has_encoded_cmdline=True)
        events = build_timeline([v], is_linux=False)
        types = [e.event_type for e in events]
        assert "encoded_cmdline" in types

    def test_encoded_cmdline_linux_suppressed(self):
        v = _vec(is_malicious=True, threat_score=0.9, has_encoded_cmdline=True)
        events = build_timeline([v], is_linux=True)
        types = [e.event_type for e in events]
        assert "encoded_cmdline" not in types

    def test_masquerading_rule_fires(self):
        v = _vec(
            is_malicious=True,
            threat_score=0.9,
            process_name_entropy=4.5,
            is_system_path=False,
        )
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "masquerading" in types

    def test_masquerading_rule_not_fires_system_path(self):
        v = _vec(
            is_malicious=True,
            threat_score=0.9,
            process_name_entropy=4.5,
            is_system_path=True,
        )
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "masquerading" not in types

    def test_c2_connection_rule_fires(self):
        v = _vec(is_malicious=True, threat_score=0.9, external_connection_count=2)
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "c2_connection" in types

    def test_lsass_suspicious_dll_rule_fires(self):
        v = _vec(
            name="lsass.exe",
            is_malicious=True,
            threat_score=0.9,
            suspicious_dll_count=2,
        )
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "lsass_suspicious_dll" in types

    def test_suspicious_dll_rule_not_fires_for_lsass(self):
        v = _vec(
            name="lsass.exe",
            is_malicious=True,
            threat_score=0.9,
            suspicious_dll_count=2,
        )
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "suspicious_dll" not in types

    def test_suspicious_dll_rule_fires_non_lsass(self):
        v = _vec(
            name="evil.exe",
            is_malicious=True,
            threat_score=0.9,
            suspicious_dll_count=3,
        )
        events = build_timeline([v])
        types = [e.event_type for e in events]
        assert "suspicious_dll" in types

    def test_events_sorted_critical_first(self):
        v1 = _vec(pid=1, name="z_proc.exe", is_malicious=True, threat_score=0.9, malfind_hits=1)
        v2 = _vec(pid=2, name="a_proc.exe", is_malicious=True, threat_score=0.9, vad_rwx_count=5)
        events = build_timeline([v1, v2])
        severities = [e.severity for e in events]
        # high severity events (malfind, vad_rwx) should appear before medium
        for i in range(len(severities) - 1):
            sev_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            assert sev_map.get(severities[i], 4) <= sev_map.get(severities[i + 1], 4)

    def test_custom_rules_used(self):
        v = _vec(is_malicious=True, threat_score=0.9, malfind_hits=5)
        # Pass empty rule list — should get no events
        events = build_timeline([v], rules=[])
        assert events == []

    def test_baseline_severity_malicious_is_critical(self):
        v = _vec(is_malicious=True, threat_score=0.92, malfind_hits=1)
        events = build_timeline([v])
        process_injection = next((e for e in events if e.event_type == "process_injection"), None)
        assert process_injection is not None
        assert process_injection.severity == "critical"

    def test_baseline_severity_suspicious_capped_at_medium(self):
        # Suspicious (not malicious): malfind rule returns baseline_sev
        v = _vec(is_malicious=False, threat_score=0.5, malfind_hits=1)
        events = build_timeline([v])
        process_injection = next((e for e in events if e.event_type == "process_injection"), None)
        assert process_injection is not None
        assert process_injection.severity == "medium"

    def test_mitre_technique_populated(self):
        v = _vec(is_malicious=True, threat_score=0.9, malfind_hits=2)
        events = build_timeline([v])
        pi = next(e for e in events if e.event_type == "process_injection")
        assert pi.mitre_technique == "T1055"

    def test_pid_and_process_name_in_event(self):
        v = _vec(pid=9999, name="badproc.exe", is_malicious=True, threat_score=0.9, malfind_hits=1)
        events = build_timeline([v])
        pi = next(e for e in events if e.event_type == "process_injection")
        assert pi.pid == 9999
        assert pi.process_name == "badproc.exe"
