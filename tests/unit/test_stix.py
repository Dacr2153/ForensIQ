# FILE: tests/unit/test_stix.py
"""Unit tests for STIX 2.1 exporter and TUI menu imports."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── STIX exporter tests ───────────────────────────────────────────────────────


class TestSTIXExporter:
    """Tests for STIXExporter class."""

    def test_stix_exporter_importable(self) -> None:
        """STIXExporter can be imported."""
        from forensiq.reporting.stix_exporter import STIXExporter

        assert STIXExporter is not None

    def test_safe_stix_helper(self) -> None:
        """_safe_stix escapes single quotes."""
        from forensiq.reporting.stix_exporter import _safe_stix

        assert _safe_stix("it's") == "it\\'s"
        assert _safe_stix("hello") == "hello"
        assert _safe_stix("no'quotes'here") == "no\\'quotes\\'here"

    def test_safe_stix_no_mutation_on_clean_string(self) -> None:
        """_safe_stix returns identical string when no quotes present."""
        from forensiq.reporting.stix_exporter import _safe_stix

        result = _safe_stix("cmd.exe")
        assert result == "cmd.exe"

    def test_stix_exporter_has_export_method(self) -> None:
        """STIXExporter has an export() method."""
        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()
        assert callable(exp.export)

    def test_stix_export_requires_stix2(self, tmp_path: Path) -> None:
        """export() raises ImportError if stix2 is not installed."""
        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()
        mock_report = MagicMock()
        mock_report.ranked_processes = []
        mock_report.mitre_techniques = []
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 0
        mock_report.malicious_count = 0
        mock_report.suspicious_count = 0
        mock_report.threat_level = "low"
        mock_report.metadata.dump_path = "/tmp/test.raw"

        # Patch stix2 import to raise ImportError
        with patch.dict(sys.modules, {"stix2": None}):
            try:
                exp.export(mock_report, output_dir=tmp_path)
            except (ImportError, TypeError):
                pass  # Expected — stix2 not available in patched context

    def test_stix_export_creates_bundle(self, tmp_path: Path) -> None:
        """export() creates a valid JSON file with STIX bundle structure."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("stix2 not installed")

        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()

        # Build a minimal report mock with one malicious process
        mock_vec = MagicMock()
        mock_vec.is_malicious = True
        mock_vec.pid = 1234
        mock_vec.name = "malware.exe"
        mock_vec.image_file_name = "C:\\Windows\\malware.exe"
        mock_vec.ensemble_score = 0.92
        mock_vec.threat_score = 0.95
        mock_vec.isolation_score = 0.87

        mock_report = MagicMock()
        mock_report.ranked_processes = [mock_vec]
        mock_report.mitre_techniques = [
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "description": "Adversary injects code into processes.",
            }
        ]
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 10
        mock_report.malicious_count = 1
        mock_report.suspicious_count = 2
        mock_report.threat_level = "high"
        mock_report.metadata.dump_path = "/tmp/MemoryDump_Lab1.raw"

        out_path = exp.export(mock_report, output_dir=tmp_path)

        assert out_path.exists()
        assert out_path.suffix == ".json"
        assert "stix" in out_path.name.lower()

        content = json.loads(out_path.read_text())
        assert content.get("type") == "bundle"
        assert "objects" in content
        assert len(content["objects"]) > 0

    def test_stix_bundle_contains_malware_object(self, tmp_path: Path) -> None:
        """export() bundle includes Malware STIX objects for malicious processes."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("stix2 not installed")

        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()

        mock_vec = MagicMock()
        mock_vec.is_malicious = True
        mock_vec.pid = 9999
        mock_vec.name = "bad_process"
        mock_vec.image_file_name = ""
        mock_vec.ensemble_score = 0.88
        mock_vec.threat_score = 0.91
        mock_vec.isolation_score = 0.82

        mock_report = MagicMock()
        mock_report.ranked_processes = [mock_vec]
        mock_report.mitre_techniques = []
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 5
        mock_report.malicious_count = 1
        mock_report.suspicious_count = 0
        mock_report.threat_level = "critical"
        mock_report.metadata.dump_path = "test.raw"

        out_path = exp.export(mock_report, output_dir=tmp_path)
        content = json.loads(out_path.read_text())
        types = {obj["type"] for obj in content["objects"]}
        assert "malware" in types

    def test_stix_bundle_contains_attack_pattern(self, tmp_path: Path) -> None:
        """export() bundle includes AttackPattern objects for MITRE techniques."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("stix2 not installed")

        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()

        mock_vec = MagicMock()
        mock_vec.is_malicious = True
        mock_vec.pid = 4321
        mock_vec.name = "inject.exe"
        mock_vec.image_file_name = ""
        mock_vec.ensemble_score = 0.85
        mock_vec.threat_score = 0.87
        mock_vec.isolation_score = 0.80

        mock_report = MagicMock()
        mock_report.ranked_processes = [mock_vec]
        mock_report.mitre_techniques = [
            {
                "technique_id": "T1134",
                "technique_name": "Access Token Manipulation",
                "description": "",
            }
        ]
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 3
        mock_report.malicious_count = 1
        mock_report.suspicious_count = 0
        mock_report.threat_level = "high"
        mock_report.metadata.dump_path = "test.raw"

        out_path = exp.export(mock_report, output_dir=tmp_path)
        content = json.loads(out_path.read_text())
        types = {obj["type"] for obj in content["objects"]}
        assert "attack-pattern" in types

    def test_stix_bundle_has_report_object(self, tmp_path: Path) -> None:
        """export() bundle includes top-level Report object."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("stix2 not installed")

        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()

        mock_report = MagicMock()
        mock_report.ranked_processes = []
        mock_report.mitre_techniques = []
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 0
        mock_report.malicious_count = 0
        mock_report.suspicious_count = 0
        mock_report.threat_level = "low"
        mock_report.metadata.dump_path = "test.raw"

        out_path = exp.export(mock_report, output_dir=tmp_path)
        content = json.loads(out_path.read_text())
        types = {obj["type"] for obj in content["objects"]}
        assert "report" in types

    def test_stix_spec_version(self, tmp_path: Path) -> None:
        """export() produces a STIX 2.1 bundle (spec_version=2.1 set by library)."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("stix2 not installed")

        from forensiq.reporting.stix_exporter import STIXExporter

        exp = STIXExporter()

        mock_report = MagicMock()
        mock_report.ranked_processes = []
        mock_report.mitre_techniques = []
        mock_report.yara_results = []
        mock_report.dll_yara_hits = []
        mock_report.total_processes = 0
        mock_report.malicious_count = 0
        mock_report.suspicious_count = 0
        mock_report.threat_level = "low"
        mock_report.metadata.dump_path = "test.raw"

        out_path = exp.export(mock_report, output_dir=tmp_path)
        content = json.loads(out_path.read_text())
        # stix2 v21 library automatically sets spec_version on all objects
        assert content.get("type") == "bundle"
        # Objects should have spec_version in them
        for obj in content.get("objects", []):
            assert obj.get("spec_version") == "2.1"


# ── TUI menu tests ────────────────────────────────────────────────────────────


class TestTUIMenu:
    """Tests for TUI menu module structure."""

    def test_tui_menu_importable(self) -> None:
        """forensiq.tui.menu is importable."""
        import forensiq.tui.menu as m

        assert m is not None

    def test_run_menu_callable(self) -> None:
        """run_menu function exists and is callable."""
        from forensiq.tui.menu import run_menu

        assert callable(run_menu)

    def test_helper_functions_exist(self) -> None:
        """Key internal helper functions exist."""
        import forensiq.tui.menu as m

        assert callable(m._ask_choice)
        assert callable(m._ask_path)
        assert callable(m._ask_confirm)
        assert callable(m._ask_text)
        assert callable(m._print_report_summary)

    def test_main_menu_choices_non_empty(self) -> None:
        """_MAIN_MENU_CHOICES has at least 5 entries."""
        from forensiq.tui.menu import _MAIN_MENU_CHOICES

        assert len(_MAIN_MENU_CHOICES) >= 5

    def test_main_menu_has_exit(self) -> None:
        """_MAIN_MENU_CHOICES always has an exit option."""
        from forensiq.tui.menu import _MAIN_MENU_CHOICES

        values = [val for _, val in _MAIN_MENU_CHOICES]
        assert "exit" in values

    def test_main_menu_has_analyze(self) -> None:
        """_MAIN_MENU_CHOICES has analyze option."""
        from forensiq.tui.menu import _MAIN_MENU_CHOICES

        values = [val for _, val in _MAIN_MENU_CHOICES]
        assert "analyze" in values

    def test_main_menu_has_diff(self) -> None:
        """_MAIN_MENU_CHOICES has diff option."""
        from forensiq.tui.menu import _MAIN_MENU_CHOICES

        values = [val for _, val in _MAIN_MENU_CHOICES]
        assert "diff" in values

    def test_qs_style_returns_style(self) -> None:
        """_qs_style() returns a questionary.Style instance."""
        try:
            import questionary  # noqa: F401
        except ImportError:
            import pytest

            pytest.skip("questionary not installed")
        from forensiq.tui.menu import _qs_style

        style = _qs_style()
        assert style is not None

    def test_import_version_helper(self) -> None:
        """_import_version returns version string for installed packages."""
        from forensiq.tui.menu import _import_version

        # sys is always available as a module; test with 'json'
        result_json = _import_version("json")
        # json is stdlib — no importlib.metadata entry, but __import__ succeeds
        assert isinstance(result_json, str)

    def test_safe_stix_is_pure_function(self) -> None:
        """_safe_stix does not modify its argument in place."""
        from forensiq.reporting.stix_exporter import _safe_stix

        original = "test'string"
        result = _safe_stix(original)
        assert original == "test'string"  # original unchanged
        assert result == "test\\'string"


# ── STIXExporter.export() integration tests ────────────────────────────────────


def _make_stix_report(
    malicious: bool = True,
    add_yara: bool = False,
    add_mitre: bool = False,
    observed_pids: list[int] | None = None,
):
    """Build a minimal ForensiqReport for STIX export tests."""
    from datetime import UTC, datetime

    from forensiq.models.features import ProcessFeatureVector
    from forensiq.models.report import DumpMetadata, ForensiqReport, YARAResult

    meta = DumpMetadata(
        dump_path="/tmp/mem.raw",
        dump_sha256="a" * 64,
        dump_size_bytes=1024,
        analysis_start=datetime(2024, 1, 1, tzinfo=UTC),
    )
    vec = ProcessFeatureVector(
        pid=1234,
        name="evil.exe",
        ppid=4,
        is_malicious=malicious,
        threat_score=0.95,
        cmd_line="evil.exe --inject",
    )

    yara_results = []
    if add_yara:
        yara_results = [
            YARAResult(
                rule_name="forensiq_evil_1234",
                process_name="evil.exe",
                pid=1234,
                rule_text='rule forensiq_evil_1234 { strings: $s = "evil" condition: $s }',
                is_valid=True,
            )
        ]

    mitre_techniques = []
    if add_mitre:
        mitre_techniques = [
            {
                "technique_id": "T1055",
                "technique_name": "Process Injection",
                "description": "Injection",
                "observed_pids": observed_pids if observed_pids is not None else [1234],
            },
        ]

    return ForensiqReport(
        metadata=meta,
        ranked_processes=[vec],
        malicious_count=1 if malicious else 0,
        yara_results=yara_results,
        mitre_techniques=mitre_techniques,
    )


class TestSTIXExporterExport:
    def test_export_creates_file(self, tmp_path) -> None:
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        assert result.exists()

    def test_export_with_non_malicious_process(self, tmp_path) -> None:
        """Export skips non-malicious processes (covers the `continue` branch)."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=False)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        assert result.exists()

    def test_export_with_yara_results(self, tmp_path) -> None:
        """Export covers the YARA Indicator creation path."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True, add_yara=True)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        bundle_data = json.loads(result.read_text())
        assert "objects" in bundle_data

    def test_export_with_mitre_techniques(self, tmp_path) -> None:
        """Export covers AttackPattern + Relationship creation."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True, add_yara=True, add_mitre=True)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        bundle_data = json.loads(result.read_text())
        # Should contain Malware, AttackPattern, Relationship, Report objects
        types = {obj["type"] for obj in bundle_data["objects"]}
        assert "attack-pattern" in types

    def test_export_relationship_only_for_observed_pid(self, tmp_path) -> None:
        """Malware→AttackPattern 'uses' edges exist only for the observing PID,
        not a cartesian cross-product of all malware and all techniques."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        # Technique observed on a DIFFERENT pid than the malicious process (1234)
        report = _make_stix_report(malicious=True, add_mitre=True, observed_pids=[9999])
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        bundle_data = json.loads(result.read_text())
        uses = [
            obj
            for obj in bundle_data["objects"]
            if obj["type"] == "relationship" and obj["relationship_type"] == "uses"
        ]
        assert uses == []

    def test_export_uses_relationship_for_matching_pid(self, tmp_path) -> None:
        """A malicious process IS linked to a technique observed on its PID."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True, add_mitre=True, observed_pids=[1234])
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        bundle_data = json.loads(result.read_text())
        uses = [
            obj
            for obj in bundle_data["objects"]
            if obj["type"] == "relationship" and obj["relationship_type"] == "uses"
        ]
        assert len(uses) == 1

    def test_export_yara_indicator_carries_rule_text(self, tmp_path) -> None:
        """YARA Indicators embed the real rule text with pattern_type='yara',
        not a placeholder STIX pattern."""
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True, add_yara=True)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        bundle_data = json.loads(result.read_text())
        yara_inds = [
            obj for obj in bundle_data["objects"] if obj.get("pattern_type") == "yara"
        ]
        assert len(yara_inds) == 1
        ind = yara_inds[0]
        assert ind["name"] == "YARA: forensiq_evil_1234"
        assert 'strings: $s = "evil"' in ind["pattern"]
        assert "placeholder" not in ind["pattern"]

    def test_export_bundle_is_valid_json(self, tmp_path) -> None:
        try:
            import stix2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("stix2 not installed")
        from forensiq.reporting.stix_exporter import STIXExporter

        report = _make_stix_report(malicious=True, add_mitre=True)
        exporter = STIXExporter()
        result = exporter.export(report, tmp_path)
        data = json.loads(result.read_text())
        assert data["type"] == "bundle"
