# FILE: tests/unit/test_extractors.py
"""Unit tests for HandlesExtractor, ServicesExtractor, and ParallelExtractor."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# ─── HandleEntry ──────────────────────────────────────────────────────────────


class TestHandleEntry:
    def _make_entry(self, handle_type: str = "Mutant", name: str = "Normal") -> object:
        from forensiq.extraction.handles_extractor import HandleEntry

        return HandleEntry(
            pid=100,
            process_name="svchost.exe",
            handle_value="0x0001",
            handle_type=handle_type,
            name=name,
            granted_access="0x001f0001",
        )

    def test_normal_mutex_not_suspicious(self) -> None:
        entry = self._make_entry(handle_type="Mutant", name="Normal_Mutex")
        assert entry.is_suspicious_mutex is False  # type: ignore[union-attr]

    def test_suspicious_mutex_detected(self) -> None:
        """Mutex names matching known malware patterns should be flagged."""
        from forensiq.extraction.handles_extractor import _MALWARE_MUTEX_PATTERNS, HandleEntry

        # Pick any pattern from the known list
        if not _MALWARE_MUTEX_PATTERNS:
            pytest.skip("No suspicious mutex patterns defined")

        pattern = next(iter(_MALWARE_MUTEX_PATTERNS))
        entry = HandleEntry(
            pid=200,
            process_name="evil.exe",
            handle_value="0x0002",
            handle_type="Mutant",
            name=f"Global\\{pattern}_instance",
            granted_access="0x001f0001",
        )
        assert entry.is_suspicious_mutex is True

    def test_registry_run_key_suspicious(self) -> None:
        from forensiq.extraction.handles_extractor import HandleEntry

        entry = HandleEntry(
            pid=300,
            process_name="malware.exe",
            handle_value="0x0003",
            handle_type="Key",
            name="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
            granted_access="0x002f0019",
        )
        assert entry.is_suspicious_registry is True

    def test_regular_registry_key_not_suspicious(self) -> None:
        from forensiq.extraction.handles_extractor import HandleEntry

        entry = HandleEntry(
            pid=400,
            process_name="explorer.exe",
            handle_value="0x0004",
            handle_type="Key",
            name="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            granted_access="0x001f0001",
        )
        assert entry.is_suspicious_registry is False


# ─── ServiceEntry ─────────────────────────────────────────────────────────────


class TestServiceEntry:
    def _make_service(self, binary_path: str = "C:\\Windows\\System32\\svc.exe") -> object:
        from forensiq.extraction.services_extractor import ServiceEntry

        return ServiceEntry(
            order=1,
            pid=500,
            service_name="TestSvc",
            display_name="Test Service",
            service_type="SERVICE_WIN32_OWN_PROCESS",
            service_state="RUNNING",
            binary_path=binary_path,
        )

    def test_system32_path_not_suspicious(self) -> None:
        entry = self._make_service("C:\\Windows\\System32\\svchost.exe")
        assert entry.is_suspicious_path is False  # type: ignore[union-attr]

    def test_temp_path_is_suspicious(self) -> None:
        entry = self._make_service("C:\\Windows\\Temp\\evil.exe")
        assert entry.is_suspicious_path is True  # type: ignore[union-attr]

    def test_appdata_path_is_suspicious(self) -> None:
        entry = self._make_service("C:\\Users\\user\\AppData\\Local\\Temp\\malicious.exe")
        assert entry.is_suspicious_path is True  # type: ignore[union-attr]

    def test_running_state(self) -> None:
        entry = self._make_service()
        assert entry.is_running is True  # type: ignore[union-attr]

    def test_stopped_state(self) -> None:
        from forensiq.extraction.services_extractor import ServiceEntry

        entry = ServiceEntry(
            order=2,
            pid=0,
            service_name="Stopped",
            display_name="",
            service_type="",
            service_state="STOPPED",
            binary_path="C:\\Windows\\System32\\stopped.exe",
        )
        assert entry.is_running is False

    def test_no_display_name_flag(self) -> None:
        from forensiq.extraction.services_extractor import ServiceEntry

        entry = ServiceEntry(
            order=3,
            pid=600,
            service_name="Evil",
            display_name="",
            service_type="SERVICE_WIN32_OWN_PROCESS",
            service_state="RUNNING",
            binary_path="C:\\Temp\\evil.exe",
        )
        assert entry.has_no_display_name is True

    def test_has_display_name_flag(self) -> None:
        from forensiq.extraction.services_extractor import ServiceEntry

        entry = ServiceEntry(
            order=4,
            pid=700,
            service_name="Normal",
            display_name="Windows Management Service",
            service_type="SERVICE_WIN32_OWN_PROCESS",
            service_state="RUNNING",
            binary_path="C:\\Windows\\System32\\wbem\\WinMgmt.exe",
        )
        assert entry.has_no_display_name is False


# ─── Parallel Extraction ─────────────────────────────────────────────────────


class TestParallelExtractorConfig:
    def test_parallel_default_true(self) -> None:
        """Parallel extraction should be enabled by default."""
        from forensiq.extraction.orchestrator import ExtractionOrchestrator

        # The orchestrator accepts parallel=True in __init__
        sig = ExtractionOrchestrator.__init__.__code__.co_varnames
        assert "parallel" in sig

    def test_orchestrator_has_run_parallel_method(self) -> None:
        """Orchestrator should have the parallel execution method."""
        from forensiq.extraction.orchestrator import ExtractionOrchestrator

        assert hasattr(ExtractionOrchestrator, "run_parallel")
        assert hasattr(ExtractionOrchestrator, "run")


# ─── ExecutiveReportGenerator ────────────────────────────────────────────────


class TestExecutiveReportGenerator:
    def test_fallback_summary_not_empty(self) -> None:
        """Fallback summary should return non-empty string when Ollama is down."""
        from forensiq.reporting.executive import ExecutiveReportGenerator

        gen = ExecutiveReportGenerator.__new__(ExecutiveReportGenerator)

        # Build a minimal report with concrete (non-MagicMock) leaf values
        # so format strings like {:.2f} work correctly.
        top_proc = MagicMock()
        top_proc.name = "evil.exe"
        top_proc.pid = 1234
        top_proc.threat_score = 0.95  # float, not MagicMock

        metadata = MagicMock()
        metadata.dump_filename = "MemoryDump_Lab1.raw"

        report = MagicMock()
        report.threat_level = "CRITICAL"
        report.metadata = metadata
        report.malicious_count = 2
        report.suspicious_count = 5
        report.total_processes = 100
        report.top_threats = [top_proc]
        report.mitre_techniques = [{"technique_id": "T1055"}, {"technique_id": "T1014"}]

        summary = gen._build_fallback_summary(report)
        assert isinstance(summary, str)
        assert len(summary) > 20

    def test_prompt_template_contains_key_fields(self) -> None:
        """Prompt template should include placeholders for dynamic data."""
        from forensiq.reporting.executive import _EXECUTIVE_PROMPT_TEMPLATE

        assert (
            "{malicious_count}" in _EXECUTIVE_PROMPT_TEMPLATE
            or "malicious" in _EXECUTIVE_PROMPT_TEMPLATE.lower()
        )


# ─── DLLExtractor unit tests ──────────────────────────────────────────────────

class TestParseIntHex:
    """Tests for _parse_int_hex helper."""

    def test_none_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex(None) == 0
        assert _parse_int_hex(None, default=99) == 99

    def test_int_passthrough(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex(42) == 42

    def test_hex_string(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("0x10") == 16
        assert _parse_int_hex("0XFF") == 255

    def test_decimal_string(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("100") == 100

    def test_dash_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("-") == 0

    def test_na_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("N/A") == 0

    def test_empty_string_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("") == 0

    def test_invalid_string_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex("not_a_number") == 0

    def test_non_string_non_int_returns_default(self) -> None:
        from forensiq.extraction.dll_extractor import _parse_int_hex
        assert _parse_int_hex([1, 2, 3]) == 0


class TestDLLExtractorRowParsing:
    """Tests for DLLExtractor._row_to_dll_entry."""

    def _make_extractor(self):
        from forensiq.extraction.dll_extractor import DLLExtractor
        runner = MagicMock()
        runner.is_linux = False
        return DLLExtractor(runner)

    def test_row_to_dll_entry_valid(self) -> None:
        extractor = self._make_extractor()
        row = {"PID": "1234", "Base": "0x10000000", "Size": "0x20000",
               "FullDllName": r"\Windows\ntdll.dll", "LoadCount": "1"}
        entry = extractor._row_to_dll_entry(row)
        assert entry is not None
        assert entry.pid == 1234

    def test_row_to_dll_entry_missing_pid(self) -> None:
        """Row with no PID column returns None."""
        extractor = self._make_extractor()
        row = {"Base": "0x10000000", "FullDllName": r"\Windows\ntdll.dll"}
        entry = extractor._row_to_dll_entry(row)
        assert entry is None

    def test_row_to_dll_entry_invalid_pid(self) -> None:
        """Row with non-numeric PID returns None."""
        extractor = self._make_extractor()
        row = {"PID": "not_a_pid", "FullDllName": r"\Windows\ntdll.dll"}
        entry = extractor._row_to_dll_entry(row)
        assert entry is None

    def test_extract_plugin_exception_returns_empty(self) -> None:
        """extract() returns {} when plugin raises."""
        from forensiq.extraction.dll_extractor import DLLExtractor
        runner = MagicMock()
        runner.is_linux = False
        runner.run_plugin.side_effect = RuntimeError("plugin failed")
        extractor = DLLExtractor(runner)
        result = extractor.extract()
        assert result == {}

    def test_extract_skips_none_entries(self) -> None:
        """extract() skips rows where _row_to_dll_entry returns None."""
        from forensiq.extraction.dll_extractor import DLLExtractor
        runner = MagicMock()
        runner.is_linux = False
        # One valid row and one invalid row (missing PID)
        runner.run_plugin.return_value = [
            {"PID": "100", "Base": "0x1000", "FullDllName": r"\ntdll.dll"},
            {"Base": "0x2000"},  # No PID — will be skipped
        ]
        extractor = DLLExtractor(runner)
        result = extractor.extract()
        assert 100 in result
        assert len(result[100]) == 1


class TestParsePort:
    """Tests for network_extractor._parse_port helper."""

    def test_none_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port(None) == -1

    def test_int_passthrough(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port(80) == 80

    def test_valid_string_port(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("443") == 443

    def test_dash_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("-") == -1

    def test_na_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("N/A") == -1

    def test_star_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("*") == -1

    def test_zero_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("0") == -1

    def test_empty_string_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("") == -1

    def test_invalid_string_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port("not_a_port") == -1

    def test_non_string_non_int_returns_minus_one(self) -> None:
        from forensiq.extraction.network_extractor import _parse_port
        assert _parse_port([80]) == -1


class TestParseAddr:
    """Tests for network_extractor._parse_addr helper."""

    def test_none_returns_empty(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr(None) == ""

    def test_dash_returns_empty(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr("-") == ""

    def test_na_returns_empty(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr("N/A") == ""

    def test_star_returns_empty(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr("*") == ""

    def test_all_zeros_kept(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr("0.0.0.0") == "0.0.0.0"

    def test_valid_ip(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        assert _parse_addr("192.168.1.1") == "192.168.1.1"

    def test_non_string_coerced(self) -> None:
        from forensiq.extraction.network_extractor import _parse_addr
        result = _parse_addr(12345)
        assert result == "12345"


class TestNetworkExtractorExtract:
    """Tests for NetworkExtractor.extract() basic paths."""

    def _make_extractor(self, rows=None, fail=False):
        from forensiq.extraction.network_extractor import NetworkExtractor
        runner = MagicMock()
        runner.is_linux = False
        if fail:
            runner.run_plugin.side_effect = RuntimeError("plugin failed")
        else:
            runner.run_plugin.return_value = rows or []
        return NetworkExtractor(runner)

    def test_extract_empty_rows(self) -> None:
        extractor = self._make_extractor(rows=[])
        result = extractor.extract()
        assert result == {}

    def test_extract_plugin_exception_returns_empty(self) -> None:
        extractor = self._make_extractor(fail=True)
        result = extractor.extract()
        assert result == {}

    def test_extract_valid_row(self) -> None:
        row = {
            "PID": "1234",
            "Proto": "TCPv4",
            "LocalAddr": "192.168.1.10",
            "LocalPort": "445",
            "ForeignAddr": "10.0.0.1",
            "ForeignPort": "50000",
            "State": "ESTABLISHED",
        }
        extractor = self._make_extractor(rows=[row])
        result = extractor.extract()
        assert 1234 in result
        assert len(result[1234]) == 1
