# FILE: tests/unit/test_services_extractor.py
"""Unit tests for ServicesExtractor and ServiceEntry (uncovered portions)."""

from __future__ import annotations

from unittest.mock import MagicMock

from forensiq.extraction.services_extractor import (
    ServiceEntry,
    ServicesExtractor,
)

# ── ServiceEntry properties ───────────────────────────────────────────────────


class TestServiceEntryProperties:
    def _make(self, **kwargs) -> ServiceEntry:
        defaults = {
            "order": 1,
            "pid": 0,
            "service_name": "MySvc",
            "display_name": "My Service",
            "service_type": "Win32OwnProcess",
            "service_state": "STOPPED",
            "binary_path": "C:\\Windows\\System32\\svchost.exe",
        }
        defaults.update(kwargs)
        return ServiceEntry(**defaults)

    # is_suspicious_path

    def test_safe_system32_path_not_suspicious(self):
        s = self._make(binary_path="C:\\Windows\\System32\\svchost.exe")
        assert s.is_suspicious_path is False

    def test_temp_path_suspicious(self):
        s = self._make(binary_path="C:\\Users\\user\\AppData\\Local\\Temp\\evil.exe")
        assert s.is_suspicious_path is True

    def test_appdata_path_suspicious(self):
        s = self._make(binary_path="C:\\Users\\Alice\\AppData\\Roaming\\evil.exe")
        assert s.is_suspicious_path is True

    def test_users_path_suspicious(self):
        s = self._make(binary_path="C:\\Users\\hacker\\evil.exe")
        assert s.is_suspicious_path is True

    def test_public_path_suspicious(self):
        s = self._make(binary_path="C:\\Users\\Public\\malware.exe")
        assert s.is_suspicious_path is True

    def test_downloads_path_suspicious(self):
        s = self._make(binary_path="C:\\Users\\user\\Downloads\\payload.exe")
        assert s.is_suspicious_path is True

    def test_recycle_bin_suspicious(self):
        s = self._make(binary_path="C:\\$Recycle.Bin\\evil.exe")
        assert s.is_suspicious_path is True

    def test_empty_binary_path_suspicious(self):
        s = self._make(binary_path="")
        assert s.is_suspicious_path is True  # No path = suspicious

    def test_program_files_not_suspicious(self):
        s = self._make(binary_path="C:\\Program Files\\MyApp\\app.exe")
        assert s.is_suspicious_path is False

    # is_running

    def test_running_state_true(self):
        s = self._make(service_state="RUNNING")
        assert s.is_running is True

    def test_stopped_state_false(self):
        s = self._make(service_state="STOPPED")
        assert s.is_running is False

    def test_running_case_insensitive(self):
        s = self._make(service_state="running")
        assert s.is_running is True

    def test_start_pending_not_running(self):
        s = self._make(service_state="START_PENDING")
        assert s.is_running is False

    # has_no_display_name

    def test_empty_display_name_true(self):
        s = self._make(display_name="")
        assert s.has_no_display_name is True

    def test_display_equals_service_name_true(self):
        s = self._make(service_name="MySvc", display_name="MySvc")
        assert s.has_no_display_name is True

    def test_proper_display_name_false(self):
        s = self._make(service_name="MySvc", display_name="My Application Service")
        assert s.has_no_display_name is False


# ── ServicesExtractor._parse_row ─────────────────────────────────────────────


class TestParseRow:
    def setup_method(self):
        runner = MagicMock()
        self.extractor = ServicesExtractor(runner)

    def test_valid_row(self):
        row = {
            "ServiceName": "EvilSvc",
            "DisplayName": "Evil Service",
            "Type": "Win32OwnProcess",
            "State": "RUNNING",
            "BinaryPath": "C:\\Temp\\evil.exe",
            "PID": "1234",
            "Order": "5",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.service_name == "EvilSvc"
        assert entry.pid == 1234
        assert entry.order == 5
        assert entry.is_running is True

    def test_alternate_key_names(self):
        row = {
            "Name": "AltSvc",
            "Pid": "999",
            "Offset": "3",
            "ServiceType": "KernelDriver",
            "ServiceState": "STOPPED",
            "Binary": "C:\\Windows\\System32\\legit.sys",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.service_name == "AltSvc"
        assert entry.pid == 999

    def test_missing_service_name_returns_none(self):
        row = {"PID": "100", "State": "RUNNING"}
        entry = self.extractor._parse_row(row)
        assert entry is None

    def test_pid_na_treated_as_zero(self):
        row = {
            "ServiceName": "Svc1",
            "PID": "N/A",
            "State": "STOPPED",
            "BinaryPath": "C:\\Temp\\a.exe",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.pid == 0

    def test_empty_pid_treated_as_zero(self):
        row = {
            "ServiceName": "Svc2",
            "PID": "",
            "State": "STOPPED",
            "BinaryPath": "C:\\Temp\\b.exe",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.pid == 0


# ── ServicesExtractor.extract ─────────────────────────────────────────────────


class TestExtract:
    def _make_extractor(self, rows) -> ServicesExtractor:
        runner = MagicMock()
        runner.run_plugin.return_value = rows
        return ServicesExtractor(runner)

    def test_returns_empty_on_plugin_failure(self):
        runner = MagicMock()
        runner.run_plugin.side_effect = Exception("plugin failed")
        extractor = ServicesExtractor(runner)
        result = extractor.extract()
        assert result == []

    def test_returns_empty_on_no_rows(self):
        extractor = self._make_extractor([])
        result = extractor.extract()
        assert result == []

    def test_all_services_returned(self):
        rows = [
            {
                "ServiceName": "Svc1",
                "State": "RUNNING",
                "BinaryPath": "C:\\Windows\\System32\\svc1.exe",
            },
            {"ServiceName": "Svc2", "State": "STOPPED", "BinaryPath": "C:\\Temp\\evil.exe"},
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert len(result) == 2

    def test_invalid_row_skipped(self):
        rows = [
            {"State": "RUNNING"},  # No ServiceName
            {"ServiceName": "Svc1", "State": "RUNNING", "BinaryPath": "C:\\Windows\\svc.exe"},
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert len(result) == 1


# ── ServicesExtractor.get_suspicious ─────────────────────────────────────────


class TestGetSuspicious:
    def setup_method(self):
        runner = MagicMock()
        self.extractor = ServicesExtractor(runner)

    def _make_service(self, path: str, state: str) -> ServiceEntry:
        return ServiceEntry(
            order=1,
            pid=0,
            service_name="Svc",
            display_name="Service",
            service_type="Win32OwnProcess",
            service_state=state,
            binary_path=path,
        )

    def test_suspicious_and_running_included(self):
        s = self._make_service("C:\\Temp\\evil.exe", "RUNNING")
        result = self.extractor.get_suspicious([s])
        assert len(result) == 1

    def test_suspicious_but_stopped_excluded(self):
        s = self._make_service("C:\\Temp\\evil.exe", "STOPPED")
        result = self.extractor.get_suspicious([s])
        assert result == []

    def test_running_but_safe_path_excluded(self):
        s = self._make_service("C:\\Windows\\System32\\legit.exe", "RUNNING")
        result = self.extractor.get_suspicious([s])
        assert result == []

    def test_empty_list_returns_empty(self):
        result = self.extractor.get_suspicious([])
        assert result == []
