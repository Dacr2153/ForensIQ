# FILE: tests/unit/test_handles_extractor.py
"""Unit tests for HandlesExtractor and HandleEntry."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from forensiq.extraction.handles_extractor import (
    HandleEntry,
    HandlesExtractor,
    _MALWARE_MUTEX_PATTERNS,
    _SUSPICIOUS_REG_PATHS,
)


# ── HandleEntry properties ────────────────────────────────────────────────────


class TestHandleEntryProperties:
    def _make_handle(self, handle_type: str, name: str) -> HandleEntry:
        return HandleEntry(
            pid=1234,
            process_name="evil.exe",
            handle_value="0x4",
            handle_type=handle_type,
            name=name,
            granted_access="0x1f0001",
        )

    # is_suspicious_mutex

    def test_mutex_with_malware_pattern_is_suspicious(self):
        entry = self._make_handle("Mutant", "Global\\gh0st_main")
        assert entry.is_suspicious_mutex is True

    def test_mutex_with_global_pattern_is_suspicious(self):
        entry = self._make_handle("Mutex", "Global\\anysuffix")
        assert entry.is_suspicious_mutex is True

    def test_clean_mutex_not_suspicious(self):
        entry = self._make_handle("Mutant", "Local\\MyAppMutex")
        assert entry.is_suspicious_mutex is False

    def test_non_mutex_type_not_suspicious(self):
        entry = self._make_handle("Event", "Global\\gh0st_main")
        assert entry.is_suspicious_mutex is False

    def test_mutex_case_insensitive(self):
        entry = self._make_handle("MUTANT", "GLOBAL\\njrat_instance")
        assert entry.is_suspicious_mutex is True

    # is_suspicious_registry

    def test_run_registry_key_suspicious(self):
        entry = self._make_handle("Key", "\\REGISTRY\\MACHINE\\SOFTWARE\\CurrentVersion\\Run\\malware")
        assert entry.is_suspicious_registry is True

    def test_runonce_registry_key_suspicious(self):
        entry = self._make_handle("Key", "HKLM\\SOFTWARE\\CurrentVersion\\RunOnce\\badkey")
        assert entry.is_suspicious_registry is True

    def test_services_registry_suspicious(self):
        entry = self._make_handle("Key", "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\evil")
        assert entry.is_suspicious_registry is True

    def test_winlogon_registry_suspicious(self):
        # Pattern requires "\\winlogon\\" — must have trailing backslash
        entry = self._make_handle("Key", "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\subkey")
        assert entry.is_suspicious_registry is True

    def test_clean_registry_key_not_suspicious(self):
        entry = self._make_handle("Key", "\\REGISTRY\\MACHINE\\SOFTWARE\\SafeApp\\Config")
        assert entry.is_suspicious_registry is False

    def test_non_key_type_not_suspicious_registry(self):
        entry = self._make_handle("Mutant", "\\run\\malware")
        assert entry.is_suspicious_registry is False

    def test_registry_case_insensitive(self):
        entry = self._make_handle("KEY", "HKLM\\SOFTWARE\\CURRENTVERSION\\RUN")
        assert entry.is_suspicious_registry is True


# ── HandlesExtractor._parse_row ───────────────────────────────────────────────


class TestParseRow:
    def setup_method(self):
        runner = MagicMock()
        self.extractor = HandlesExtractor(runner)

    def test_parse_valid_row(self):
        row = {
            "PID": "1234",
            "Type": "Mutant",
            "Name": "Global\\evil",
            "HandleValue": "0x4",
            "ImageFileName": "malware.exe",
            "GrantedAccess": "0x1f0001",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.pid == 1234
        assert entry.handle_type == "Mutant"
        assert entry.name == "Global\\evil"

    def test_parse_row_with_alternate_keys(self):
        row = {
            "Pid": "4567",
            "HandleType": "Key",
            "HandleName": "\\Run\\evil",
            "Handle": "0x8",
            "Process": "svchost.exe",
        }
        entry = self.extractor._parse_row(row)
        assert entry is not None
        assert entry.pid == 4567
        assert entry.handle_type == "Key"

    def test_parse_row_no_pid_returns_none(self):
        row = {"Type": "Mutant", "Name": "foo"}
        entry = self.extractor._parse_row(row)
        assert entry is None

    def test_parse_row_invalid_pid_returns_none(self):
        row = {"PID": "not_a_number", "Type": "Mutant", "Name": "foo"}
        entry = self.extractor._parse_row(row)
        assert entry is None


# ── HandlesExtractor.extract ──────────────────────────────────────────────────


class TestHandlesExtractorExtract:
    def _make_extractor(self, rows) -> HandlesExtractor:
        runner = MagicMock()
        runner.run_plugin.return_value = rows
        return HandlesExtractor(runner)

    def test_returns_empty_on_plugin_failure(self):
        runner = MagicMock()
        runner.run_plugin.side_effect = Exception("plugin crashed")
        extractor = HandlesExtractor(runner)
        result = extractor.extract()
        assert result == {}

    def test_returns_empty_when_no_rows(self):
        extractor = self._make_extractor([])
        result = extractor.extract()
        assert result == {}

    def test_suspicious_mutex_included(self):
        rows = [
            {
                "PID": "1234",
                "Type": "Mutant",
                "Name": "Global\\gh0st",
                "HandleValue": "0x4",
                "ImageFileName": "evil.exe",
                "GrantedAccess": "0x1f",
            }
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert 1234 in result
        assert len(result[1234]) == 1

    def test_clean_handle_excluded(self):
        rows = [
            {
                "PID": "1234",
                "Type": "Event",
                "Name": "Local\\NormalEvent",
                "HandleValue": "0x8",
                "ImageFileName": "notepad.exe",
                "GrantedAccess": "0x1f",
            }
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert result == {}

    def test_suspicious_registry_included(self):
        rows = [
            {
                "PID": "999",
                "Type": "Key",
                "Name": "\\SOFTWARE\\CurrentVersion\\Run\\badkey",
                "HandleValue": "0xc",
                "ImageFileName": "malware.exe",
                "GrantedAccess": "0x2000000",
            }
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert 999 in result

    def test_multiple_pids_grouped(self):
        rows = [
            {
                "PID": "100",
                "Type": "Mutant",
                "Name": "Global\\poison_instance",
                "HandleValue": "0x4",
                "ImageFileName": "a.exe",
                "GrantedAccess": "0x1f",
            },
            {
                "PID": "200",
                "Type": "Key",
                "Name": "\\Run\\backdoor",
                "HandleValue": "0x8",
                "ImageFileName": "b.exe",
                "GrantedAccess": "0x2",
            },
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert 100 in result
        assert 200 in result

    def test_invalid_row_skipped(self):
        rows = [
            {"Type": "Mutant", "Name": "Global\\gh0st"},  # No PID
        ]
        extractor = self._make_extractor(rows)
        result = extractor.extract()
        assert result == {}
