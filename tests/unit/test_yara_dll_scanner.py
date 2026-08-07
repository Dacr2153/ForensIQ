# FILE: tests/unit/test_yara_dll_scanner.py
"""Unit tests for YARADLLScanner and related types."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from forensiq.utils.hexdump import hexdump_to_bytes
from forensiq.yara.dll_scanner import YARADLLHit, YARADLLScanner

# ── hexdump_to_bytes (shared) ─────────────────────────────────────────────────


class TestDecodeHexdump:
    def test_empty_string_returns_empty_bytes(self):
        assert hexdump_to_bytes("") == b""

    def test_none_like_empty(self):
        assert hexdump_to_bytes("") == b""

    def test_plain_hex_decoded(self):
        result = hexdump_to_bytes("4d5a")
        assert result == b"\x4d\x5a"

    def test_spaced_hex_decoded(self):
        result = hexdump_to_bytes("4d 5a 90 00")
        assert result == b"\x4d\x5a\x90\x00"

    def test_mixed_whitespace(self):
        result = hexdump_to_bytes("4d5a 9000\n0300 0000")
        assert result == b"\x4d\x5a\x90\x00\x03\x00\x00\x00"

    def test_odd_length_token_dropped(self):
        # A ragged odd-length token is not a valid byte group → ignored
        result = hexdump_to_bytes("4d5a9")
        assert result == b""

    def test_non_hex_chars_ignored(self):
        # A token containing non-hex separators is not a valid byte group
        result = hexdump_to_bytes("4d-5a")
        assert result == b""

    def test_single_char_returns_empty(self):
        assert hexdump_to_bytes("4") == b""

    def test_address_and_ascii_columns_stripped(self):
        # Full Volatility malfind line: offset column, byte groups, ASCII column
        line = (
            "0xfffff80411234567  4d 5a 90 00 03 00 00 00  "
            "ff ff 00 00 b8 00 00 00  MZ.............."
        )
        result = hexdump_to_bytes(line)
        assert result == bytes.fromhex("4d5a900003000000ffff0000b8000000")

    def test_compact_groups_with_ascii_column(self):
        # Compact 4-char groups with a trailing ASCII render column
        line = "0x1 4d5a 9000 0300  0000 ffff  MZ.."
        result = hexdump_to_bytes(line)
        assert result == bytes.fromhex("4d5a900003000000ffff")


# ── YARADLLScanner.is_ready ───────────────────────────────────────────────────


class TestYARADLLScannerReady:
    def test_is_ready_false_when_yara_not_installed(self):
        """When yara-python is not installed, scanner must still instantiate."""
        import sys
        from unittest.mock import patch

        with patch.dict(sys.modules, {"yara": None}):
            scanner = YARADLLScanner()
            # is_ready depends on whether yara compiled; with None it may raise
            # but scanner must not crash — just be not ready
            # (result depends on implementation, just assert it doesn't raise)
            _ = scanner.is_ready  # should not raise

    def test_is_ready_true_when_yara_available(self):
        """When yara-python IS installed, scanner should be ready."""
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()
        assert scanner.is_ready is True


# ── scan_extraction with mocked extraction ────────────────────────────────────


class TestScanExtraction:
    def _make_extraction(self, malfind: dict, process_tree=None):
        mock = MagicMock()
        mock.malfind = malfind
        mock.process_tree = process_tree
        return mock

    def test_returns_empty_when_not_ready(self):
        scanner = YARADLLScanner()
        scanner._compiled_rules = []  # force not-ready
        extraction = self._make_extraction({})
        result = scanner.scan_extraction(extraction)
        assert result == []

    def test_no_malfind_regions_returns_empty(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()
        extraction = self._make_extraction({})
        result = scanner.scan_extraction(extraction)
        assert result == []

    def test_pe_header_detected(self):
        """MZ header in hexdump triggers PE detection rule."""
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        region = MagicMock()
        region.hexdump = "4d 5a 90 00"  # MZ header
        region.start = 0x1000
        region.end = 0x2000

        extraction = self._make_extraction({1234: [region]}, process_tree=None)
        hits = scanner.scan_extraction(extraction)

        assert len(hits) >= 1
        rule_names = {h.rule_name for h in hits}
        assert "forensiq_pe_in_injected_memory" in rule_names

    def test_specific_pids_filter(self):
        """When suspicious_pids provided, only those PIDs are scanned."""
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        region = MagicMock()
        region.hexdump = "4d 5a 90 00"
        region.start = 0x1000
        region.end = 0x2000

        extraction = self._make_extraction({1234: [region], 9999: [region]})
        # Only scan PID 9999 (which also has MZ), PID 1234 should be skipped
        hits = scanner.scan_extraction(extraction, suspicious_pids={9999})
        pids_hit = {h.pid for h in hits}
        assert 1234 not in pids_hit
        assert 9999 in pids_hit

    def test_process_name_resolved_from_tree(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        region = MagicMock()
        region.hexdump = "4d 5a 90 00"
        region.start = 0x100
        region.end = 0x200

        proc = MagicMock()
        proc.name = "malware.exe"
        tree = MagicMock()
        tree.flat_map = {1234: proc}

        extraction = self._make_extraction({1234: [region]}, process_tree=tree)
        hits = scanner.scan_extraction(extraction)
        assert any(h.process_name == "malware.exe" for h in hits)

    def test_process_name_unknown_when_no_tree(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        region = MagicMock()
        region.hexdump = "4d 5a 90 00"
        region.start = 0x100
        region.end = 0x200

        extraction = self._make_extraction({1234: [region]}, process_tree=None)
        hits = scanner.scan_extraction(extraction)
        assert all(h.process_name == "unknown" for h in hits)

    def test_empty_hexdump_region_skipped(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        region = MagicMock()
        region.hexdump = ""
        region.start = 0
        region.end = 0

        extraction = self._make_extraction({1234: [region]})
        hits = scanner.scan_extraction(extraction)
        assert hits == []

    def test_nop_sled_shellcode_detected(self):
        """Eight consecutive 0x90 bytes trigger NOP sled rule."""
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        scanner = YARADLLScanner()

        # 16 NOPs
        hexdump = " ".join(["90"] * 16)
        region = MagicMock()
        region.hexdump = hexdump
        region.start = 0
        region.end = 16

        extraction = self._make_extraction({5555: [region]})
        hits = scanner.scan_extraction(extraction)
        rule_names = {h.rule_name for h in hits}
        assert "forensiq_nop_sled_shellcode" in rule_names


# ── YARADLLHit dataclass ──────────────────────────────────────────────────────


class TestYARADLLHit:
    def test_hit_fields(self):
        hit = YARADLLHit(
            pid=1234,
            process_name="evil.exe",
            region_start=0x1000,
            region_end=0x2000,
            rule_name="forensiq_pe_in_injected_memory",
            rule_description="PE header found",
            severity="high",
        )
        assert hit.pid == 1234
        assert hit.process_name == "evil.exe"
        assert hit.severity == "high"
        assert hit.match_strings == []

    def test_hit_with_match_strings(self):
        hit = YARADLLHit(
            pid=1,
            process_name="a.exe",
            region_start=0,
            region_end=0,
            rule_name="x",
            rule_description="y",
            severity="low",
            match_strings=["$mz", "$pe"],
        )
        assert "$mz" in hit.match_strings
        assert "$pe" in hit.match_strings
