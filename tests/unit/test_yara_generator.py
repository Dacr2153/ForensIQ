# FILE: tests/unit/test_yara_generator.py
"""Unit tests for YARA generator utility functions."""

from __future__ import annotations

import pytest

from forensiq.yara.generator import (
    _build_yara_rule_programmatic,
    _extract_iocs,
    _sanitize_rule_name,
    _validate_yara_rule,
)

# ── _sanitize_rule_name ───────────────────────────────────────────────────────


class TestSanitizeRuleName:
    def test_normal_name(self):
        result = _sanitize_rule_name("svchost.exe", 1234)
        assert result == "forensiq_svchost_1234"

    def test_strips_extension(self):
        result = _sanitize_rule_name("malware.dll", 999)
        assert "dll" not in result
        assert result.endswith("_999")

    def test_replaces_non_alnum(self):
        result = _sanitize_rule_name("evil proc#1", 5)
        assert "#" not in result
        assert " " not in result

    def test_numeric_prefix_gets_proc_prefix(self):
        result = _sanitize_rule_name("1mal.exe", 1)
        assert not result.startswith("forensiq_1")  # "1" triggers proc_ prefix
        assert "proc_" in result

    def test_unicode_normalized(self):
        result = _sanitize_rule_name("mälwäre.exe", 42)
        # Unicode stripped: "mlwre" or similar — should be valid ASCII
        assert result.isascii()

    def test_long_name_truncated(self):
        long_name = "a" * 100 + ".exe"
        result = _sanitize_rule_name(long_name, 1)
        # stem ≤ 50 chars
        stem = result[len("forensiq_"):result.rfind("_1")]
        assert len(stem) <= 50

    def test_starts_with_forensiq(self):
        result = _sanitize_rule_name("cmd.exe", 7)
        assert result.startswith("forensiq_")

    def test_ends_with_pid(self):
        result = _sanitize_rule_name("cmd.exe", 7777)
        assert result.endswith("_7777")


# ── _build_yara_rule_programmatic ─────────────────────────────────────────────


class TestBuildYaraRuleProgrammatic:
    def test_valid_rule_compiles(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        vector = _make_vector(name="evil.exe", threat_score=0.9)
        rule_text = _build_yara_rule_programmatic(
            "forensiq_evil_1234", vector, ["Process name: evil.exe"], "test desc"
        )
        is_valid, err = _validate_yara_rule(rule_text, "forensiq_evil_1234")
        assert is_valid is True, err

    def test_escapes_backslash_in_strings_and_meta(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        vector = _make_vector(name="evil.exe", threat_score=0.9)
        vector.suspicious_dll_paths = []
        rule_text = _build_yara_rule_programmatic(
            "forensiq_bs_1",
            vector,
            [
                "Suspicious DLL: C:\\Windows\\Temp\\evil.dll",
                "Network connection: [::1]:443 (ESTABLISHED)",
            ],
            "C:\\temp\\desc",
        )
        # YARA string literals must not contain raw backslashes or unescaped quotes
        assert 'description = "C:\\\\temp\\\\desc"' in rule_text
        is_valid, err = _validate_yara_rule(rule_text, "forensiq_bs_1")
        assert is_valid is True, err

    def test_ipv6_bracketed_host_extracted(self):
        """An IPv6 IOC '[::1]:443' must yield the host '::1', not '[' or ''."""
        vector = _make_vector(name="evil.exe", threat_score=0.9)
        rule_text = _build_yara_rule_programmatic(
            "forensiq_ipv6_1",
            vector,
            ["Network connection: [::1]:443 (ESTABLISHED)"],
            "test desc",
        )
        assert '$net_1 = "::1"' in rule_text


def _make_vector(name: str = "evil.exe", threat_score: float = 0.9):
    from unittest.mock import MagicMock

    v = MagicMock()
    v.name = name
    v.threat_score = threat_score
    return v


# ── _validate_yara_rule ───────────────────────────────────────────────────────


class TestValidateYaraRule:
    def test_valid_rule_returns_true(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        rule = """rule forensiq_valid_test {
    strings:
        $s = "malware"
    condition:
        $s
}"""
        is_valid, err = _validate_yara_rule(rule, "forensiq_valid_test")
        assert is_valid is True
        assert err == ""

    def test_invalid_rule_returns_false_with_error(self):
        try:
            import yara  # noqa: F401
        except ImportError:
            pytest.skip("yara-python not installed")

        rule = "this is not valid YARA at all"
        is_valid, err = _validate_yara_rule(rule, "bad_rule")
        assert is_valid is False
        assert len(err) > 0

    def test_empty_rule_returns_false(self):
        is_valid, err = _validate_yara_rule("", "empty")
        assert is_valid is False
        assert "Empty" in err

    def test_whitespace_rule_returns_false(self):
        is_valid, _err = _validate_yara_rule("   \n  ", "blank")
        assert is_valid is False


# ── _extract_iocs ─────────────────────────────────────────────────────────────


class TestExtractIOCs:
    """Tests for _extract_iocs."""

    def test_iocs_not_empty(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert len(iocs) > 0

    def test_process_name_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("payload.exe" in ioc for ioc in iocs)

    def test_malfind_hex_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("Memory bytes" in ioc or "4d5a" in ioc.lower() for ioc in iocs)

    def test_suspicious_dll_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("malicious.dll" in ioc or "Temp" in ioc for ioc in iocs)

    def test_external_connection_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("185.220.101.45" in ioc for ioc in iocs)

    def test_clean_process_has_minimal_iocs(self, clean_vector, sample_extraction) -> None:
        iocs = _extract_iocs(clean_vector, sample_extraction)
        assert len(iocs) >= 1
