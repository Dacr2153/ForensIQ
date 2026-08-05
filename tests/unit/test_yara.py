# FILE: tests/unit/test_yara.py
"""Unit tests for YARA generation utilities (no Ollama required)."""

from __future__ import annotations

import pytest

from forensiq.utils.exceptions import YARAGenerationError
from forensiq.yara.generator import (
    _extract_iocs,
    _parse_yara_block,
    _sanitize_rule_name,
    _validate_yara_rule,
)


class TestSanitizeRuleName:
    """Tests for _sanitize_rule_name."""

    def test_normal_process_name(self) -> None:
        name = _sanitize_rule_name("payload.exe", 3388)
        assert name == "forensiq_payload_3388"

    def test_special_chars_replaced(self) -> None:
        name = _sanitize_rule_name("my proc!@#.exe", 100)
        assert name.startswith("forensiq_")
        assert " " not in name
        assert "!" not in name

    def test_starts_with_digit_gets_prefix(self) -> None:
        name = _sanitize_rule_name("123bad.exe", 99)
        # Should not start with a digit after forensiq_
        parts = name.split("forensiq_")[1]
        assert not parts[0].isdigit() or name.startswith("forensiq_proc_")

    def test_result_is_valid_identifier(self) -> None:
        import re

        name = _sanitize_rule_name("complex name (1).exe", 777)
        # YARA identifiers: alphanumeric + underscore, start with letter or _
        assert re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name)

    def test_empty_name(self) -> None:
        name = _sanitize_rule_name("", 42)
        assert "forensiq_" in name
        assert "42" in name

    def test_unicode_name_normalized(self) -> None:
        name = _sanitize_rule_name("procéss.exe", 10)
        # Should be ASCII only
        assert name.isascii()


class TestParseYARABlock:
    """Tests for _parse_yara_block."""

    def test_clean_rule_extracted(self) -> None:
        rule_text = """rule forensiq_payload_3388 {
    meta:
        author = "ForensIQ"
    strings:
        $proc = "payload.exe" nocase
    condition:
        $proc
}"""
        result = _parse_yara_block(rule_text)
        assert result.startswith("rule forensiq_payload_3388")

    def test_strips_markdown_fences(self) -> None:
        rule_with_fences = """```yara
rule forensiq_payload_3388 {
    strings:
        $s = "payload"
    condition:
        $s
}
```"""
        result = _parse_yara_block(rule_with_fences)
        assert "```" not in result
        assert result.startswith("rule ")

    def test_empty_response_raises(self) -> None:
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("   \n\t  ")

    def test_no_rule_block_raises(self) -> None:
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("This is just some random text without any YARA rule.")

    def test_rule_with_preamble(self) -> None:
        response = """Here is your YARA rule:

rule forensiq_payload_3388 {
    strings:
        $s = "payload"
    condition:
        $s
}

I hope this helps!"""
        result = _parse_yara_block(response)
        assert result.startswith("rule forensiq_payload_3388")
        assert "I hope this helps" not in result


class TestValidateYARARule:
    """Tests for _validate_yara_rule (requires yara-python installed)."""

    def test_valid_rule_returns_true(self) -> None:
        rule = """rule forensiq_valid_test {
    meta:
        author = "test"
    strings:
        $s = "malicious" nocase
    condition:
        $s
}"""
        try:
            is_valid, error = _validate_yara_rule(rule, "forensiq_valid_test")
            assert is_valid is True
            assert error == ""
        except ImportError:
            pytest.skip("yara-python not installed")

    def test_invalid_rule_returns_false(self) -> None:
        # Missing closing brace — invalid YARA
        bad_rule = """rule forensiq_bad_test {
    strings:
        $s = "malicious"
    condition:
        $s
    // Missing closing brace!
"""
        try:
            is_valid, error = _validate_yara_rule(bad_rule, "forensiq_bad_test")
            assert is_valid is False
            assert len(error) > 0
        except ImportError:
            pytest.skip("yara-python not installed")

    def test_empty_rule_returns_false(self) -> None:
        try:
            is_valid, _ = _validate_yara_rule("", "empty_rule")
            assert is_valid is False
        except ImportError:
            pytest.skip("yara-python not installed")

    def test_rule_with_hex_strings(self) -> None:
        rule = """rule forensiq_hex_test {
    strings:
        $pe_header = { 4D 5A }
    condition:
        $pe_header
}"""
        try:
            is_valid, _ = _validate_yara_rule(rule, "forensiq_hex_test")
            assert is_valid is True
        except ImportError:
            pytest.skip("yara-python not installed")


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
        # Should include hex bytes from the malfind region
        assert any("Memory bytes" in ioc or "4d5a" in ioc.lower() for ioc in iocs)

    def test_suspicious_dll_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("malicious.dll" in ioc or "Temp" in ioc for ioc in iocs)

    def test_external_connection_in_iocs(self, malicious_vector, sample_extraction) -> None:
        iocs = _extract_iocs(malicious_vector, sample_extraction)
        assert any("185.220.101.45" in ioc for ioc in iocs)

    def test_clean_process_has_minimal_iocs(self, clean_vector, sample_extraction) -> None:
        iocs = _extract_iocs(clean_vector, sample_extraction)
        # At minimum: process name
        assert len(iocs) >= 1
        assert any("svchost" in ioc for ioc in iocs)
