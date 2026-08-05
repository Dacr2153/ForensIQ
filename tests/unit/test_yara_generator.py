# FILE: tests/unit/test_yara_generator.py
"""Unit tests for YARA generator utility functions."""

from __future__ import annotations

import pytest

from forensiq.yara.generator import (
    _fix_common_yara_errors,
    _parse_yara_block,
    _sanitize_rule_name,
    _validate_yara_rule,
)
from forensiq.utils.exceptions import YARAGenerationError


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


# ── _parse_yara_block ─────────────────────────────────────────────────────────


class TestParseYaraBlock:
    def test_clean_rule_extracted(self):
        rule = """rule forensiq_evil_1234 {
    meta:
        author = "test"
    strings:
        $s1 = "evil"
    condition:
        any of them
}"""
        result = _parse_yara_block(rule)
        assert "forensiq_evil_1234" in result
        assert "condition" in result

    def test_markdown_fence_stripped(self):
        rule = """```yara
rule forensiq_test_1 {
    strings:
        $s = "test"
    condition:
        $s
}
```"""
        result = _parse_yara_block(rule)
        assert "forensiq_test_1" in result
        assert "```" not in result

    def test_preamble_stripped(self):
        rule = """Here is the YARA rule:

rule forensiq_test_2 {
    strings:
        $a = "hack"
    condition:
        $a
}"""
        result = _parse_yara_block(rule)
        assert result.startswith("rule ")

    def test_empty_response_raises(self):
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("")

    def test_whitespace_only_raises(self):
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("   \n\t  ")

    def test_no_rule_block_raises(self):
        with pytest.raises(YARAGenerationError):
            _parse_yara_block("This response has no YARA rule at all.")

    def test_generic_code_block_fence_stripped(self):
        rule = """```
rule forensiq_test_3 {
    strings:
        $x = "x"
    condition:
        $x
}
```"""
        result = _parse_yara_block(rule)
        assert "forensiq_test_3" in result


# ── _fix_common_yara_errors ───────────────────────────────────────────────────


class TestFixCommonYaraErrors:
    def test_float_in_meta_converted(self):
        text = 'threat_level = 0.65'
        result = _fix_common_yara_errors(text)
        # 0.65 * 10 = 6
        assert "0.65" not in result
        assert "6" in result

    def test_colon_after_rule_name_removed(self):
        text = "rule forensiq_evil_1 : {"
        result = _fix_common_yara_errors(text)
        assert "rule forensiq_evil_1 {" in result

    def test_no_change_when_already_correct(self):
        text = "rule forensiq_test_1 {\n    strings:\n        $s = \"ok\"\n    condition:\n        $s\n}"
        result = _fix_common_yara_errors(text)
        # Should not break anything already correct
        assert "rule forensiq_test_1 {" in result


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
        is_valid, err = _validate_yara_rule("   \n  ", "blank")
        assert is_valid is False
