# FILE: tests/unit/test_exceptions.py
"""Unit tests for ForensIQ custom exception hierarchy."""

from __future__ import annotations

import pytest

from forensiq.utils.exceptions import (
    AcquisitionError,
    ClassificationError,
    ExtractionError,
    FeatureEngineeringError,
    ForensiqError,
    LLMError,
    MissingPluginOutputError,
    ModelNotLoadedError,
    OllamaConnectionError,
    OllamaModelNotFoundError,
    OllamaTimeoutError,
    ReportError,
    UnsupportedProfileError,
    VolatilityParseError,
    VolatilityTimeoutError,
    YARACompilationError,
    YARAError,
    YARAGenerationError,
)


class TestForensiqError:
    def test_message_is_exception_str(self):
        exc = ForensiqError("test message")
        assert str(exc) == "test message"

    def test_default_correlation_id_empty(self):
        exc = ForensiqError("msg")
        assert exc.correlation_id == ""

    def test_custom_correlation_id(self):
        exc = ForensiqError("msg", correlation_id="abc-123")
        assert exc.correlation_id == "abc-123"

    def test_context_stored(self):
        exc = ForensiqError("msg", context={"key": "value"})
        assert exc.context["key"] == "value"

    def test_default_context_is_empty_dict(self):
        exc = ForensiqError("msg")
        assert exc.context == {}


class TestVolatilityTimeoutError:
    def test_message_contains_timeout(self):
        exc = VolatilityTimeoutError(timeout_seconds=30, plugin="pslist")
        assert "30" in str(exc)
        assert "pslist" in str(exc)

    def test_context_fields(self):
        exc = VolatilityTimeoutError(timeout_seconds=60, plugin="dlllist")
        assert exc.context["timeout_seconds"] == 60
        assert exc.context["plugin"] == "dlllist"

    def test_is_acquisition_error(self):
        exc = VolatilityTimeoutError(timeout_seconds=10, plugin="netscan")
        assert isinstance(exc, AcquisitionError)


class TestVolatilityParseError:
    def test_message_contains_plugin(self):
        exc = VolatilityParseError(plugin="pslist", raw_output='{"bad": json')
        assert "pslist" in str(exc)

    def test_raw_output_truncated_when_long(self):
        long_output = "x" * 300
        exc = VolatilityParseError(plugin="pslist", raw_output=long_output)
        assert "..." in str(exc)
        assert exc.plugin == "pslist"

    def test_short_output_not_truncated(self):
        exc = VolatilityParseError(plugin="pslist", raw_output="short")
        assert "..." not in str(exc)


class TestUnsupportedProfileError:
    def test_message_contains_dump_path(self):
        exc = UnsupportedProfileError(dump_path="/tmp/mem.raw")
        assert "/tmp/mem.raw" in str(exc)

    def test_context_has_dump_path(self):
        exc = UnsupportedProfileError(dump_path="/tmp/mem.raw")
        assert exc.context["dump_path"] == "/tmp/mem.raw"


class TestMissingPluginOutputError:
    def test_message_contains_plugin_and_dump(self):
        exc = MissingPluginOutputError(plugin="pslist", dump_path="/tmp/mem.raw")
        assert "pslist" in str(exc)
        assert "/tmp/mem.raw" in str(exc)

    def test_is_extraction_error(self):
        exc = MissingPluginOutputError(plugin="pslist", dump_path="/tmp/mem.raw")
        assert isinstance(exc, ExtractionError)


class TestFeatureEngineeringError:
    def test_message_contains_pid_and_name(self):
        exc = FeatureEngineeringError(pid=1234, process_name="evil.exe", reason="NaN value")
        assert "1234" in str(exc)
        assert "evil.exe" in str(exc)
        assert "NaN value" in str(exc)

    def test_context_fields(self):
        exc = FeatureEngineeringError(pid=99, process_name="bad.exe", reason="missing")
        assert exc.context["pid"] == 99
        assert exc.context["process_name"] == "bad.exe"


class TestModelNotLoadedError:
    def test_is_classification_error(self):
        exc = ModelNotLoadedError(model_path="/tmp/model.joblib")
        assert isinstance(exc, ClassificationError)
        assert "/tmp/model.joblib" in str(exc)


class TestYARACompilationError:
    def test_message_contains_rule_name_and_error(self):
        exc = YARACompilationError(
            rule_name="forensiq_evil",
            compile_error="syntax error",
            rule_text="rule forensiq_evil { }"
        )
        assert "forensiq_evil" in str(exc)
        assert "syntax error" in str(exc)

    def test_rule_text_truncated_in_context(self):
        exc = YARACompilationError(
            rule_name="r",
            compile_error="err",
            rule_text="x" * 400,
        )
        assert len(exc.context["rule_text_preview"]) == 300

    def test_is_yara_error(self):
        exc = YARACompilationError(rule_name="r", compile_error="e", rule_text="t")
        assert isinstance(exc, YARAError)


class TestOllamaErrors:
    def test_ollama_connection_error_message(self):
        exc = OllamaConnectionError(base_url="http://localhost:11434")
        assert "http://localhost:11434" in str(exc)
        assert isinstance(exc, LLMError)

    def test_ollama_timeout_error_message(self):
        exc = OllamaTimeoutError(timeout_seconds=120, model="llama3")
        assert "120" in str(exc)
        assert "llama3" in str(exc)

    def test_ollama_model_not_found_message(self):
        exc = OllamaModelNotFoundError(model="llama3:70b")
        assert "llama3:70b" in str(exc)
        assert isinstance(exc, LLMError)


class TestReportError:
    def test_is_forensiq_error(self):
        exc = ReportError(output_path="/tmp/report.html", reason="template missing")
        assert isinstance(exc, ForensiqError)
        assert "template missing" in str(exc)
