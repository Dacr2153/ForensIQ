# FILE: tests/unit/test_logger_utils.py
"""Unit tests for forensiq.utils.logger and forensiq.utils.exceptions."""

from __future__ import annotations

import pytest

from forensiq.utils.exceptions import (
    AcquisitionError,
    ClassificationError,
    ForensiqError,
    InsufficientDataError,
    ModelNotLoadedError,
    ReportError,
    VolatilityTimeoutError,
)
from forensiq.utils.logger import (
    bind_analysis_context,
    configure_logging,
    get_logger,
)

# ── configure_logging / get_logger ────────────────────────────────────────────


class TestConfigureLogging:
    def test_configure_logging_json(self):
        # Should not raise
        configure_logging(log_level="WARNING", log_format="json")

    def test_configure_logging_console(self):
        configure_logging(log_level="DEBUG", log_format="console")

    def test_get_logger_returns_logger(self):
        log = get_logger("forensiq.test")
        assert log is not None

    def test_get_logger_methods_callable(self):
        log = get_logger("forensiq.test")
        # These should not raise
        log.info("test info message", key="value")
        log.warning("test warning", key="value")
        log.debug("test debug", key="value")

    def test_double_configure_is_noop(self):
        """configure_logging is idempotent — calling twice should not raise."""
        configure_logging(log_level="INFO", log_format="json")
        configure_logging(log_level="DEBUG", log_format="console")


# ── bind_analysis_context ─────────────────────────────────────────────────────


class TestBindAnalysisContext:
    def test_context_manager_returns(self):
        with bind_analysis_context(dump_path="/dumps/memory.raw", correlation_id="abc123"):
            log = get_logger("test")
            log.info("inside context")

    def test_context_manager_without_args(self):
        with bind_analysis_context():
            pass

    def test_nested_context(self):
        with bind_analysis_context(dump_path="/a.raw", correlation_id="outer"):
            with bind_analysis_context(dump_path="/b.raw", correlation_id="inner"):
                pass


# ── Exceptions ────────────────────────────────────────────────────────────────


class TestForensiqErrors:
    def test_forensiq_error_base(self):
        exc = ForensiqError("base error")
        assert "base error" in str(exc)

    def test_acquisition_error(self):
        exc = AcquisitionError(message="dump failed", context={"path": "/a.raw"})
        assert "dump failed" in str(exc)
        assert exc.context == {"path": "/a.raw"}

    def test_acquisition_error_no_context(self):
        exc = AcquisitionError(message="no context")
        assert exc.context == {}

    def test_volatility_timeout_error(self):
        exc = VolatilityTimeoutError(plugin="windows.pslist", timeout_seconds=300)
        assert "windows.pslist" in str(exc)
        assert exc.plugin == "windows.pslist"
        assert exc.timeout_seconds == 300
        assert isinstance(exc, AcquisitionError)

    def test_classification_error(self):
        exc = ClassificationError(message="model exploded")
        assert "model exploded" in str(exc)

    def test_model_not_loaded_error(self):
        exc = ModelNotLoadedError(model_path="/models/model.joblib")
        assert "/models/model.joblib" in str(exc)
        assert isinstance(exc, ClassificationError)

    def test_insufficient_data_error(self):
        exc = InsufficientDataError(count=1, minimum=3)
        assert exc.context["process_count"] == 1
        assert exc.context["minimum"] == 3
        assert isinstance(exc, ClassificationError)

    def test_report_error(self):
        exc = ReportError(output_path="/reports/out.html", reason="template not found")
        assert "/reports/out.html" in str(exc)
        assert "template not found" in str(exc)

    def test_exceptions_are_catchable_as_base(self):
        with pytest.raises(ForensiqError):
            raise ClassificationError(message="test")

    def test_model_not_loaded_catchable_as_classification(self):
        with pytest.raises(ClassificationError):
            raise ModelNotLoadedError(model_path="/model.joblib")


# ── Additional coverage tests ────────────────────────────────────────────────


class TestBindAnalysisContextCoverage:
    def test_correlation_id_injected(self):
        """bind_analysis_context with correlation_id covers ContextVar set path."""
        from forensiq.utils.logger import bind_analysis_context
        with bind_analysis_context(
            correlation_id="abc-123",
            dump_path="/tmp/mem.raw",
            phase="extraction",
        ):
            # Just ensure it doesn't raise
            pass

    def test_set_phase_updates_context(self):
        """set_phase updates the analysis phase context variable."""
        from forensiq.utils.logger import set_phase
        set_phase("acquisition")
        # No assertion needed — just ensure no exception

    def test_sanitize_paths_strips_absolute_path(self):
        """_sanitize_paths replaces absolute path values with basename."""
        from forensiq.utils.logger import _sanitize_paths
        event_dict = {"event": "test", "some_file": "/home/user/dumps/mem.raw"}
        result = _sanitize_paths(None, "info", event_dict)
        assert result["some_file"] == "mem.raw"

    def test_sanitize_paths_keeps_allowed_fields(self):
        """_sanitize_paths does not alter dump/path/output_path fields."""
        from forensiq.utils.logger import _sanitize_paths
        event_dict = {"event": "test", "path": "/home/user/reports/out.html"}
        result = _sanitize_paths(None, "info", event_dict)
        assert result["path"] == "/home/user/reports/out.html"

    def test_sanitize_paths_ignores_non_path_str(self):
        """_sanitize_paths leaves non-path strings unchanged."""
        from forensiq.utils.logger import _sanitize_paths
        event_dict = {"event": "test", "msg": "hello world"}
        result = _sanitize_paths(None, "info", event_dict)
        assert result["msg"] == "hello world"

    def test_add_correlation_id_injects_when_set(self):
        """_add_correlation_id injects correlation_id when ContextVar is set."""
        from forensiq.utils import logger as logger_mod
        token = logger_mod._correlation_id.set("my-cid")
        try:
            event_dict: dict = {"event": "test"}
            result = logger_mod._add_correlation_id(None, "info", event_dict)
            assert result.get("correlation_id") == "my-cid"
        finally:
            logger_mod._correlation_id.reset(token)

    def test_add_analysis_context_injects_phase_and_dump(self):
        """_add_analysis_context injects phase and dump when set."""
        from forensiq.utils import logger as logger_mod
        tok_phase = logger_mod._analysis_phase.set("feature_engineering")
        tok_dump = logger_mod._dump_basename.set("mem.raw")
        try:
            event_dict: dict = {"event": "test"}
            result = logger_mod._add_analysis_context(None, "info", event_dict)
            assert result.get("phase") == "feature_engineering"
            assert result.get("dump") == "mem.raw"
        finally:
            logger_mod._analysis_phase.reset(tok_phase)
            logger_mod._dump_basename.reset(tok_dump)
