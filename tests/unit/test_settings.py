# FILE: tests/unit/test_settings.py
"""Unit tests for forensiq.config.settings.Settings validators and methods."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from forensiq.config.settings import Settings


def _make_settings(**kwargs) -> Settings:
    """Create a Settings instance with sensible defaults and no real dirs."""
    base = {
        "REPORTS_DIR": "/tmp/forensiq_test_reports",
        "YARA_RULES_DIR": "/tmp/forensiq_test_yara",
    }
    base.update(kwargs)
    return Settings(**base)


# ── LOG_LEVEL validator ───────────────────────────────────────────────────────


class TestLogLevelValidator:
    def test_valid_info(self):
        s = _make_settings(LOG_LEVEL="info")
        assert s.LOG_LEVEL == "INFO"

    def test_valid_debug(self):
        s = _make_settings(LOG_LEVEL="DEBUG")
        assert s.LOG_LEVEL == "DEBUG"

    def test_valid_warning(self):
        s = _make_settings(LOG_LEVEL="WARNING")
        assert s.LOG_LEVEL == "WARNING"

    def test_valid_error(self):
        s = _make_settings(LOG_LEVEL="error")
        assert s.LOG_LEVEL == "ERROR"

    def test_valid_critical(self):
        s = _make_settings(LOG_LEVEL="CRITICAL")
        assert s.LOG_LEVEL == "CRITICAL"

    def test_invalid_log_level_raises(self):
        with pytest.raises(ValidationError):
            _make_settings(LOG_LEVEL="TRACE")


# ── LOG_FORMAT validator ──────────────────────────────────────────────────────


class TestLogFormatValidator:
    def test_valid_json(self):
        s = _make_settings(LOG_FORMAT="json")
        assert s.LOG_FORMAT == "json"

    def test_valid_console(self):
        s = _make_settings(LOG_FORMAT="CONSOLE")
        assert s.LOG_FORMAT == "console"

    def test_invalid_format_raises(self):
        with pytest.raises(ValidationError):
            _make_settings(LOG_FORMAT="xml")


# ── OLLAMA_BASE_URL validator ─────────────────────────────────────────────────


class TestOllamaUrlValidator:
    def test_valid_http(self):
        s = _make_settings(OLLAMA_BASE_URL="http://localhost:11434")
        assert s.OLLAMA_BASE_URL == "http://localhost:11434"

    def test_valid_https(self):
        s = _make_settings(OLLAMA_BASE_URL="https://api.example.com/ollama")
        assert "https://" in s.OLLAMA_BASE_URL

    def test_trailing_slash_removed(self):
        s = _make_settings(OLLAMA_BASE_URL="http://localhost:11434/")
        assert not s.OLLAMA_BASE_URL.endswith("/")

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValidationError):
            _make_settings(OLLAMA_BASE_URL="ftp://localhost:11434")


# ── Convenience methods ───────────────────────────────────────────────────────


class TestConvenienceMethods:
    def test_get_reports_dir_returns_path(self):
        s = _make_settings()
        assert isinstance(s.get_reports_dir(), Path)

    def test_get_yara_rules_dir_returns_path(self):
        s = _make_settings()
        assert isinstance(s.get_yara_rules_dir(), Path)

    def test_is_model_available_false_when_file_missing(self):
        s = _make_settings(MODEL_PATH="/nonexistent/model.joblib")
        assert s.is_model_available() is False

    def test_is_model_available_true_when_file_exists(self, tmp_path: Path):
        model_file = tmp_path / "model.joblib"
        model_file.write_bytes(b"fake")
        s = _make_settings(MODEL_PATH=str(model_file))
        assert s.is_model_available() is True

    def test_get_volatility_executable_raises_when_missing(self, monkeypatch, tmp_path):
        s = _make_settings(VOLATILITY_PATH="no_such_vol_exe")
        # Patch shutil.which AND Path.is_file so fallback paths are skipped too
        with patch("forensiq.config.settings.shutil.which", return_value=None), \
             patch("pathlib.Path.is_file", return_value=False):
            with pytest.raises(FileNotFoundError):
                s.get_volatility_executable()

    def test_get_volatility_executable_from_path(self, tmp_path: Path):
        fake_vol = tmp_path / "vol"
        fake_vol.write_text("#!/bin/sh\n")
        fake_vol.chmod(0o755)
        s = _make_settings(VOLATILITY_PATH=str(fake_vol))
        result = s.get_volatility_executable()
        assert str(fake_vol) in result

    def test_repr_does_not_raise(self):
        s = _make_settings()
        r = repr(s)
        assert "Settings(" in r

    def test_threat_threshold_default(self):
        s = _make_settings()
        assert 0.0 < s.THREAT_THRESHOLD < 1.0

    def test_threat_threshold_invalid_zero(self):
        with pytest.raises(ValidationError):
            _make_settings(THREAT_THRESHOLD=0.0)

    def test_threat_threshold_invalid_one(self):
        with pytest.raises(ValidationError):
            _make_settings(THREAT_THRESHOLD=1.0)


# ── DB_PATH env mapping ───────────────────────────────────────────────────────


class TestDbPath:
    def test_field_is_db_path_not_prefixed(self):
        """The field must be named DB_PATH so FORENSIQ_DB_PATH maps to it."""
        s = _make_settings()
        assert hasattr(s, "DB_PATH")
        assert not hasattr(s, "FORENSIQ_DB_PATH")

    def test_db_path_default_empty(self):
        s = _make_settings()
        assert s.DB_PATH == ""

    def test_db_path_env_var_binding(self, monkeypatch):
        """FORENSIQ_DB_PATH env var is bound to settings.DB_PATH via the prefix."""
        monkeypatch.setenv("FORENSIQ_DB_PATH", "/var/lib/forensiq/custom.db")
        s = Settings(_env_file=None)
        assert s.DB_PATH == "/var/lib/forensiq/custom.db"
