# FILE: src/forensiq/config/settings.py
"""ForensIQ application configuration via Pydantic BaseSettings.

All settings are loaded from environment variables with the FORENSIQ_ prefix.
Settings can be overridden via a .env file in the project root.

Usage:
    from forensiq.config.settings import get_settings

    settings = get_settings()
    vol_path = settings.VOLATILITY_PATH
    threshold = settings.THREAT_THRESHOLD

The settings object is a cached singleton — get_settings() always returns
the same instance for the lifetime of the process.
"""

from __future__ import annotations

import shutil
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ForensIQ application settings.

    All fields correspond to FORENSIQ_* environment variables.
    See .env.example for documentation of each variable.
    """

    model_config = SettingsConfigDict(
        # Look for .env in the current working directory and parent dirs
        env_file=".env",
        env_prefix="FORENSIQ_",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Allow extra fields without raising an error (forward compatibility)
        extra="ignore",
    )

    # ─── Volatility 3 ─────────────────────────────────────────────────────────
    VOLATILITY_PATH: str = Field(
        default="vol",
        description="Path to the vol executable (Volatility 3 CLI). "
        "Defaults to 'vol' (must be in PATH).",
    )

    # ─── Ollama LLM ────────────────────────────────────────────────────────────
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434",
        description="Base URL of the Ollama API server.",
    )
    OLLAMA_MODEL: str = Field(
        default="mistral:latest",
        description="Ollama model to use for YARA rule generation.",
    )
    OLLAMA_TIMEOUT: Annotated[int, Field(gt=0, le=600)] = Field(
        default=120,
        description="Timeout in seconds for Ollama API requests.",
    )

    # ─── ML Model ─────────────────────────────────────────────────────────────
    MODEL_PATH: str = Field(
        default="./ml/data/forensiq_model.joblib",
        description="Path to the trained XGBoost model (joblib format).",
    )

    # ─── Output Directories ───────────────────────────────────────────────────
    REPORTS_DIR: str = Field(
        default="./reports",
        description="Directory where HTML forensic reports are saved.",
    )
    YARA_RULES_DIR: str = Field(
        default="./yara_rules",
        description="Directory where generated YARA rules are saved.",
    )

    # ─── Analysis Limits ──────────────────────────────────────────────────────
    MAX_PROCESSES_ANALYZE: Annotated[int, Field(ge=0)] = Field(
        default=500,
        description="Max number of processes to analyze. 0 = unlimited.",
    )

    # ─── Detection ────────────────────────────────────────────────────────────
    THREAT_THRESHOLD: Annotated[float, Field(gt=0.0, lt=1.0)] = Field(
        default=0.65,
        description="Probability threshold above which a process is classified as malicious.",
    )
    YARA_GENERATE: bool = Field(
        default=True,
        description="Enable YARA rule generation via Ollama LLM.",
    )

    # ─── External Integrations (optional) ────────────────────────────────────
    VT_API_KEY: str = Field(
        default="",
        description="VirusTotal API v3 key. Leave empty to disable VT lookups.",
    )
    FORENSIQ_DB_PATH: str = Field(
        default="",
        description="SQLite database path for analysis history. Empty = ~/.forensiq/forensiq.db",
    )

    # ─── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL.",
    )
    LOG_FORMAT: str = Field(
        default="console",
        description="Log format: 'json' for production, 'console' for development.",
    )

    # ─── Validators ───────────────────────────────────────────────────────────

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log level is a valid Python logging level."""
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of: {', '.join(sorted(valid))}")
        return upper

    @field_validator("LOG_FORMAT")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        """Ensure log format is 'json' or 'console'."""
        lower = v.lower()
        if lower not in {"json", "console"}:
            raise ValueError("LOG_FORMAT must be 'json' or 'console'")
        return lower

    @field_validator("OLLAMA_BASE_URL")
    @classmethod
    def validate_ollama_url(cls, v: str) -> str:
        """Ensure Ollama URL has a valid scheme."""
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("OLLAMA_BASE_URL must start with http:// or https://")
        return v.rstrip("/")  # Remove trailing slash for consistent URL construction

    @model_validator(mode="after")
    def create_output_directories(self) -> Settings:
        """Create output directories if they don't exist."""
        Path(self.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        return self

    # ─── Convenience Methods ──────────────────────────────────────────────────

    def get_model_path(self) -> Path:
        """Return the resolved absolute path to the ML model file.

        Resolution strategy for relative paths:
            1. Try relative to current working directory (default behavior).
            2. If not found, try relative to the package root (the directory
               containing this settings.py file, traversed up to the project root).
               This handles the common case where forensiq is invoked from a
               directory other than the project root.

        Returns:
            Absolute Path object for the model file (may not exist yet).
        """
        model_path_str = self.MODEL_PATH
        candidate = Path(model_path_str).resolve()

        # Fast path: already absolute or relative path resolves correctly
        if candidate.is_file():
            return candidate

        # If relative and not found from CWD, try relative to package root
        if not Path(model_path_str).is_absolute():
            # settings.py is at src/forensiq/config/settings.py
            # Package root is 4 levels up from here
            pkg_root = Path(__file__).parent.parent.parent.parent.resolve()
            alt_candidate = (pkg_root / model_path_str).resolve()
            if alt_candidate.is_file():
                return alt_candidate

        return candidate

    def get_reports_dir(self) -> Path:
        """Return the resolved absolute path to the reports output directory."""
        return Path(self.REPORTS_DIR).resolve()

    def get_yara_rules_dir(self) -> Path:
        """Return the resolved absolute path to the YARA rules output directory."""
        return Path(self.YARA_RULES_DIR).resolve()

    def get_volatility_executable(self) -> str:
        """Return the absolute path to vol, or the configured path if already absolute.

        Searches PATH if the configured value is just 'vol'.

        Returns:
            Resolved path to the vol executable.

        Raises:
            FileNotFoundError: If vol cannot be found.
        """
        path = self.VOLATILITY_PATH

        # If it's already an absolute path, use it directly
        if Path(path).is_absolute():
            if not Path(path).is_file():
                raise FileNotFoundError(
                    f"Volatility 3 executable not found at: {path}\n"
                    "Install with: pip install volatility3"
                )
            return path

        # Search in PATH
        resolved = shutil.which(path)
        if resolved:
            return resolved

        # Try common locations
        fallbacks = [
            Path(".venv/bin/vol"),
            Path("~/.local/bin/vol").expanduser(),
        ]
        for fb in fallbacks:
            if fb.is_file():
                return str(fb)

        raise FileNotFoundError(
            f"Volatility 3 executable '{path}' not found in PATH.\n"
            "Install with: pip install volatility3\n"
            "Or set FORENSIQ_VOLATILITY_PATH=/path/to/vol in .env"
        )

    def is_model_available(self) -> bool:
        """Check if the trained ML model file exists."""
        return self.get_model_path().is_file()

    def __repr__(self) -> str:
        """Safe repr that does not expose sensitive path information."""
        return (
            f"Settings("
            f"LOG_LEVEL={self.LOG_LEVEL!r}, "
            f"LOG_FORMAT={self.LOG_FORMAT!r}, "
            f"THREAT_THRESHOLD={self.THREAT_THRESHOLD}, "
            f"YARA_GENERATE={self.YARA_GENERATE}, "
            f"MAX_PROCESSES_ANALYZE={self.MAX_PROCESSES_ANALYZE})"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (loaded once, cached forever).

    Uses lru_cache to ensure Settings is only instantiated and validated once.
    The cache is process-scoped, not thread-local.

    Returns:
        The global Settings instance.

    Example:
        from forensiq.config.settings import get_settings
        settings = get_settings()
        print(settings.THREAT_THRESHOLD)  # 0.65
    """
    return Settings()
