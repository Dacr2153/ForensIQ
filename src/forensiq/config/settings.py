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

from pydantic import Field, field_validator
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
        # An empty env var (FORENSIQ_X="") must not clobber a configured default —
        # it is treated as "not set" so unset-but-exported variables stay sane.
        env_ignore_empty=True,
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
    OLLAMA_TIMEOUT: int = Field(
        default=120, gt=0, le=600,
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
    MAX_PROCESSES_ANALYZE: int = Field(
        default=500, ge=0,
        description="Max number of processes to analyze. 0 = unlimited.",
    )

    # ─── Detection ────────────────────────────────────────────────────────────
    THREAT_THRESHOLD: float = Field(
        default=0.65, gt=0.0, lt=1.0,
        description="Probability threshold above which a process is classified as malicious.",
    )
    YARA_GENERATE: bool = Field(
        default=True,
        description="Enable YARA rule generation via Ollama LLM.",
    )

    # ─── Threat Intelligence (optional) ──────────────────────────────────────
    DLL_ROOT: str = Field(
        default="",
        description="Root directory for resolving DLL content files during "
        "artifact hashing. Windows dump analysis happens on a separate host "
        "where the original files are unavailable, so set this to the mount "
        "point or copied tree of the suspect system's files to compute genuine "
        "SHA-256 content hashes (e.g. /mnt/evidence). Empty = hashing only "
        "works when the DLL path is a real file on this host (live Linux).",
    )
    VT_API_KEY: str = Field(
        default="",
        description="VirusTotal API v3 key. Leave empty to disable VT lookups.",
    )
    DB_PATH: str = Field(
        default="",
        description="SQLite database path for analysis history. "
        "Empty = ~/.forensiq/forensiq.db. Env var: FORENSIQ_DB_PATH.",
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
        """Return the resolved absolute path to the reports output directory.

        Creates the directory lazily on first use so instantiating Settings
        (import time) has no filesystem side effects.
        """
        path = Path(self.REPORTS_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_yara_rules_dir(self) -> Path:
        """Return the resolved absolute path to the YARA rules output directory.

        Creates the directory lazily on first use.
        """
        path = Path(self.YARA_RULES_DIR).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_dll_root(self) -> Path | None:
        """Return the resolved absolute DLL content root, or None if unset.

        Returns:
            Absolute Path if DLL_ROOT is configured, None otherwise.
        """
        if not self.DLL_ROOT:
            return None
        return Path(self.DLL_ROOT).resolve()

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
    """Return the process-scoped singleton Settings instance.

    Uses lru_cache so Settings is instantiated and validated exactly once per
    process. Because the cache is process-scoped, changes to environment
    variables after the first call are not picked up — tests that need fresh
    settings should call ``get_settings.cache_clear()`` first.
    """
    return Settings()
