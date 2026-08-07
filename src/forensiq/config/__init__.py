# FILE: src/forensiq/config/__init__.py
"""forensiq.config — Application configuration via Pydantic BaseSettings."""

from forensiq.config.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
