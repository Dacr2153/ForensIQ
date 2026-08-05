# FILE: src/forensiq/utils/exceptions.py
"""ForensIQ custom exception hierarchy.

All exceptions inherit from ForensiqError which carries a correlation_id
for log tracing and a context dict for structured error information.

Hierarchy:
    ForensiqError
        AcquisitionError           — Volatility 3 invocation failures
            VolatilityTimeoutError
            VolatilityParseError
            UnsupportedProfileError
        ExtractionError            — Plugin output parsing failures
            MissingPluginOutputError
        FeatureEngineeringError    — Feature computation failures
        ClassificationError        — ML model failures
            ModelNotLoadedError
            InsufficientDataError
        YARAError                  — YARA generation/validation failures
            YARAGenerationError
            YARACompilationError
            YARAValidationError
        LLMError                   — Ollama/LLM communication failures
            OllamaConnectionError
            OllamaTimeoutError
            OllamaModelNotFoundError
        ReportError                — HTML report generation failures
"""

from __future__ import annotations

from typing import Any


class ForensiqError(Exception):
    """Base exception for all ForensIQ errors.

    Args:
        message: Human-readable error description.
        correlation_id: UUID string for log correlation across pipeline stages.
        context: Additional key-value pairs for structured error context.
    """

    def __init__(
        self,
        message: str,
        correlation_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.correlation_id = correlation_id
        self.context: dict[str, Any] = context or {}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"correlation_id={self.correlation_id!r}, "
            f"context={self.context!r})"
        )


# ─── Acquisition Errors (Volatility 3 subprocess) ────────────────────────────


class AcquisitionError(ForensiqError):
    """Raised when Volatility 3 cannot be invoked or returns an error."""


class VolatilityTimeoutError(AcquisitionError):
    """Raised when a Volatility 3 plugin exceeds the configured timeout.

    Args:
        plugin: Name of the Volatility 3 plugin that timed out.
        timeout_seconds: The timeout limit that was exceeded.
    """

    def __init__(
        self,
        plugin: str,
        timeout_seconds: int,
        correlation_id: str = "",
    ) -> None:
        super().__init__(
            message=f"Volatility 3 plugin '{plugin}' timed out after {timeout_seconds}s",
            correlation_id=correlation_id,
            context={"plugin": plugin, "timeout_seconds": timeout_seconds},
        )
        self.plugin = plugin
        self.timeout_seconds = timeout_seconds


class VolatilityParseError(AcquisitionError):
    """Raised when Volatility 3 output cannot be parsed as valid JSON."""

    def __init__(
        self,
        plugin: str,
        raw_output: str,
        correlation_id: str = "",
    ) -> None:
        # Truncate raw output in exception message (may be very long)
        preview = raw_output[:200] + "..." if len(raw_output) > 200 else raw_output
        super().__init__(
            message=f"Failed to parse JSON output from '{plugin}': {preview}",
            correlation_id=correlation_id,
            context={"plugin": plugin, "raw_output_preview": preview},
        )
        self.plugin = plugin


class UnsupportedProfileError(AcquisitionError):
    """Raised when the memory dump OS profile cannot be determined or is unsupported."""

    def __init__(self, dump_path: str, correlation_id: str = "") -> None:
        super().__init__(
            message=(
                f"Cannot determine OS profile for dump: {dump_path}. "
                "Ensure this is a valid Windows memory dump and Volatility 3 "
                "has the required symbol tables."
            ),
            correlation_id=correlation_id,
            context={"dump_path": dump_path},
        )


# ─── Extraction Errors (plugin output parsing) ────────────────────────────────


class ExtractionError(ForensiqError):
    """Raised when forensic artifact extraction from plugin output fails."""


class MissingPluginOutputError(ExtractionError):
    """Raised when a required plugin produces no output (e.g., no processes found)."""

    def __init__(self, plugin: str, dump_path: str, correlation_id: str = "") -> None:
        super().__init__(
            message=f"Plugin '{plugin}' returned empty output for dump: {dump_path}",
            correlation_id=correlation_id,
            context={"plugin": plugin, "dump_path": dump_path},
        )


# ─── Feature Engineering Errors ──────────────────────────────────────────────


class FeatureEngineeringError(ForensiqError):
    """Raised when feature computation fails for a process."""

    def __init__(self, pid: int, process_name: str, reason: str, correlation_id: str = "") -> None:
        super().__init__(
            message=f"Feature engineering failed for PID {pid} ({process_name}): {reason}",
            correlation_id=correlation_id,
            context={"pid": pid, "process_name": process_name, "reason": reason},
        )


# ─── Classification Errors ────────────────────────────────────────────────────


class ClassificationError(ForensiqError):
    """Raised when the ML classifier encounters an error."""


class ModelNotLoadedError(ClassificationError):
    """Raised when predict() is called before the model is loaded."""

    def __init__(self, model_path: str, correlation_id: str = "") -> None:
        super().__init__(
            message=(
                f"ML model not loaded. Load it first with: classifier.load_model(). "
                f"Expected path: {model_path}"
            ),
            correlation_id=correlation_id,
            context={"model_path": model_path},
        )


class InsufficientDataError(ClassificationError):
    """Raised when there are too few processes to classify meaningfully."""

    def __init__(self, count: int, minimum: int = 3, correlation_id: str = "") -> None:
        super().__init__(
            message=f"Only {count} processes found. Minimum for classification: {minimum}",
            correlation_id=correlation_id,
            context={"process_count": count, "minimum": minimum},
        )


# ─── YARA Errors ──────────────────────────────────────────────────────────────


class YARAError(ForensiqError):
    """Base class for YARA-related errors."""


class YARAGenerationError(YARAError):
    """Raised when the LLM fails to generate a parseable YARA rule."""

    def __init__(self, process_name: str, reason: str, correlation_id: str = "") -> None:
        super().__init__(
            message=f"YARA generation failed for '{process_name}': {reason}",
            correlation_id=correlation_id,
            context={"process_name": process_name, "reason": reason},
        )


class YARACompilationError(YARAError):
    """Raised when yara-python fails to compile a generated rule.

    This is non-fatal: the rule is marked as validation_failed in the report,
    and a new generation attempt can be made.
    """

    def __init__(
        self,
        rule_name: str,
        compile_error: str,
        rule_text: str,
        correlation_id: str = "",
    ) -> None:
        super().__init__(
            message=f"YARA compilation failed for rule '{rule_name}': {compile_error}",
            correlation_id=correlation_id,
            context={
                "rule_name": rule_name,
                "compile_error": compile_error,
                # Store rule text for debugging (truncated)
                "rule_text_preview": rule_text[:300],
            },
        )
        self.rule_name = rule_name
        self.compile_error = compile_error


class YARAValidationError(YARAError):
    """Raised when a compiled YARA rule fails its validation test."""


# ─── LLM Errors ──────────────────────────────────────────────────────────────


class LLMError(ForensiqError):
    """Base class for Ollama/LLM communication errors."""


class OllamaConnectionError(LLMError):
    """Raised when ForensIQ cannot connect to the Ollama API."""

    def __init__(self, base_url: str, correlation_id: str = "") -> None:
        super().__init__(
            message=(
                f"Cannot connect to Ollama at {base_url}. "
                "Ensure Ollama is running: 'ollama serve' or 'systemctl start ollama'"
            ),
            correlation_id=correlation_id,
            context={"base_url": base_url},
        )


class OllamaTimeoutError(LLMError):
    """Raised when the Ollama API does not respond within the configured timeout."""

    def __init__(self, timeout_seconds: int, model: str, correlation_id: str = "") -> None:
        super().__init__(
            message=(
                f"Ollama request for model '{model}' timed out after {timeout_seconds}s. "
                "Try increasing FORENSIQ_OLLAMA_TIMEOUT in .env."
            ),
            correlation_id=correlation_id,
            context={"timeout_seconds": timeout_seconds, "model": model},
        )


class OllamaModelNotFoundError(LLMError):
    """Raised when the configured LLM model is not available in Ollama."""

    def __init__(self, model: str, correlation_id: str = "") -> None:
        super().__init__(
            message=(f"Model '{model}' not found in Ollama. Download it with: ollama pull {model}"),
            correlation_id=correlation_id,
            context={"model": model},
        )


# ─── Report Errors ────────────────────────────────────────────────────────────


class ReportError(ForensiqError):
    """Raised when HTML report generation fails."""

    def __init__(self, output_path: str, reason: str, correlation_id: str = "") -> None:
        super().__init__(
            message=f"Report generation failed for '{output_path}': {reason}",
            correlation_id=correlation_id,
            context={"output_path": output_path, "reason": reason},
        )
