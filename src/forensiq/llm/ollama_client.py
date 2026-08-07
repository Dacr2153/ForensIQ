# FILE: src/forensiq/llm/ollama_client.py
"""Ollama LLM client for YARA rule generation.

Communicates with a local Ollama server via its REST API.
Uses httpx for async HTTP with explicit timeouts.
No external API keys — all inference runs locally via Ollama.

Ollama API endpoints used:
    POST /api/generate   — single-shot text generation
    GET  /api/tags       — list available models (health check)

Usage:
    client = OllamaClient()
    await client.check_health()  # raises OllamaConnectionError if unreachable
    text = await client.generate(prompt="Write a YARA rule for...")
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import httpx

from forensiq.config.settings import get_settings
from forensiq.utils.exceptions import (
    OllamaConnectionError,
    OllamaModelNotFoundError,
    OllamaTimeoutError,
)
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Guard against a misbehaving model flooding memory with a huge response.
_MAX_RESPONSE_BYTES = 65536  # 64 KB is plenty for a single YARA rule

# Ollama base URL must be http(s) with a host, never a bare path or file scheme.
_URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

# Number of times to retry transient failures before giving up.
# A failure is transient when it is a connection/read error (httpx.RequestError)
# or a 5xx / 429 server response. Other statuses are not retried.
_MAX_RETRIES = 3
_BASE_BACKOFF_SECONDS = 1.0

# Model families to prefer (in order) when the configured model is not
# installed.  Matching is a case-insensitive prefix match against the full
# Ollama model tag (e.g. "qwen" matches "qwen2.5-coder:7b").
_FALLBACK_MODEL_PATTERNS = (
    "mistral",
    "llama",
    "qwen",
    "phi",
    "gemma",
    "codellama",
    "deepseek",
)


class OllamaClient:
    """HTTP client for the local Ollama inference API.

    Args:
        base_url: Ollama server base URL (overrides settings).
        model: Model name to use for generation (overrides settings).
        timeout: Request timeout in seconds (overrides settings).
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ) -> None:
        settings = get_settings()
        # Validate even an explicitly-passed base_url (settings already validates).
        raw_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        if not _URL_PATTERN.match(raw_url):
            raise ValueError(
                f"Invalid Ollama base URL: {raw_url!r}. "
                "Must be an http:// or https:// URL pointing at the Ollama server."
            )
        parsed = urlparse(raw_url)
        if not parsed.hostname:
            raise ValueError(f"Invalid Ollama base URL (no host): {raw_url!r}")
        self.base_url = raw_url
        self.model = model or settings.OLLAMA_MODEL
        self.timeout = timeout or settings.OLLAMA_TIMEOUT

        # Single shared transport — reused across every request instead of
        # opening a new connection pool per call. Lazily created on first use
        # and closed via aclose()/close().
        self._client: httpx.AsyncClient | None = None

        # Prompts contain analysis data (rule text, file hashes, artifact names).
        # Only allow plaintext HTTP for loopback — warn loudly for remote hosts.
        hostname = parsed.hostname.lower()
        is_loopback = hostname in {"localhost", "::1"} or hostname.startswith("127.")
        if parsed.scheme == "http" and not is_loopback:
            log.warning(
                "Ollama reachable over plaintext HTTP on a non-loopback host — "
                "prompts containing analysis data will be sent unencrypted",
                url=raw_url,
            )

    def _get_client(self) -> httpx.AsyncClient:
        """Return the shared httpx client, creating it on first use."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=float(self.timeout))
        return self._client

    async def aclose(self) -> None:
        """Close the shared httpx client and release its connection pool."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def close(self) -> None:
        """Synchronously close the shared httpx client (best-effort)."""
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    async def _get_tags(self) -> list[str]:
        """Fetch installed model tags from ``/api/tags`` with transient retries.

        Raises:
            OllamaConnectionError: If Ollama is unreachable or keeps failing.
        """
        url = f"{self.base_url}/api/tags"
        last_error: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = await self._get_client().get(url)
                if response.status_code < 500 and response.status_code != 429:
                    response.raise_for_status()
                    data = response.json()
                    return [
                        name
                        for name in (
                            m.get("name", "") for m in data.get("models", [])
                        )
                        if name
                    ]
                last_error = httpx.HTTPStatusError(
                    f"HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_error = exc
            if attempt < _MAX_RETRIES:
                await asyncio.sleep(_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        raise OllamaConnectionError(base_url=self.base_url) from last_error

    async def check_health(self) -> None:
        """Verify Ollama is running and the configured model is available.

        Raises:
            OllamaConnectionError: If Ollama is not reachable at base_url.
            OllamaModelNotFoundError: If the configured model is not installed,
                or Ollama reports no models at all.
        """
        available_models = await self._get_tags()

        # An Ollama instance with zero models is unhealthy for our purposes:
        # there is nothing to generate with, and model resolution would fail.
        if not available_models:
            raise OllamaModelNotFoundError(model=self.model)

        # Check if our model is available
        model_available = any(
            self.model in name or name.startswith(self.model.split(":")[0])
            for name in available_models
        )

        if not model_available:
            log.warning(
                "Configured model not found in Ollama",
                model=self.model,
                available=available_models[:5],
            )
            raise OllamaModelNotFoundError(model=self.model)

        log.debug("Ollama health check passed", model=self.model, url=self.base_url)

    async def list_models(self) -> list[str]:
        """Return the names of all models currently installed in Ollama.

        Returns:
            List of model tag names (e.g. ``["mistral:latest", "qwen2.5-coder:7b"]``),
            in the order returned by Ollama's ``/api/tags`` endpoint.

        Raises:
            OllamaConnectionError: If Ollama is not reachable at base_url.
        """
        return await self._get_tags()

    async def resolve_model(self) -> str | None:
        """Pick a usable model, preferring the configured one.

        Resolution order:
            1. The configured model, if installed (or an exact/prefix match).
            2. The first installed model matching a curated fallback family
               (:data:`_FALLBACK_MODEL_PATTERNS`), in priority order.
            3. Any installed model (first in ``/api/tags`` order).

        The resolved name is stored on ``self.model`` so subsequent
        :meth:`generate` calls use it.

        Returns:
            The resolved model tag, or ``None`` when Ollama is unreachable or
            no model is installed.
        """
        try:
            available = await self.list_models()
        except OllamaConnectionError:
            log.warning(
                "Ollama unreachable during model resolution",
                url=self.base_url,
            )
            return None

        if not available:
            log.warning("Ollama has no models installed", url=self.base_url)
            return None

        configured = self.model
        if self._matches_any(configured, available):
            log.debug("Using configured Ollama model", model=configured)
            return configured

        for pattern in _FALLBACK_MODEL_PATTERNS:
            for name in available:
                if name.lower().startswith(pattern):
                    log.warning(
                        "Configured model not installed; falling back",
                        configured=configured,
                        model=name,
                        reason="fallback_family",
                    )
                    self.model = name
                    return name

        fallback = available[0]
        log.warning(
            "Configured model not installed; using first available",
            configured=configured,
            model=fallback,
            reason="first_available",
        )
        self.model = fallback
        return fallback

    @staticmethod
    def _matches_any(model: str, available: list[str]) -> bool:
        """True if ``model`` matches an installed model exactly or by family prefix."""
        family = model.split(":")[0]
        return any(
            name == model or name.lower().startswith(family)
            for name in available
        )

    async def generate(self, prompt: str) -> str:
        """Send a generation request to Ollama and return the response text.

        Uses the /api/generate endpoint in non-streaming mode
        (stream=false) for simpler response handling.

        Args:
            prompt: The full prompt to send to the model.

        Returns:
            Generated text response from the model.

        Raises:
            OllamaConnectionError: If the request cannot be sent.
            OllamaTimeoutError: If the request exceeds self.timeout.
            OllamaModelNotFoundError: If the model is not available.
        """
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Low temperature for deterministic YARA output
                "top_p": 0.9,
                "num_predict": 1024,  # Enough for a single YARA rule
            },
        }

        log.debug("Sending generation request to Ollama", model=self.model)

        # Retry transient failures (connection/read/timeout errors and 5xx/429
        # responses) with exponential backoff.
        response: httpx.Response | None = None
        last_error: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                response = await self._get_client().post(url, json=payload)
                if response.status_code < 500 and response.status_code != 429:
                    last_error = None
                    break
                last_error = httpx.HTTPStatusError(
                    f"HTTP {response.status_code}",
                    request=response.request,
                    response=response,
                )
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_error = exc
            if attempt >= _MAX_RETRIES:
                break
            log.warning(
                "Ollama request failed, retrying",
                attempt=attempt,
                max_retries=_MAX_RETRIES,
            )
            await asyncio.sleep(_BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))

        if isinstance(last_error, httpx.TimeoutException):
            raise OllamaTimeoutError(
                timeout_seconds=self.timeout,
                model=self.model,
            ) from last_error
        if last_error is not None:
            raise OllamaConnectionError(base_url=self.base_url) from last_error

        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status == 404:
                raise OllamaModelNotFoundError(model=self.model) from exc
            raise OllamaConnectionError(base_url=self.base_url) from exc

        try:
            data = response.json()
            text = str(data.get("response", ""))
        except Exception as exc:
            raise OllamaConnectionError(
                base_url=self.base_url,
            ) from exc

        # Cap the response length so a misbehaving model cannot exhaust memory.
        if len(text) > _MAX_RESPONSE_BYTES:
            log.warning(
                "Truncating oversized Ollama response",
                received_bytes=len(text),
                cap_bytes=_MAX_RESPONSE_BYTES,
            )
            text = text[:_MAX_RESPONSE_BYTES]

        log.debug("Ollama generation complete", response_length=len(text))
        return text
