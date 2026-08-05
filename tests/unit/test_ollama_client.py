# FILE: tests/unit/test_ollama_client.py
"""Unit tests for the Ollama LLM client (URL validation, retries, response cap)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from forensiq.utils.exceptions import (
    OllamaConnectionError,
    OllamaModelNotFoundError,
    OllamaTimeoutError,
)


class _FakeSettings:
    OLLAMA_BASE_URL = "http://localhost:11434"
    OLLAMA_MODEL = "mistral:latest"
    OLLAMA_TIMEOUT = 120


def _settings_patch():
    return patch(
        "forensiq.llm.ollama_client.get_settings",
        return_value=_FakeSettings(),
    )


class _AsyncCM:
    """Async context manager wrapping a fake httpx AsyncClient."""

    def __init__(self, behavior):
        self._client = AsyncMock()
        if isinstance(behavior, Exception):
            self._client.post = AsyncMock(side_effect=behavior)
            self._client.get = AsyncMock(side_effect=behavior)
        else:
            self._client.post = AsyncMock(return_value=behavior)
            self._client.get = AsyncMock(return_value=behavior)

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, *exc):
        return False


def _client_factory(*post_behaviors):
    """Return a fake httpx.AsyncClient class whose post uses the given behaviors.

    Each behavior is either an exception (raised) or an httpx.Response (returned).
    Once the queue is exhausted the last behavior is reused.
    """
    queue = list(post_behaviors)

    def _factory(*args, **kwargs):
        behavior = queue.pop(0) if len(queue) > 1 else queue[0]
        return _AsyncCM(behavior)

    return _factory


def _request() -> httpx.Request:
    return httpx.Request("POST", "http://localhost:11434/api/generate")


class TestBaseUrlValidation:
    def test_rejects_non_http_scheme(self) -> None:
        with _settings_patch():
            with pytest.raises(ValueError, match="Invalid Ollama base URL"):
                from forensiq.llm.ollama_client import OllamaClient

                OllamaClient(base_url="file:///tmp/ollama.sock")

    def test_rejects_ftp_scheme(self) -> None:
        with _settings_patch():
            with pytest.raises(ValueError, match="Invalid Ollama base URL"):
                from forensiq.llm.ollama_client import OllamaClient

                OllamaClient(base_url="ftp://ollama.local:11434")

    def test_rejects_missing_host(self) -> None:
        with _settings_patch():
            with pytest.raises(ValueError, match="Invalid Ollama base URL"):
                from forensiq.llm.ollama_client import OllamaClient

                OllamaClient(base_url="http:///just/a/path")

    def test_rejects_bare_path(self) -> None:
        with _settings_patch():
            with pytest.raises(ValueError, match="Invalid Ollama base URL"):
                from forensiq.llm.ollama_client import OllamaClient

                OllamaClient(base_url="/var/run/ollama.sock")

    def test_accepts_valid_http_url(self) -> None:
        with _settings_patch():
            from forensiq.llm.ollama_client import OllamaClient

            client = OllamaClient(base_url="http://localhost:11434/")
        assert client.base_url == "http://localhost:11434"

    def test_accepts_valid_https_url(self) -> None:
        with _settings_patch():
            from forensiq.llm.ollama_client import OllamaClient

            client = OllamaClient(base_url="https://ollama.example.com:11434")
        assert client.base_url == "https://ollama.example.com:11434"


class TestGenerateSuccess:
    async def test_returns_response_text(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"response": "rule evil { condition: true }"},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            text = await client.generate("Write a rule")

        assert text == "rule evil { condition: true }"

    async def test_404_raises_model_not_found(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(404, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            with pytest.raises(OllamaModelNotFoundError):
                await client.generate("Write a rule")

    async def test_5xx_raises_connection_error(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(500, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            with pytest.raises(OllamaConnectionError):
                await client.generate("Write a rule")


class TestResponseCap:
    async def test_oversized_response_is_truncated(self) -> None:
        from forensiq.llm.ollama_client import _MAX_RESPONSE_BYTES, OllamaClient

        huge = "A" * (_MAX_RESPONSE_BYTES + 1000)
        response = httpx.Response(200, json={"response": huge}, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            text = await client.generate("Write a rule")

        assert len(text) == _MAX_RESPONSE_BYTES

    async def test_normal_response_untouched(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"response": "short"},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            text = await client.generate("Write a rule")

        assert text == "short"


class TestRetries:
    async def test_recovers_after_transient_failure(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"response": "recovered"},
            request=_request(),
        )
        behaviors = [
            httpx.ConnectError("boom 1"),
            httpx.ConnectError("boom 2"),
            response,
        ]
        factory = _client_factory(*behaviors)
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient", factory
        ), patch("forensiq.llm.ollama_client.asyncio.sleep", new=AsyncMock()):
            client = OllamaClient()
            text = await client.generate("Write a rule")

        assert text == "recovered"

    async def test_raises_connection_error_after_max_retries(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        behaviors = [httpx.ConnectError("boom")] * 3
        factory = _client_factory(*behaviors)
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient", factory
        ), patch("forensiq.llm.ollama_client.asyncio.sleep", new=AsyncMock()):
            client = OllamaClient()
            with pytest.raises(OllamaConnectionError):
                await client.generate("Write a rule")

    async def test_raises_timeout_error_after_max_retries(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        behaviors = [httpx.TimeoutException("slow")] * 3
        factory = _client_factory(*behaviors)
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient", factory
        ), patch("forensiq.llm.ollama_client.asyncio.sleep", new=AsyncMock()):
            client = OllamaClient()
            with pytest.raises(OllamaTimeoutError):
                await client.generate("Write a rule")


class TestCheckHealth:
    async def test_health_ok_with_available_model(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"models": [{"name": "mistral:latest"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            await client.check_health()

    async def test_health_raises_model_not_found_when_missing(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"models": [{"name": "llama3:latest"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            with pytest.raises(OllamaModelNotFoundError):
                await client.check_health()


class TestListModels:
    async def test_returns_model_names(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={
                "models": [
                    {"name": "mistral:latest"},
                    {"name": "qwen2.5-coder:7b"},
                ]
            },
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            names = await client.list_models()

        assert names == ["mistral:latest", "qwen2.5-coder:7b"]

    async def test_empty_models_returns_empty_list(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(200, json={"models": []}, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            assert await client.list_models() == []

    async def test_missing_models_key_returns_empty_list(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(200, json={}, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            assert await client.list_models() == []

    async def test_connection_error_raises(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(httpx.ConnectError("down")),
        ):
            client = OllamaClient()
            with pytest.raises(OllamaConnectionError):
                await client.list_models()


class TestResolveModel:
    async def test_uses_configured_model_when_installed(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"models": [{"name": "mistral:latest"}, {"name": "llama3:latest"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            resolved = await client.resolve_model()

        assert resolved == "mistral:latest"
        assert client.model == "mistral:latest"

    async def test_falls_back_to_curated_family_when_configured_missing(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={
                "models": [
                    {"name": "qwen2.5-coder:7b"},
                    {"name": "llama3:latest"},
                ]
            },
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            resolved = await client.resolve_model()

        # llama ranks above qwen in the curated priority list.
        assert resolved == "llama3:latest"
        assert client.model == "llama3:latest"

    async def test_qwen_selected_when_llama_absent(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"models": [{"name": "qwen2.5-coder:7b"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            resolved = await client.resolve_model()

        assert resolved == "qwen2.5-coder:7b"

    async def test_uses_first_available_for_unknown_family(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(
            200,
            json={"models": [{"name": "some-custom-model:latest"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            resolved = await client.resolve_model()

        assert resolved == "some-custom-model:latest"

    async def test_returns_none_when_no_models_installed(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        response = httpx.Response(200, json={"models": []}, request=_request())
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ):
            client = OllamaClient()
            assert await client.resolve_model() is None

    async def test_returns_none_when_ollama_unreachable(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(httpx.ConnectError("down")),
        ):
            client = OllamaClient()
            assert await client.resolve_model() is None

    async def test_prefix_matches_family(self) -> None:
        from forensiq.llm.ollama_client import OllamaClient

        # Configured "qwen:latest" should match installed "qwen2.5-coder:7b".
        response = httpx.Response(
            200,
            json={"models": [{"name": "qwen2.5-coder:7b"}]},
            request=_request(),
        )
        with _settings_patch(), patch(
            "forensiq.llm.ollama_client.httpx.AsyncClient",
            _client_factory(response),
        ), patch.object(_FakeSettings, "OLLAMA_MODEL", "qwen:latest"):
            client = OllamaClient()
            resolved = await client.resolve_model()

        assert resolved == "qwen:latest"
        assert client.model == "qwen:latest"
