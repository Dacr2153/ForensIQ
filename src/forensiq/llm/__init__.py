# FILE: src/forensiq/llm/__init__.py
"""forensiq.llm — Async Ollama HTTP client for local LLM inference."""

from forensiq.llm.ollama_client import OllamaClient

__all__ = ["OllamaClient"]
