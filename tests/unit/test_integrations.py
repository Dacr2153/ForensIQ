# FILE: tests/unit/test_integrations.py
"""Unit tests for MalwareBazaarClient and VirusTotalClient."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forensiq.integrations.malwarebazaar import MalwareBazaarClient, ThreatIntelResult
from forensiq.integrations.virustotal import VirusTotalClient, VTResult


# ── ThreatIntelResult dataclass ───────────────────────────────────────────────


class TestThreatIntelResult:
    def test_default_tags_and_raw_response(self):
        r = ThreatIntelResult(
            hash_value="abc123",
            hash_type="md5",
            source="malwarebazaar",
            is_malicious=False,
            verdict="unknown",
        )
        assert r.tags == []
        assert r.raw_response == {}

    def test_is_malicious_true(self):
        r = ThreatIntelResult(
            hash_value="a" * 64,
            hash_type="sha256",
            source="malwarebazaar",
            is_malicious=True,
            verdict="malicious",
            malware_name="Emotet",
        )
        assert r.is_malicious is True
        assert r.malware_name == "Emotet"


# ── MalwareBazaarClient ───────────────────────────────────────────────────────


class TestMalwareBazaarClient:
    @pytest.mark.asyncio
    async def test_no_client_returns_unavailable(self):
        """Without httpx client initialized, returns unavailable verdict."""
        client = MalwareBazaarClient()
        # Don't call __aenter__, so _client stays None
        result = await client.lookup_hash("abc123")
        assert result.verdict == "unavailable"
        assert result.is_malicious is False
        assert result.source == "malwarebazaar"

    @pytest.mark.asyncio
    async def test_lookup_hash_not_found(self):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"query_status": "hash_not_found"}

        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.lookup_hash("a" * 32)
        assert result.verdict == "unknown"
        assert result.is_malicious is False

    @pytest.mark.asyncio
    async def test_lookup_hash_malicious(self):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "Emotet",
                    "file_type": "exe",
                    "first_seen": "2023-01-01",
                    "tags": ["emotet", "banking"],
                }
            ],
        }

        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.lookup_hash("a" * 64)
        assert result.verdict == "malicious"
        assert result.is_malicious is True
        assert result.malware_name == "Emotet"
        assert result.hash_type == "sha256"
        assert "emotet" in result.tags

    @pytest.mark.asyncio
    async def test_lookup_hash_network_error(self):
        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(side_effect=Exception("Connection refused"))

        result = await client.lookup_hash("a" * 32)
        assert result.verdict == "error"
        assert result.is_malicious is False

    @pytest.mark.asyncio
    async def test_lookup_hash_md5_detected(self):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"query_status": "hash_not_found"}

        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.lookup_hash("a" * 32)  # 32 chars = MD5
        assert result.hash_type == "md5"

    @pytest.mark.asyncio
    async def test_lookup_hash_unknown_status(self):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"query_status": "something_weird"}

        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        result = await client.lookup_hash("a" * 32)
        assert result.verdict == "unknown"

    @pytest.mark.asyncio
    async def test_lookup_batch_returns_all_hashes(self):
        """lookup_batch returns a dict keyed by hash."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"query_status": "hash_not_found"}

        client = MalwareBazaarClient()
        client._client = AsyncMock()
        client._client.post = AsyncMock(return_value=mock_response)

        hashes = ["a" * 32, "b" * 32]
        results = await client.lookup_batch(hashes, delay_ms=0)

        assert set(results.keys()) == set(hashes)
        assert all(isinstance(v, ThreatIntelResult) for v in results.values())

    @pytest.mark.asyncio
    async def test_context_manager_no_httpx(self):
        """Without httpx available, __aenter__ does not raise."""
        client = MalwareBazaarClient()
        with patch.dict("sys.modules", {"httpx": None}):
            async with MalwareBazaarClient() as c:
                assert c._client is None


# ── VirusTotalClient ──────────────────────────────────────────────────────────


class TestVirusTotalClient:
    def test_is_configured_false_no_key(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        assert client.is_configured() is False

    def test_is_configured_true_with_key(self):
        client = VirusTotalClient(api_key="my_api_key")
        assert client.is_configured() is True

    def test_is_configured_from_env(self, monkeypatch):
        monkeypatch.setenv("FORENSIQ_VT_API_KEY", "env_key")
        client = VirusTotalClient()
        assert client.is_configured() is True

    @pytest.mark.asyncio
    async def test_lookup_hash_not_configured_returns_unavailable(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash("a" * 64)
        assert result.verdict == "unavailable"
        assert result.is_malicious is False
        assert result.source == "virustotal"

    @pytest.mark.asyncio
    async def test_lookup_hash_sha256_type_detected(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash("a" * 64)
        assert result.hash_type == "sha256"

    @pytest.mark.asyncio
    async def test_lookup_hash_md5_type_detected(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash("a" * 32)
        assert result.hash_type == "md5"

    @pytest.mark.asyncio
    async def test_lookup_hash_sha1_type_detected(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash("a" * 40)
        assert result.hash_type == "sha1"

    @pytest.mark.asyncio
    async def test_vt_result_is_threat_intel_result(self, monkeypatch):
        monkeypatch.delenv("FORENSIQ_VT_API_KEY", raising=False)
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash("a" * 64)
        assert isinstance(result, VTResult)
        assert isinstance(result, ThreatIntelResult)

    @pytest.mark.asyncio
    async def test_lookup_hash_with_client_404(self):
        mock_response = MagicMock()
        mock_response.status_code = 404

        client = VirusTotalClient(api_key="test_key")
        client._client = AsyncMock()
        client._client.get = AsyncMock(return_value=mock_response)

        result = await client.lookup_hash("a" * 64)
        assert result.verdict == "unknown"
        assert result.is_malicious is False

    @pytest.mark.asyncio
    async def test_lookup_hash_with_client_network_error(self):
        client = VirusTotalClient(api_key="test_key")
        client._client = AsyncMock()
        client._client.get = AsyncMock(side_effect=Exception("network timeout"))

        result = await client.lookup_hash("a" * 64)
        assert result.verdict == "error"
