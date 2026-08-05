# FILE: tests/unit/test_pipeline_llm_fallback.py
"""Tests for graceful LLM degradation in AnalysisPipeline.

Covers:
    - _resolve_ollama_client: returns (None, None) when no usable model
    - _run_yara_generation: skips cleanly without a usable model
    - _run_executive_summary: always returns a non-empty summary
    - _build_extraction_error: targeted Volatility guidance
    - Full run(): produces a complete report with llm_info when Ollama is absent
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forensiq.models.features import ProcessFeatureVector
from forensiq.pipeline.analysis_pipeline import AnalysisPipeline


def _vec(**kwargs) -> ProcessFeatureVector:
    """Build a minimal ProcessFeatureVector with sane defaults."""
    defaults = {
        "pid": 100,
        "ppid": 4,
        "name": "test.exe",
        "image_file_name": r"\Windows\System32\test.exe",
        "process_name_entropy": 2.5,
        "path_entropy": 3.0,
        "path_depth": 4,
        "is_system_path": True,
        "parent_child_legit": True,
        "dll_count": 5,
        "suspicious_dll_count": 0,
        "has_network_connection": False,
        "network_connection_count": 0,
        "external_connection_count": 0,
        "malfind_hits": 0,
        "vad_rwx_count": 0,
        "thread_count": 5,
        "handle_count": 100,
        "has_encoded_cmdline": False,
        "threat_score": 0.05,
        "is_malicious": False,
        "shap_values": {},
    }
    defaults.update(kwargs)
    return ProcessFeatureVector(**defaults)


def _make_extraction() -> MagicMock:
    extraction = MagicMock()
    extraction.dump_sha256 = "a" * 64
    extraction.dump_size_bytes = 1024 * 1024
    extraction.volatility_version = "2.11.0"
    extraction.process_tree = MagicMock()
    extraction.process_tree.flat_map = {}
    return extraction


def _make_pipeline(**kwargs) -> AnalysisPipeline:
    return AnalysisPipeline(
        show_progress=False,
        generate_yara=kwargs.get("generate_yara", True),
        generate_html=False,
        generate_json=False,
        force_reanalyze=True,
    )


# ── _resolve_ollama_client ────────────────────────────────────────────────────


class TestResolveOllamaClient:
    @pytest.mark.asyncio
    async def test_returns_none_none_when_model_unavailable(self) -> None:
        pipeline = _make_pipeline()
        with patch("forensiq.llm.ollama_client.OllamaClient") as mock_client_cls:
            instance = mock_client_cls.return_value
            instance.resolve_model = AsyncMock(return_value=None)
            client, resolved = await pipeline._resolve_ollama_client()

        assert client is None
        assert resolved is None

    @pytest.mark.asyncio
    async def test_returns_client_and_model_when_resolved(self) -> None:
        pipeline = _make_pipeline()
        with patch("forensiq.llm.ollama_client.OllamaClient") as mock_client_cls:
            instance = mock_client_cls.return_value
            instance.resolve_model = AsyncMock(return_value="qwen2.5-coder:7b")
            client, resolved = await pipeline._resolve_ollama_client()

        assert client is instance
        assert resolved == "qwen2.5-coder:7b"

    @pytest.mark.asyncio
    async def test_resolve_error_degrades_to_none(self) -> None:
        pipeline = _make_pipeline()
        with patch("forensiq.llm.ollama_client.OllamaClient") as mock_client_cls:
            instance = mock_client_cls.return_value
            instance.resolve_model = AsyncMock(side_effect=RuntimeError("boom"))
            client, resolved = await pipeline._resolve_ollama_client()

        assert client is None
        assert resolved is None


# ── _run_yara_generation ─────────────────────────────────────────────────────


class TestRunYaraGeneration:
    @pytest.mark.asyncio
    async def test_returns_empty_without_usable_model(self) -> None:
        pipeline = _make_pipeline()
        results = await pipeline._run_yara_generation(
            [_vec()], _make_extraction(), None, None
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_uses_resolved_client(self) -> None:
        pipeline = _make_pipeline()
        client = MagicMock()
        expected = [MagicMock()]
        with patch("forensiq.yara.generator.YARAGenerator") as mock_gen_cls:
            gen = mock_gen_cls.return_value
            gen.generate_for_malicious = AsyncMock(return_value=expected)
            results = await pipeline._run_yara_generation(
                [_vec()], _make_extraction(), client, "qwen2.5-coder:7b"
            )

        assert results == expected
        mock_gen_cls.assert_called_once_with(client=client)


# ── _run_executive_summary ───────────────────────────────────────────────────


class TestRunExecutiveSummary:
    @pytest.mark.asyncio
    async def test_always_returns_non_empty_fallback_without_llm(self) -> None:
        pipeline = _make_pipeline()
        report = MagicMock()
        report.malicious_count = 0
        report.suspicious_count = 0
        report.total_processes = 10
        report.threat_level = "low"
        report.executive_summary = ""
        report.timeline = []
        report.mitre_techniques = []
        report.top_threats = []
        report.metadata = MagicMock()
        report.metadata.dump_path = "C:\\dumps\\mem.raw"
        report.metadata.dump_filename = "mem.raw"

        summary = await pipeline._run_executive_summary(report, None, None)

        assert isinstance(summary, str)
        assert len(summary.strip()) > 0

    @pytest.mark.asyncio
    async def test_uses_llm_when_available(self) -> None:
        pipeline = _make_pipeline()
        report = MagicMock()
        report.malicious_count = 0
        report.suspicious_count = 0
        report.total_processes = 10
        report.threat_level = "low"
        report.timeline = []
        report.mitre_techniques = []
        report.top_threats = []
        report.metadata = MagicMock()
        report.metadata.dump_path = "C:\\dumps\\mem.raw"
        report.metadata.dump_filename = "mem.raw"

        client = MagicMock()
        with patch(
            "forensiq.reporting.executive.ExecutiveReportGenerator"
        ) as mock_gen_cls:
            gen = mock_gen_cls.return_value
            gen.generate = AsyncMock(return_value="LLM summary text.")

            summary = await pipeline._run_executive_summary(
                report, client, "qwen2.5-coder:7b"
            )

        assert summary == "LLM summary text."


# ── _build_extraction_error ──────────────────────────────────────────────────


class TestBuildExtractionError:
    def test_missing_volatility_gives_guidance(self) -> None:
        fake_settings = MagicMock()
        fake_settings.get_volatility_executable.side_effect = FileNotFoundError(
            "vol not found"
        )
        with patch(
            "forensiq.pipeline.analysis_pipeline.get_settings",
            return_value=fake_settings,
        ):
            pipeline = _make_pipeline()
            msg = pipeline._build_extraction_error()

        assert "pip install volatility3" in msg
        assert "FORENSIQ_VOLATILITY_PATH" in msg

    def test_surfaces_underlying_exception(self) -> None:
        fake_settings = MagicMock()
        fake_settings.get_volatility_executable.return_value = "/usr/bin/vol"
        with patch(
            "forensiq.pipeline.analysis_pipeline.get_settings",
            return_value=fake_settings,
        ):
            pipeline = _make_pipeline()
            pipeline._extraction_exception = RuntimeError("plugin crashed")
            msg = pipeline._build_extraction_error()

        assert "plugin crashed" in msg
        assert "/usr/bin/vol" in msg


# ── Full run() without a usable LLM ──────────────────────────────────────────


class TestRunWithoutLLM:
    @pytest.mark.asyncio
    async def test_run_produces_report_with_llm_info_unavailable(self, tmp_path) -> None:
        pipeline = _make_pipeline()
        vectors = [_vec()]

        pipeline._check_sha256_cache = AsyncMock(return_value=None)
        pipeline._run_extraction = AsyncMock(return_value=_make_extraction())
        pipeline._run_feature_engineering = MagicMock(return_value=vectors)
        pipeline._run_classification = MagicMock(return_value=vectors)
        pipeline._run_explanation = MagicMock(return_value=vectors)
        pipeline._run_detectors = MagicMock(return_value=[])
        pipeline._persist_to_database = AsyncMock()

        with patch.object(
            pipeline,
            "_resolve_ollama_client",
            new=AsyncMock(return_value=(None, None)),
        ), patch.object(
            pipeline,
            "_run_yara_generation",
            new=AsyncMock(return_value=[]),
        ):
            result = await pipeline.run(
                dump_path=tmp_path / "test.raw",
                output_dir=tmp_path,
                correlation_id="test123",
            )

        assert result.exit_code == 0
        assert result.report is not None
        assert result.report.llm_info["status"] == "unavailable"
        assert result.report.llm_info["model"] == ""
        assert result.report.executive_summary.strip() != ""
