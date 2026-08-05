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

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from forensiq.models.features import ProcessFeatureVector
from forensiq.pipeline.analysis_pipeline import AnalysisPipeline
from forensiq.pipeline.dump_context import DumpContext


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


def _ctx() -> DumpContext:
    """A non-Linux DumpContext so classification proceeds (Windows path)."""
    return DumpContext(
        dump_path=Path("/dumps/test.raw"),
        is_linux=False,
        threshold=0.65,
        correlation_id="test",
    )


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
        pipeline._run_classification = MagicMock(return_value=(vectors, ""))
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

    @pytest.mark.asyncio
    async def test_run_records_real_analysis_duration(self, tmp_path) -> None:
        """analysis_start/end must span the whole run (not both 'now' at the end)."""
        pipeline = _make_pipeline()
        vectors = [_vec()]

        pipeline._check_sha256_cache = AsyncMock(return_value=None)
        pipeline._run_extraction = AsyncMock(return_value=_make_extraction())
        pipeline._run_feature_engineering = MagicMock(return_value=vectors)
        pipeline._run_classification = MagicMock(return_value=(vectors, ""))
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
                correlation_id="duration-test",
            )

        assert result.report is not None
        start = result.report.metadata.analysis_start
        end = result.report.metadata.analysis_end
        assert end is not None
        assert end > start
        assert result.report.metadata.analysis_duration_seconds > 0

    @pytest.mark.asyncio
    async def test_run_forwards_precomputed_hash_to_extraction(self, tmp_path) -> None:
        """The hash computed by the cache check is reused, avoiding a second read."""
        pipeline = _make_pipeline()
        vectors = [_vec()]

        pipeline._check_sha256_cache = AsyncMock(return_value=None)
        extraction = _make_extraction()
        pipeline._run_feature_engineering = MagicMock(return_value=vectors)
        pipeline._run_classification = MagicMock(return_value=(vectors, ""))
        pipeline._run_explanation = MagicMock(return_value=vectors)
        pipeline._run_detectors = MagicMock(return_value=[])
        pipeline._persist_to_database = AsyncMock()

        # Simulate the precomputed hash being set by the cache pre-check
        pipeline._precomputed_sha256 = "b" * 64

        mock_orch = MagicMock()
        mock_orch.run_async = AsyncMock(return_value=extraction)

        with patch.object(
            pipeline,
            "_resolve_ollama_client",
            new=AsyncMock(return_value=(None, None)),
        ), patch.object(
            pipeline,
            "_run_yara_generation",
            new=AsyncMock(return_value=[]),
        ), patch(
            "forensiq.pipeline.analysis_pipeline.ExtractionOrchestrator",
            return_value=mock_orch,
        ) as mock_orch_cls:
            await pipeline.run(
                dump_path=tmp_path / "test.raw",
                output_dir=tmp_path,
                correlation_id="hash-reuse-test",
            )

        _, kwargs = mock_orch_cls.call_args
        assert kwargs["precomputed_sha256"] == "b" * 64


# ── _run_classification — degraded signalling ─────────────────────────────────


class TestRunClassificationDegraded:
    def _make_pipeline(self) -> AnalysisPipeline:
        return _make_pipeline()

    def test_returns_clean_pair_when_model_available_and_loads(
        self, tmp_path: Path
    ) -> None:
        from forensiq.config.settings import Settings

        pipeline = self._make_pipeline()
        model_path = tmp_path / "model.joblib"
        model_path.write_bytes(b"not really a model")
        pipeline._settings = Settings(MODEL_PATH=str(model_path), _env_file=None)

        fake_classifier = MagicMock()
        classified = [_vec(threat_score=0.1)]
        fake_classifier.predict_batch.return_value = classified

        with patch(
            "forensiq.pipeline.analysis_pipeline.ForensiqClassifier",
            return_value=fake_classifier,
        ):
            result, reason = pipeline._run_classification([_vec()], ctx=_ctx())

        assert reason == ""
        assert result == classified

    def test_returns_degraded_reason_when_model_missing(self, tmp_path: Path) -> None:
        from forensiq.config.settings import Settings

        pipeline = self._make_pipeline()
        pipeline._settings = Settings(
            MODEL_PATH=str(tmp_path / "no_such_model.joblib"), _env_file=None
        )

        result, reason = pipeline._run_classification([_vec()], ctx=_ctx())

        assert reason.startswith("ML model not found")
        assert len(result) == 1

    def test_returns_degraded_reason_on_classification_error(self, tmp_path: Path) -> None:
        from forensiq.config.settings import Settings

        pipeline = self._make_pipeline()
        corrupt_path = tmp_path / "corrupt.joblib"
        corrupt_path.write_bytes(b"not really a model")
        pipeline._settings = Settings(MODEL_PATH=str(corrupt_path), _env_file=None)

        fake_classifier = MagicMock()
        fake_classifier.predict_batch.side_effect = ValueError("model corrupt")

        with patch(
            "forensiq.pipeline.analysis_pipeline.ForensiqClassifier",
            return_value=fake_classifier,
        ):
            result, reason = pipeline._run_classification([_vec()], ctx=_ctx())

        assert "failed" in reason
        assert len(result) == 1

    def test_skips_linux_dump_without_degredation(self, tmp_path: Path) -> None:
        from forensiq.pipeline.dump_context import DumpContext

        pipeline = self._make_pipeline()
        linux_ctx = DumpContext(
            dump_path=Path("/proc/kcore"),
            is_linux=True,
            threshold=0.65,
            correlation_id="x",
        )
        result, reason = pipeline._run_classification([_vec()], ctx=linux_ctx)

        assert reason == ""
        assert len(result) == 1


# ── run() — degraded exit-code signalling ─────────────────────────────────────


class TestRunDegradedExitCode:
    @pytest.mark.asyncio
    async def test_degraded_clean_run_exits_3_with_reason(self, tmp_path) -> None:
        pipeline = _make_pipeline()
        vectors = [_vec()]

        pipeline._check_sha256_cache = AsyncMock(return_value=None)
        pipeline._run_extraction = AsyncMock(return_value=_make_extraction())
        pipeline._run_feature_engineering = MagicMock(return_value=vectors)
        pipeline._run_classification = MagicMock(return_value=(vectors, "ML model not found"))
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

        assert result.exit_code == 3
        assert result.degraded_reason == "ML model not found"
        assert result.report is not None
        assert result.report.degraded_reason == "ML model not found"

    @pytest.mark.asyncio
    async def test_degraded_with_malicious_still_exits_1(self, tmp_path) -> None:
        pipeline = _make_pipeline()
        vectors = [_vec(is_malicious=True, threat_score=0.9)]

        pipeline._check_sha256_cache = AsyncMock(return_value=None)
        pipeline._run_extraction = AsyncMock(return_value=_make_extraction())
        pipeline._run_feature_engineering = MagicMock(return_value=vectors)
        pipeline._run_classification = MagicMock(return_value=(vectors, "ML model corrupt"))
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

        assert result.exit_code == 1
        assert result.report is not None
        assert result.report.degraded_reason == "ML model corrupt"


# ── _check_sha256_cache — precomputed hash reuse ──────────────────────────────


class TestCheckSha256Cache:
    @pytest.mark.asyncio
    async def test_sets_precomputed_sha256(self, tmp_path) -> None:
        """The cache check stores the computed hash for reuse by extraction."""
        pipeline = _make_pipeline()
        dump_file = tmp_path / "mem.raw"
        dump_file.write_bytes(b"forensic dump content for hashing")

        from unittest.mock import AsyncMock

        mock_db_instance = MagicMock()
        mock_db_instance.__aenter__ = AsyncMock(return_value=mock_db_instance)
        mock_db_instance.__aexit__ = AsyncMock(return_value=None)
        mock_db_instance.get_analysis_by_sha256 = AsyncMock(return_value=None)

        with patch(
            "forensiq.db.manager.ForensiqDatabase", return_value=mock_db_instance
        ):
            cached = await pipeline._check_sha256_cache(dump_file)

        assert cached is None
        assert pipeline._precomputed_sha256 == (
            "b12cfdfb8549c5933d89c2e55222a47edb94881730c9ee0da6286e05379942e7"
        )
