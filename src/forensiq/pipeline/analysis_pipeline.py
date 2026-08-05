# FILE: src/forensiq/pipeline/analysis_pipeline.py
"""Top-level analysis pipeline that chains all ForensIQ components.

This module orchestrates the complete forensic analysis workflow:

    1. Extraction — Run all Volatility 3 plugins and gather raw artifacts
    2. Feature Engineering — Compute 20 per-process ML features
    3. Classification — XGBoost + CalibratedClassifierCV threat scoring
    4. Explanation — SHAP feature attribution for malicious processes
    5. YARA Generation — Ollama rule generation + yara-python validation
       (uses the configured Ollama model, auto-falling back to any installed
       model; skipped entirely when no local model is available)
    6. Report Building — HTML + JSON report output
       (executive summary falls back to a deterministic rule-based summary
       when no local AI model is available)

Usage:
    import asyncio
    from forensiq.pipeline.analysis_pipeline import AnalysisPipeline

    pipeline = AnalysisPipeline()
    result = asyncio.run(pipeline.run(
        dump_path=Path("/cases/dump.raw"),
        output_dir=Path("./reports"),
    ))
    # result.exit_code: 0=clean, 1=threats found, 2=error
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from forensiq.config.settings import get_settings
from forensiq.extraction.orchestrator import ExtractionOrchestrator, ExtractionResult
from forensiq.features.engineer import FeatureEngineer
from forensiq.ml.classifier import ForensiqClassifier
from forensiq.ml.explainer import SHAPExplainer
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.report import (
    DumpMetadata,
    ForensiqReport,
)
from forensiq.pipeline.dump_context import DumpContext
from forensiq.pipeline.timeline import build_timeline
from forensiq.reporting.builder import ReportBuilder
from forensiq.utils.exceptions import (
    AcquisitionError,
    ClassificationError,
)
from forensiq.utils.logger import bind_analysis_context, get_logger, set_phase

log = get_logger(__name__)

# ── Linux heuristic scoring ───────────────────────────────────────────────────

_LINUX_HEURISTIC_SCORE: dict[str, float] = {
    "critical": 0.85,
    "high": 0.70,  # Corroborated evidence required to reach HIGH; clear margin above threshold
    "medium": 0.45,  # Suspicious but below default 0.65 threshold — not marked malicious
    "low": 0.20,
    "info": 0.0,
}


def _apply_linux_heuristic_scores(
    vectors: list[ProcessFeatureVector],
    detector_findings: list,
    threshold: float = 0.65,
) -> list[ProcessFeatureVector]:
    """Assign heuristic threat scores to Linux process vectors from detector findings.

    The XGBoost model is trained on Windows memory and cannot be applied to Linux
    dumps.  Instead, we derive a threat_score from the highest-severity detector
    finding for each process so that the rest of the pipeline (timeline, top_threats,
    YARA generation, suspicious_count) can produce meaningful output.

    Score mapping:
        critical finding → 0.85  (marked malicious well above default 0.65 threshold)
        high     finding → 0.70  (marked malicious; HIGH requires corroborated evidence)
        medium   finding → 0.45  (suspicious but NOT malicious at default threshold)
        low/info finding → 0.20 / 0.0  (informational, not malicious)

    Args:
        vectors: Per-process feature vectors (threat_score = 0.0 post-classification skip).
        detector_findings: All DetectorResult objects from the detector phase.

    Returns:
        Updated vector list with heuristic threat_score and ensemble_score set.
    """
    # Build a map: PID → highest heuristic score from detector findings
    pid_score: dict[int, float] = {}
    for finding in detector_findings:
        severity_key = (
            finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        )
        score = _LINUX_HEURISTIC_SCORE.get(severity_key.lower(), 0.0)
        pid_score[finding.pid] = max(pid_score.get(finding.pid, 0.0), score)

    if not pid_score:
        return vectors

    updated: list[ProcessFeatureVector] = []
    for v in vectors:
        score = pid_score.get(v.pid, 0.0)
        if score > 0.0:
            updated.append(
                v.model_copy(
                    update={
                        "threat_score": score,
                        "ensemble_score": score,
                        "is_malicious": score >= threshold,
                    }
                )
            )
        else:
            updated.append(v)

    # Re-sort by threat_score descending (mirrors classifier behavior)
    updated.sort(key=lambda x: x.threat_score, reverse=True)
    return updated


@dataclass
class PipelineResult:
    """Result of a complete analysis pipeline run.

    Attributes:
        report: The complete ForensiqReport (None if failed before report stage).
        report_path: Path to the generated HTML report.
        json_path: Path to the generated JSON report.
        yara_dir: Path to exported YARA rule files.
        exit_code: 0=clean, 1=threats found, 2=analysis error.
        error: Error message if exit_code == 2.
    """

    report: ForensiqReport | None = None
    report_path: Path | None = None
    json_path: Path | None = None
    yara_dir: Path | None = None
    exit_code: int = 0
    error: str = ""


class AnalysisPipeline:
    """Orchestrates the complete ForensIQ memory forensics analysis.

    This class chains all analysis components in sequence with structured
    logging and progress tracking at each phase.

    Args:
        show_progress: Display Rich progress bars in the terminal.
        generate_yara: Generate YARA rules for malicious processes (requires Ollama).
        generate_html: Generate HTML report.
        generate_json: Generate JSON report.
        on_stage_complete: Optional callback called after each pipeline stage completes.
            Signature: callback(stage: str, data: Any) where stage is one of
            "extraction", "classification", "detectors", "mitre", "yara", "report".
            This enables streaming/incremental output to the CLI.
    """

    def __init__(
        self,
        show_progress: bool = True,
        generate_yara: bool = True,
        generate_html: bool = True,
        generate_json: bool = True,
        on_stage_complete: Callable[[str, Any], None] | None = None,
        force_reanalyze: bool = False,
        on_cached_result: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        self._settings = get_settings()
        self._show_progress = show_progress
        self._generate_yara = generate_yara
        self._generate_html = generate_html
        self._generate_json = generate_json
        self._on_stage_complete = on_stage_complete
        self._force_reanalyze = force_reanalyze
        # Callback invoked when a cached analysis is found.
        # Receives the cached analysis dict, returns True to proceed with full
        # reanalysis or False to accept the cached result.
        self._on_cached_result = on_cached_result
        # Set when extraction raises, so _build_extraction_error() can surface
        # the underlying cause in the "Analysis failed" message.
        self._extraction_exception: Exception | None = None

    def _emit(self, stage: str, data: Any) -> None:
        """Emit a streaming event to the registered callback (if any)."""
        if self._on_stage_complete is not None:
            try:
                self._on_stage_complete(stage, data)
            except Exception:  # noqa: S110
                pass  # Never let callback errors break the pipeline

    async def run(
        self,
        dump_path: Path,
        output_dir: Path,
        threshold: float | None = None,
        correlation_id: str | None = None,
    ) -> PipelineResult:
        """Run the complete analysis pipeline.

        Args:
            dump_path: Absolute path to the memory dump file (Windows raw/vmem/dmp or Linux LiME/kcore).
            output_dir: Directory where reports and YARA rules are saved.
            threshold: Override the configured threat threshold (0.0-1.0).
            correlation_id: Optional correlation ID for log tracing.

        Returns:
            PipelineResult with report, paths, and exit code.
        """
        import uuid

        corr_id = correlation_id or str(uuid.uuid4())[:8]

        effective_threshold = (
            threshold if threshold is not None else self._settings.THREAT_THRESHOLD
        )

        with bind_analysis_context(
            correlation_id=corr_id,
            dump_path=str(dump_path),
            phase="init",
        ):
            log.info(
                "ForensIQ analysis started",
                dump=str(dump_path),
                threshold=effective_threshold,
                correlation_id=corr_id,
            )

            start_time = time.monotonic()

            # ── Phase 0: SHA-256 Cache Check ──────────────────────────────
            # Compute SHA-256 of the dump before running any plugins.
            # If the same dump was analyzed before, show the user the
            # previous result and ask whether to re-analyze.
            if not self._force_reanalyze:
                cached_info = await self._check_sha256_cache(dump_path)
                if cached_info is not None:
                    # Emit the cached result to CLI for display
                    self._emit("cached_result", cached_info)
                    # Ask caller whether to proceed with full analysis
                    if self._on_cached_result is not None:
                        should_reanalyze = self._on_cached_result(cached_info)
                    else:
                        # Non-interactive: skip reanalysis by default
                        should_reanalyze = False

                    if not should_reanalyze:
                        log.info(
                            "Using cached analysis result",
                            sha256=cached_info.get("dump_sha256", "")[:12],
                            analysis_id=cached_info.get("id"),
                        )
                        return PipelineResult(
                            exit_code=1 if cached_info.get("malicious_count", 0) > 0 else 0,
                            error="",
                        )

            # ── Phase 1: Extraction ────────────────────────────────────────
            set_phase("extraction")
            extraction = await self._run_extraction(dump_path)
            if extraction is None:
                return PipelineResult(
                    exit_code=2,
                    error=self._build_extraction_error(),
                )

            # Build immutable OS + threshold context — single source of truth.
            # All pipeline stages receive this object instead of bare flags.
            ctx = DumpContext.from_path(
                dump_path=dump_path,
                threshold=effective_threshold,
                correlation_id=corr_id,
            )

            # ── Phase 2: Feature Engineering ──────────────────────────────
            set_phase("feature_engineering")
            vectors = self._run_feature_engineering(extraction)
            if not vectors:
                return PipelineResult(exit_code=2, error="Feature engineering produced no vectors")

            # ── Phase 3: Classification ────────────────────────────────────
            set_phase("classification")
            vectors = self._run_classification(vectors, ctx)
            # Streaming: emit classified vectors so CLI can show partial results
            self._emit("classification", vectors)

            # ── Phase 4: SHAP Explanation ─────────────────────────────────
            set_phase("explanation")
            vectors = self._run_explanation(vectors, ctx)

            # ── Phase 5: Detector Plugin System ───────────────────────────
            set_phase("detectors")
            detector_findings = self._run_detectors(extraction, vectors, ctx)
            # Streaming: emit detector findings as soon as all plugins finish
            self._emit("detectors", detector_findings)

            # ── Phase 5b: Linux heuristic scoring ─────────────────────────
            # The XGBoost model is trained on Windows data and is skipped for
            # Linux dumps.  After the detectors run, we assign a heuristic
            # threat_score to each process based on detector finding severity so
            # that downstream pipeline stages (timeline, top_threats, suspicious
            # count, YARA) can produce meaningful output.
            if ctx.is_linux and detector_findings:
                vectors = _apply_linux_heuristic_scores(
                    vectors, detector_findings, threshold=ctx.threshold
                )
                log.info(
                    "Linux heuristic scores applied from detector findings",
                    flagged=sum(1 for v in vectors if v.threat_score > 0),
                )

            # ── Phase 6: Timeline Building ────────────────────────────────
            set_phase("timeline")
            timeline = build_timeline(vectors, is_linux=ctx.is_linux)
            log.info("Timeline built", events=len(timeline))

            # ── Phase 7: YARA Generation ──────────────────────────────────
            # Resolve the Ollama client + model once per run so YARA
            # generation and the executive summary agree on which model to use.
            # When no local AI model is available this gracefully disables the
            # AI features and the pipeline continues with a basic report.
            llm_client, resolved_model = await self._resolve_ollama_client()
            yara_results: list = []
            if self._generate_yara and self._settings.YARA_GENERATE:
                set_phase("yara_generation")
                yara_results = await self._run_yara_generation(
                    vectors, extraction, llm_client, resolved_model
                )
                self._emit("yara", yara_results)

            # ── Phase 7b: DLL / Malfind YARA Scanning ────────────────────
            # Scan injected memory regions against built-in YARA rules.
            # This is a fast, offline scan (no Ollama required).
            set_phase("dll_yara_scan")
            dll_yara_hits: list = []
            try:
                from forensiq.yara.dll_scanner import YARADLLScanner

                dll_scanner = YARADLLScanner()
                if dll_scanner.is_ready:
                    malicious_pids = {v.pid for v in vectors if v.is_malicious}
                    suspicious_pids = {v.pid for v in vectors if v.ensemble_score >= 0.30}
                    scan_pids = malicious_pids | suspicious_pids
                    dll_yara_hits = dll_scanner.scan_extraction(
                        extraction, suspicious_pids=scan_pids or None
                    )
                    log.info("DLL YARA scan complete", hits=len(dll_yara_hits))
                    self._emit("dll_yara", dll_yara_hits)
            except Exception as exc:
                log.warning("DLL YARA scan failed (non-fatal)", error=str(exc))

            # ── Phase 8: MITRE ATT&CK aggregation ────────────────────────
            set_phase("mitre_mapping")
            from forensiq.models.mitre import build_mitre_summary

            mitre_techniques = build_mitre_summary(timeline, detector_findings)
            log.info("MITRE ATT&CK techniques mapped", count=len(mitre_techniques))
            self._emit("mitre", mitre_techniques)

            # ── Phase 9: Build Report Object ──────────────────────────────
            set_phase("report_building")
            import importlib.metadata

            try:
                forensiq_version = importlib.metadata.version("forensiq")
            except Exception:
                forensiq_version = "dev"

            from datetime import datetime

            metadata = DumpMetadata(
                dump_path=str(dump_path.resolve()),
                dump_sha256=extraction.dump_sha256 or "",
                dump_size_bytes=extraction.dump_size_bytes,
                analysis_start=datetime.now(tz=UTC),
                analysis_end=datetime.now(tz=UTC),
                volatility_version=extraction.volatility_version or "unknown",
                forensiq_version=forensiq_version,
                os_profile=None,
            )

            malicious_processes = [v for v in vectors if v.is_malicious]
            suspicious_processes = [
                v for v in vectors if v.threat_score >= 0.35 and not v.is_malicious
            ]

            model_info: dict[str, str] = {}
            model_path = self._settings.get_model_path()
            if model_path.exists():
                meta_path = model_path.with_suffix(".json")
                if meta_path.exists():
                    import json

                    try:
                        with meta_path.open() as f:
                            saved_meta = json.load(f)
                        model_info = {k: str(v) for k, v in saved_meta.items()}
                    except Exception:  # noqa: S110
                        pass  # Corrupt/missing metadata is not fatal

            if resolved_model is not None:
                llm_status = "ok"
            else:
                llm_status = "unavailable"
            llm_info = {
                "model": resolved_model or "",
                "status": llm_status,
                "requested_model": self._settings.OLLAMA_MODEL,
            }

            report = ForensiqReport(
                metadata=metadata,
                total_processes=len(vectors),
                suspicious_count=len(suspicious_processes),
                malicious_count=len(malicious_processes),
                timeline=timeline,
                ranked_processes=vectors,
                yara_results=yara_results,
                model_info=model_info,
                llm_info=llm_info,
                detector_findings=[f.to_dict() for f in detector_findings],
                mitre_techniques=mitre_techniques,
                dll_yara_hits=[
                    {
                        "pid": h.pid,
                        "process_name": h.process_name,
                        "region_start": h.region_start,
                        "region_end": h.region_end,
                        "rule_name": h.rule_name,
                        "description": h.rule_description,
                        "severity": h.severity,
                        "match_strings": h.match_strings,
                    }
                    for h in dll_yara_hits
                ],
            )

            # ── Phase 10: Executive Summary (optional, via Ollama) ─────────
            # Always attempt: _run_executive_summary falls back gracefully if
            # Ollama is unavailable.  Executive summary generation is independent
            # of YARA rule generation and should not be gated by YARA_GENERATE.
            report.executive_summary = await self._run_executive_summary(
                report, llm_client, resolved_model
            )

            # ── Phase 11: Persist to SQLite ────────────────────────────────
            await self._persist_to_database(report, detector_findings, yara_results)

            # ── Phase 12: Write Outputs ────────────────────────────────────
            output_dir.mkdir(parents=True, exist_ok=True)
            result = PipelineResult(report=report)

            if self._generate_html:
                result.report_path = self._write_html_report(report, output_dir)

            if self._generate_json:
                result.json_path = self._write_json_report(report, output_dir)

            if yara_results:
                yara_dir = output_dir / "yara_rules"
                from forensiq.yara.generator import YARAGenerator

                gen = YARAGenerator()
                gen.export_valid_rules(yara_results, yara_dir)
                result.yara_dir = yara_dir

            # ── Final exit code ────────────────────────────────────────────
            result.exit_code = 1 if len(malicious_processes) > 0 else 0

            elapsed = time.monotonic() - start_time
            log.info(
                "Analysis complete",
                duration_seconds=round(elapsed, 2),
                malicious=len(malicious_processes),
                detector_findings=len(detector_findings),
                mitre_techniques=len(mitre_techniques),
                exit_code=result.exit_code,
            )

            return result

    async def _check_sha256_cache(self, dump_path: Path) -> dict[str, Any] | None:
        """Compute dump SHA-256 and check the database for a previous analysis.

        Returns the cached analysis record dict if found, or None.
        Computing the hash is a blocking operation run in an executor thread.
        """
        import hashlib

        log.info("Computing dump SHA-256 for cache check...", dump=dump_path.name)

        def _compute_sha256(path: Path) -> str:
            sha256 = hashlib.sha256()
            with path.open("rb") as fh:
                while chunk := fh.read(64 * 1024 * 1024):
                    sha256.update(chunk)
            return sha256.hexdigest()

        try:
            loop = asyncio.get_event_loop()
            sha256 = await loop.run_in_executor(None, _compute_sha256, dump_path)
        except Exception as exc:
            log.warning("SHA-256 pre-check failed", error=str(exc))
            return None

        log.info("Dump SHA-256 computed", sha256=sha256[:16], dump=dump_path.name)

        try:
            from forensiq.db.manager import ForensiqDatabase

            async with ForensiqDatabase() as db:
                cached = await db.get_analysis_by_sha256(sha256)
                return cached
        except Exception as exc:
            log.debug("SHA-256 DB cache check failed (non-fatal)", error=str(exc))
            return None

    async def _run_extraction(self, dump_path: Path) -> ExtractionResult | None:
        """Run Volatility 3 extraction using true asyncio concurrency.

        Uses asyncio.create_subprocess_exec under the hood so multiple plugins
        run as independent OS processes concurrently with no GIL overhead.

        Args:
            dump_path: Path to the memory dump.

        Returns:
            ExtractionResult or None on failure.
        """
        try:
            orchestrator = ExtractionOrchestrator(
                dump_path=dump_path,
                compute_hash=True,
                show_progress=self._show_progress,
            )
            # True async — no run_in_executor needed; each plugin is a subprocess
            extraction = await orchestrator.run_async()
            log.info(
                "Extraction complete",
                processes=len(extraction.process_tree.flat_map) if extraction.process_tree else 0,
                failed_plugins=extraction.failed_plugins,
            )
            return extraction
        except AcquisitionError as exc:
            log.error("Extraction failed", error=str(exc))
            self._extraction_exception = exc
            return None
        except Exception as exc:
            log.error("Unexpected extraction error", error=str(exc))
            self._extraction_exception = exc
            return None

    def _build_extraction_error(self) -> str:
        """Build a targeted error message for a failed extraction phase.

        When the Volatility 3 executable cannot be located the message points
        the user at the two most likely fixes; otherwise the underlying
        exception is surfaced so "Analysis failed — no report generated" is
        self-explanatory.
        """
        try:
            vol_path = self._settings.get_volatility_executable()
        except Exception as exc:
            return (
                "Extraction failed — Volatility 3 executable could not be located. "
                "Install it with 'pip install volatility3' or set "
                "FORENSIQ_VOLATILITY_PATH=<path-to-vol> in your .env file. "
                f"(detail: {exc})"
            )

        exc = getattr(self, "_extraction_exception", None)
        if exc is not None:
            return (
                "Extraction failed — Volatility 3 could not analyze this memory dump. "
                f"Executable: {vol_path}. Detail: {exc}"
            )
        return "Extraction failed — check Volatility 3 installation"

    async def _resolve_ollama_client(self) -> tuple[Any, str | None]:
        """Create an OllamaClient and pick which installed model to use.

        Resolution happens once per run so YARA generation and the executive
        summary agree on the model in use.  When Ollama is unreachable or has
        no models installed this returns ``(None, None)`` so callers can
        gracefully degrade to a basic report.

        Returns:
            ``(client, resolved_model)``.
        """
        from forensiq.llm.ollama_client import OllamaClient

        client = OllamaClient(
            base_url=self._settings.OLLAMA_BASE_URL,
            model=self._settings.OLLAMA_MODEL,
            timeout=self._settings.OLLAMA_TIMEOUT,
        )
        try:
            resolved_model = await client.resolve_model()
        except Exception as exc:
            log.warning(
                "Ollama model resolution failed — AI features disabled",
                error=str(exc),
            )
            return None, None
        if resolved_model is None:
            log.warning(
                "No usable Ollama model — AI features disabled, using basic report",
                requested_model=self._settings.OLLAMA_MODEL,
            )
            return None, None
        if resolved_model != self._settings.OLLAMA_MODEL:
            log.warning(
                "Configured model unavailable — using fallback model",
                requested_model=self._settings.OLLAMA_MODEL,
                resolved_model=resolved_model,
            )
        return client, resolved_model

    def _run_feature_engineering(
        self,
        extraction: ExtractionResult,
    ) -> list[ProcessFeatureVector]:
        """Compute per-process features from extraction result.

        Args:
            extraction: Full extraction result.

        Returns:
            List of ProcessFeatureVector (sorted by PID).
        """
        engineer = FeatureEngineer()
        vectors = engineer.compute(extraction)
        log.info("Feature engineering complete", vectors=len(vectors))
        return vectors

    def _run_classification(
        self,
        vectors: list[ProcessFeatureVector],
        ctx: DumpContext,
    ) -> list[ProcessFeatureVector]:
        """Run XGBoost classification on all process feature vectors.

        Falls back gracefully if model is not available (returns vectors unchanged).
        Skips the Windows-trained XGBoost model entirely for Linux dumps: the model
        was trained on CIC-MalMem2022 (Windows processes) so its scores are
        meaningless on Linux and produce 100% false-positive rates.

        Args:
            vectors: Feature vectors to classify.
            ctx: Runtime dump context (OS profile + threshold).

        Returns:
            Classified vectors sorted by threat_score descending.
        """
        if ctx.is_linux:
            log.info(
                "Linux dump — skipping Windows XGBoost model (CIC-MalMem2022 is Windows-only)",
                count=len(vectors),
            )
            return vectors

        classifier = ForensiqClassifier()
        classifier.threshold = ctx.threshold
        model_path = self._settings.get_model_path()

        if not self._settings.is_model_available():
            log.warning(
                "Model not found — classification skipped, all scores set to 0.0",
                model_path=str(model_path),
            )
            return vectors

        try:
            classifier.load_model(model_path)
            classified = classifier.predict_batch(vectors)
            malicious_count = sum(1 for v in classified if v.is_malicious)
            log.info(
                "Classification complete",
                total=len(classified),
                malicious=malicious_count,
                threshold=ctx.threshold,
            )
            return classified
        except ClassificationError as exc:
            log.error("Classification failed", error=str(exc))
            return vectors
        except Exception as exc:
            log.error("Unexpected classification error", error=str(exc))
            return vectors

    def _run_explanation(
        self,
        vectors: list[ProcessFeatureVector],
        ctx: DumpContext,
    ) -> list[ProcessFeatureVector]:
        """Run SHAP explanation on classified vectors.

        Only explains malicious processes to save time. Non-fatal on failure.
        Skipped for Linux dumps since the Windows XGBoost model is not used.

        Args:
            vectors: Classified feature vectors.
            ctx: Runtime dump context (OS profile + threshold).

        Returns:
            Vectors with shap_values populated for malicious processes.
        """
        if ctx.is_linux:
            return vectors

        classifier = ForensiqClassifier()
        classifier.threshold = self._settings.THREAT_THRESHOLD
        if not self._settings.is_model_available():
            return vectors

        try:
            classifier.load_model(self._settings.get_model_path())
            explainer = SHAPExplainer(classifier.model)
            explained = explainer.explain_batch(vectors)
            log.info("SHAP explanation complete", vectors=len(explained))
            return explained
        except Exception as exc:
            log.warning("SHAP explanation failed (non-fatal)", error=str(exc))
            return vectors

    async def _run_yara_generation(
        self,
        vectors: list[ProcessFeatureVector],
        extraction: ExtractionResult,
        llm_client: Any | None,
        resolved_model: str | None,
    ) -> list:
        """Generate YARA rules for malicious processes via Ollama.

        Returns empty list if Ollama is unavailable or no model resolved
        (non-fatal).

        Args:
            vectors: Classified feature vectors.
            extraction: Full extraction result for IOC gathering.
            llm_client: Resolved OllamaClient (None when no usable model).
            resolved_model: Model selected by _resolve_ollama_client (None when
                Ollama is unreachable or no model is installed).

        Returns:
            List of YARAResult objects.
        """
        from forensiq.yara.generator import YARAGenerator

        if llm_client is None or resolved_model is None:
            log.warning(
                "No usable Ollama model — YARA generation skipped",
                url=self._settings.OLLAMA_BASE_URL,
            )
            return []

        generator = YARAGenerator(client=llm_client)
        try:
            results = await generator.generate_for_malicious(
                vectors=vectors,
                extraction=extraction,
                max_rules=10,
            )
            return results
        except Exception as exc:
            log.error("YARA generation pipeline failed", error=str(exc))
            return []

    def _write_html_report(
        self,
        report: ForensiqReport,
        output_dir: Path,
    ) -> Path | None:
        """Write the HTML report to disk.

        Args:
            report: Complete ForensiqReport.
            output_dir: Target directory.

        Returns:
            Path to the HTML file, or None on failure.
        """
        try:
            builder = ReportBuilder()
            path = builder.render(report, output_dir)
            log.info("HTML report written", path=str(path))
            return path
        except Exception as exc:
            log.error("HTML report generation failed", error=str(exc))
            return None

    def _write_json_report(
        self,
        report: ForensiqReport,
        output_dir: Path,
    ) -> Path | None:
        """Write the full report as JSON for programmatic consumption.

        Args:
            report: Complete ForensiqReport.
            output_dir: Target directory.

        Returns:
            Path to the JSON file, or None on failure.
        """
        try:
            import re
            from pathlib import Path as PathType

            dump_stem = PathType(report.metadata.dump_path).stem
            safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "_", dump_stem)[:50]
            timestamp = report.metadata.analysis_start.strftime("%Y%m%d_%H%M%S")
            json_filename = f"forensiq_{safe_stem}_{timestamp}.json"
            json_path = output_dir / json_filename

            json_content = report.model_dump_json(indent=2)
            json_path.write_text(json_content, encoding="utf-8")
            log.info("JSON report written", path=str(json_path))
            return json_path
        except Exception as exc:
            log.error("JSON report generation failed", error=str(exc))
            return None

    def _run_detectors(
        self,
        extraction: ExtractionResult,
        vectors: list[ProcessFeatureVector],
        ctx: DumpContext,
    ) -> list:
        """Run all registered detector plugins.

        Windows-only detectors (psscan, svcscan, handles) are excluded
        automatically when ctx.is_linux is True.

        Returns:
            List of DetectorResult findings.
        """
        from forensiq.detectors.registry import build_default_registry

        try:
            registry = build_default_registry(is_linux=ctx.is_linux)
            findings = registry.run_all(extraction, vectors)
            log.info(
                "Detector plugins complete",
                detectors=len(registry),
                findings=len(findings),
            )
            return findings
        except Exception as exc:
            log.warning("Detector registry failed (non-fatal)", error=str(exc))
            return []

    async def _run_executive_summary(
        self,
        report: ForensiqReport,
        llm_client: Any | None,
        resolved_model: str | None,
    ) -> str:
        """Generate executive summary via Ollama LLM (non-fatal).

        Always returns a non-empty string: when no usable LLM is available, or
        generation fails, a deterministic rule-based summary is produced so the
        report is complete even without a local AI model.

        Args:
            report: Complete ForensiqReport.
            llm_client: Resolved OllamaClient (None when no usable model).
            resolved_model: Model selected by _resolve_ollama_client.

        Returns:
            Executive summary string (never empty).
        """
        from forensiq.reporting.executive import ExecutiveReportGenerator

        generator = ExecutiveReportGenerator(client=llm_client)
        if llm_client is None or resolved_model is None:
            log.info(
                "Ollama not available — using rule-based executive summary",
                url=self._settings.OLLAMA_BASE_URL,
            )
            return generator._build_fallback_summary(report)

        try:
            summary = await generator.generate(report)
        except Exception as exc:
            log.warning("Executive summary failed", error=str(exc))
            return generator._build_fallback_summary(report)

        if summary.strip():
            return summary
        return generator._build_fallback_summary(report)

    async def _persist_to_database(
        self,
        report: ForensiqReport,
        detector_findings: list,
        yara_results: list,
    ) -> None:
        """Persist analysis results to SQLite database (non-fatal).

        Args:
            report: Complete ForensiqReport.
            detector_findings: List of DetectorResult objects.
            yara_results: List of YARAResult objects.
        """
        from forensiq.db.manager import ForensiqDatabase

        try:
            async with ForensiqDatabase() as db:
                analysis_id = await db.save_analysis(
                    dump_name=report.metadata.dump_filename,
                    dump_sha256=report.metadata.dump_sha256,
                    dump_size_bytes=report.metadata.dump_size_bytes,
                    forensiq_version=report.metadata.forensiq_version,
                    volatility_version=report.metadata.volatility_version,
                    total_processes=report.total_processes,
                    malicious_count=report.malicious_count,
                    suspicious_count=report.suspicious_count,
                    timeline_events=len(report.timeline),
                    yara_rules_count=len(yara_results),
                )
                if detector_findings:
                    await db.save_findings(analysis_id, detector_findings)
                if yara_results:
                    await db.save_yara_rules(analysis_id, yara_results)
                log.info("Analysis persisted to database", analysis_id=analysis_id)
        except Exception as exc:
            log.warning("Database persistence failed (non-fatal)", error=str(exc))
