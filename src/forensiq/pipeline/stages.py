# FILE: src/forensiq/pipeline/stages.py
"""Standalone pipeline stage implementations.

The AnalysisPipeline.run() method chains these stages in sequence.  They are
kept here (rather than as methods on the pipeline) to keep the pipeline class
focused on orchestration and streaming, while each stage owns its own I/O.

Stages here are intentionally stateless: all configuration is passed in via
the ``settings`` argument so they stay trivially testable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from forensiq.config.settings import Settings
from forensiq.detectors.base import DetectorResult
from forensiq.extraction.orchestrator import ExtractionResult
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.report import ForensiqReport, YARAResult
from forensiq.pipeline.dump_context import DumpContext
from forensiq.reporting.builder import ReportBuilder
from forensiq.utils.filename import safe_filename
from forensiq.utils.logger import get_logger

log = get_logger(__name__)


async def generate_yara_rules(
    settings: Settings,
    vectors: list[ProcessFeatureVector],
    extraction: ExtractionResult,
    llm_client: Any | None,
    resolved_model: str | None,
) -> list[YARAResult]:
    """Generate YARA rules for malicious processes via Ollama.

    Returns empty list if Ollama is unavailable or no model resolved
    (non-fatal).
    """
    from forensiq.yara.generator import YARAGenerator

    if llm_client is None or resolved_model is None:
        log.warning(
            "No usable Ollama model — YARA generation skipped",
            url=settings.OLLAMA_BASE_URL,
        )
        return []

    generator = YARAGenerator(client=llm_client)
    try:
        return await generator.generate_for_malicious(
            vectors=vectors,
            extraction=extraction,
            max_rules=10,
        )
    except Exception as exc:
        log.error("YARA generation pipeline failed", error=str(exc))
        return []


def write_html_report(report: ForensiqReport, output_dir: Path) -> Path | None:
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


def write_json_report(report: ForensiqReport, output_dir: Path) -> Path | None:
    """Write the full report as JSON for programmatic consumption.

    Args:
        report: Complete ForensiqReport.
        output_dir: Target directory.

    Returns:
        Path to the JSON file, or None on failure.
    """
    try:
        dump_stem = Path(report.metadata.dump_path).stem
        safe_stem = safe_filename(dump_stem)
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


def run_detectors(
    settings: Settings,
    extraction: ExtractionResult,
    vectors: list[ProcessFeatureVector],
    ctx: DumpContext,
) -> list[DetectorResult]:
    """Run all registered detector plugins.

    Windows-only detectors (psscan, svcscan, handles) are excluded
    automatically when ctx.is_linux is True.

    Returns:
        List of DetectorResult findings.
    """
    from forensiq.detectors.registry import build_default_registry

    try:
        registry = build_default_registry(
            is_linux=ctx.is_linux,
            vt_api_key=settings.VT_API_KEY,
        )
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


async def generate_executive_summary(
    settings: Settings,
    report: ForensiqReport,
    llm_client: Any | None,
    resolved_model: str | None,
) -> str:
    """Generate executive summary via Ollama LLM (non-fatal).

    Always returns a non-empty string: when no usable LLM is available, or
    generation fails, a deterministic rule-based summary is produced so the
    report is complete even without a local AI model.
    """
    from forensiq.reporting.executive import ExecutiveReportGenerator

    if llm_client is None or resolved_model is None:
        log.info(
            "Ollama not available — using rule-based executive summary",
            url=settings.OLLAMA_BASE_URL,
        )
        return ExecutiveReportGenerator(
            client=cast(Any, llm_client)
        )._build_fallback_summary(report)

    generator = ExecutiveReportGenerator(client=cast(Any, llm_client))

    try:
        summary = await generator.generate(report)
    except Exception as exc:
        log.warning("Executive summary failed", error=str(exc))
        return generator._build_fallback_summary(report)

    if summary.strip():
        return summary
    return generator._build_fallback_summary(report)


async def persist_to_database(
    report: ForensiqReport,
    detector_findings: list[DetectorResult],
    yara_results: list[YARAResult],
) -> None:
    """Persist analysis results to SQLite database (non-fatal)."""
    from forensiq.db.manager import ForensiqDatabase

    try:
        async with ForensiqDatabase() as db:
            analysis_id = await db.save_analysis_bundle(
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
                findings=detector_findings,
                yara_results=yara_results,
            )
            log.info("Analysis persisted to database", analysis_id=analysis_id)
    except Exception as exc:
        log.warning("Database persistence failed (non-fatal)", error=str(exc))
