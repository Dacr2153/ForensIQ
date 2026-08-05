# FILE: src/forensiq/reporting/builder.py
"""HTML forensic report builder using Jinja2 templates.

Renders the ForensiqReport data model to a self-contained HTML file.
The HTML report includes:
    - Executive summary (threat level, process counts, key findings)
    - Process table ranked by threat score with SHAP bar charts
    - Forensic timeline of detected events
    - YARA rules generated (with syntax highlighting)
    - Model info panel
    - Full CSS + JavaScript inline (no external CDN dependencies)

Usage:
    from forensiq.reporting.builder import ReportBuilder
    from forensiq.models.report import ForensiqReport

    builder = ReportBuilder()
    output_path = builder.render(report, output_dir=Path("./reports"))
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup

from forensiq.models.report import ForensiqReport
from forensiq.utils.exceptions import ReportError
from forensiq.utils.logger import get_logger

log = get_logger(__name__)


def _json_for_script(value: object) -> Markup:
    """Serialize ``value`` to JSON safe to embed in an HTML ``<script>`` block.

    ``json.dumps`` does not escape ``<``, ``>`` or ``&`` (or U+2028/U+2029),
    so attacker-controlled strings (process names, timeline descriptions) can
    break out of a JS string literal and inject markup — a stored-XSS vector
    in generated reports.  Re-encoding those characters as ``\\uXXXX`` escapes
    keeps the JSON valid while neutralising the script-context breakout.
    """
    encoded = json.dumps(value, ensure_ascii=False)
    escaped = (
        encoded.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    # Deliberate Markup: content is escaped above BEFORE wrapping, so this is
    # the safe (and only) way to inject JSON into a <script> block without
    # double-escaped strings corrupting the literal.
    return Markup(escaped)  # noqa: S704


class ReportBuilder:
    """Renders a ForensiqReport to a self-contained HTML file.

    Uses Jinja2 with templates from the forensiq.reporting.templates package.
    The output is a single .html file with all CSS/JS inlined.
    """

    def __init__(self) -> None:
        try:
            self._env = Environment(
                loader=PackageLoader("forensiq", "reporting/templates"),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        except Exception:
            # Fallback: use filesystem loader relative to this file
            from jinja2 import FileSystemLoader

            templates_dir = Path(__file__).parent / "templates"
            self._env = Environment(
                loader=FileSystemLoader(str(templates_dir)),
                autoescape=select_autoescape(["html", "xml"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )

        # Register custom filters
        self._env.filters["format_score"] = lambda s: f"{s:.1%}"
        self._env.filters["format_size"] = self._format_size
        self._env.filters["format_dt"] = lambda dt: (
            dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "N/A"
        )
        self._env.filters["json_script"] = _json_for_script

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte count as human-readable size string."""
        value: float = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024:
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} PB"

    def _build_report_filename(self, report: ForensiqReport) -> str:
        """Generate a timestamped report filename.

        Args:
            report: The ForensiqReport to name.

        Returns:
            Filename like 'forensiq_memory_20240115_103045.html'.
        """
        dump_stem = Path(report.metadata.dump_path).stem
        # Sanitize: remove non-alphanumeric characters except hyphen and underscore
        import re

        safe_stem = re.sub(r"[^a-zA-Z0-9_-]", "_", dump_stem)[:50]
        timestamp = report.metadata.analysis_start.strftime("%Y%m%d_%H%M%S")
        return f"forensiq_{safe_stem}_{timestamp}.html"

    def render(
        self,
        report: ForensiqReport,
        output_dir: Path,
    ) -> Path:
        """Render the report to an HTML file.

        Args:
            report: The complete ForensiqReport to render.
            output_dir: Directory where the HTML file will be saved.

        Returns:
            Path to the generated HTML file.

        Raises:
            ReportError: If template rendering or file writing fails.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = self._build_report_filename(report)
        output_path = output_dir / filename

        log.info("Rendering HTML report", output=str(output_path))

        try:
            template = self._env.get_template("report.html.j2")
        except Exception as exc:
            raise ReportError(
                output_path=str(output_path),
                reason=f"Template not found: {exc}",
            ) from exc

        # Prepare template context
        context = {
            "report": report,
            "metadata": report.metadata,
            "ranked_processes": report.ranked_processes,
            "timeline": sorted(report.timeline, key=lambda e: e.timestamp),
            "yara_results": report.yara_results,
            "valid_yara_results": [r for r in report.yara_results if r.is_valid],
            "top_threats": report.top_threats,
            "generated_at": datetime.now(tz=UTC),
            "threat_level_color": {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#16a34a",
            },
            # Timeline events as JSON for the interactive canvas chart.  The
            # json_script filter serialises AND escapes for <script> context.
            "timeline_json": [
                {
                    "idx": i,
                    "ts": e.timestamp.timestamp() if e.timestamp else 0,
                    "pid": e.pid,
                    "process_name": e.process_name,
                    "severity": e.severity,
                    "mitre_technique": e.mitre_technique or "",
                    "mitre_technique_name": e.mitre_technique_name or "",
                    "description": e.description,
                }
                for i, e in enumerate(sorted(report.timeline, key=lambda ev: ev.timestamp))
            ],
        }

        try:
            html_content = template.render(**context)
        except Exception as exc:
            raise ReportError(
                output_path=str(output_path),
                reason=f"Template rendering failed: {exc}",
            ) from exc

        try:
            output_path.write_text(html_content, encoding="utf-8")
        except OSError as exc:
            raise ReportError(
                output_path=str(output_path),
                reason=f"Failed to write HTML file: {exc}",
            ) from exc

        log.info(
            "Report generated",
            path=str(output_path),
            size_kb=round(len(html_content.encode()) / 1024, 1),
        )
        return output_path
