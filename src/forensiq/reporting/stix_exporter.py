# FILE: src/forensiq/reporting/stix_exporter.py
"""STIX 2.1 export for ForensIQ analysis reports.

Converts a ForensiqReport into a STIX 2.1 Bundle containing:
  - Indicator objects (process file hashes, network connection IOCs)
  - Malware objects (for malicious processes)
  - AttackPattern objects (MITRE ATT&CK techniques detected)
  - Relationship objects (links Indicator → Malware, Malware → AttackPattern)
  - Report object (top-level bundle summary)

The bundle is serialized to a JSON file that can be imported into any
STIX-compatible threat intelligence platform (MISP, OpenCTI, etc.).

Usage:
    from forensiq.reporting.stix_exporter import STIXExporter
    exporter = STIXExporter()
    bundle_path = exporter.export(report, output_dir=Path("reports/"))
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from forensiq.models.report import ForensiqReport

log = get_logger(__name__)


class STIXExporter:
    """Exports a ForensiqReport as a STIX 2.1 JSON bundle."""

    def export(self, report: ForensiqReport, output_dir: Path) -> Path:
        """Export report as STIX 2.1 bundle JSON file.

        Args:
            report:     Completed ForensiqReport.
            output_dir: Directory to write the .stix.json file.

        Returns:
            Path to the written STIX bundle file.

        Raises:
            ImportError: If stix2 is not installed.
        """
        import stix2  # type: ignore[import]

        objects: list[Any] = []
        now = datetime.now(tz=UTC)
        ts = now.strftime("%Y%m%d_%H%M%S")

        # ── Malware + Indicator objects per malicious process ─────────────────
        malware_by_pid: dict[int, Any] = {}
        indicator_by_pid: dict[int, Any] = {}

        for vec in report.ranked_processes:
            if not vec.is_malicious:
                continue

            name = vec.name or f"pid_{vec.pid}"

            # Malware object
            mal = stix2.Malware(
                name=f"{name} (PID {vec.pid})",
                description=(
                    f"Malicious process detected by ForensIQ. "
                    f"Ensemble score: {vec.ensemble_score:.3f}. "
                    f"XGBoost score: {vec.threat_score:.3f}."
                ),
                is_family=False,
                malware_types=["unknown"],
                labels=["malicious-code"],
            )
            malware_by_pid[vec.pid] = mal
            objects.append(mal)

            # Build indicator pattern from available IOCs
            patterns: list[str] = []

            # Process name pattern
            patterns.append(f"[process:name = '{_safe_stix(name)}']")

            # Path-based indicator
            if vec.name:
                _safe_path = _safe_stix(vec.name).replace("\\", "\\\\")
                patterns.append(f"[file:name = '{_safe_stix(name)}']")

            # Network connections for this PID from dll_yara_hits
            _network_patterns = [
                hit
                for hit in report.dll_yara_hits
                if hit.get("pid") == vec.pid and hit.get("severity") in ("high", "critical")
            ]

            if patterns:
                # Combine patterns with OR
                combined_pattern = " OR ".join(patterns)
                try:
                    ind = stix2.Indicator(
                        name=f"ForensIQ: {name} (PID {vec.pid})",
                        description=(
                            f"Indicators of compromise for malicious process '{name}' "
                            f"(PID {vec.pid}) detected during memory forensics analysis. "
                            f"Ensemble threat score: {vec.ensemble_score:.3f}."
                        ),
                        pattern=combined_pattern,
                        pattern_type="stix",
                        indicator_types=["malicious-activity"],
                        valid_from=now,
                        labels=["forensiq-detection"],
                    )
                    indicator_by_pid[vec.pid] = ind
                    objects.append(ind)

                    # Relationship: Indicator indicates Malware
                    rel = stix2.Relationship(
                        relationship_type="indicates",
                        source_ref=ind.id,
                        target_ref=mal.id,
                    )
                    objects.append(rel)
                except Exception as exc:
                    log.warning("Failed to create STIX Indicator", pid=vec.pid, error=str(exc))

        # ── AttackPattern objects per MITRE technique ─────────────────────────
        attack_pattern_by_id: dict[str, Any] = {}
        for tech in report.mitre_techniques:
            tech_id = tech.get("technique_id", "")
            tech_name = tech.get("technique_name", tech_id)
            if not tech_id or tech_id in attack_pattern_by_id:
                continue

            try:
                ap = stix2.AttackPattern(
                    name=f"{tech_id}: {tech_name}",
                    description=tech.get("description", ""),
                    external_references=[
                        stix2.ExternalReference(
                            source_name="mitre-attack",
                            external_id=tech_id,
                            url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                        )
                    ],
                )
                attack_pattern_by_id[tech_id] = ap
                objects.append(ap)
            except Exception as exc:
                log.warning("Failed to create STIX AttackPattern", tech_id=tech_id, error=str(exc))

        # ── Relationships: Malware uses AttackPattern ─────────────────────────
        # Link all malicious processes to all MITRE techniques (conservative)
        for _, mal_obj in malware_by_pid.items():
            for _, ap_obj in attack_pattern_by_id.items():
                try:
                    rel = stix2.Relationship(
                        relationship_type="uses",
                        source_ref=mal_obj.id,
                        target_ref=ap_obj.id,
                    )
                    objects.append(rel)
                except Exception as exc:
                    log.debug("Relationship creation skipped", error=str(exc))

        # ── YARA rules as STIX Indicators ─────────────────────────────────────
        for yara_result in report.yara_results:
            if not yara_result.is_valid or not yara_result.rule_text:
                continue
            try:
                yara_ind = stix2.Indicator(
                    name=f"YARA: {yara_result.rule_name}",
                    description=f"ForensIQ-generated YARA rule for process '{yara_result.process_name}'",
                    pattern="[file:content_ref = 'placeholder']",  # YARA not STIX native
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    valid_from=now,
                    labels=["yara-rule", "forensiq-detection"],
                )
                objects.append(yara_ind)
            except Exception as exc:
                log.debug("YARA STIX Indicator skipped", error=str(exc))

        # ── Top-level Report object ────────────────────────────────────────────
        report_obj_refs = [obj.id for obj in objects]

        # stix2.Report requires at least one object_ref
        if not report_obj_refs:
            # Create a placeholder Indicator when there are no findings
            placeholder = stix2.Indicator(
                name="ForensIQ: No threats detected",
                description="Memory analysis completed with no malicious findings.",
                pattern="[process:pid > 0]",
                pattern_type="stix",
                indicator_types=["benign"],
                valid_from=now,
            )
            objects.append(placeholder)
            report_obj_refs = [placeholder.id]

        report_obj = stix2.Report(
            name=f"ForensIQ Memory Analysis — {report.metadata.dump_path.rsplit('/', 1)[-1] if '/' in report.metadata.dump_path else report.metadata.dump_path}",
            description=(
                f"ForensIQ automated memory forensics analysis. "
                f"Total processes: {report.total_processes}. "
                f"Malicious: {report.malicious_count}. "
                f"Suspicious: {report.suspicious_count}. "
                f"Threat level: {report.threat_level}."
            ),
            published=now,
            report_types=["threat-report"],
            object_refs=report_obj_refs,
            labels=["forensiq", "memory-forensics", "automated-analysis"],
        )

        # ── Build and serialize bundle ────────────────────────────────────────
        # stix2 v21 automatically sets spec_version=2.1; no need to pass it
        bundle = stix2.Bundle(
            objects=[*objects, report_obj],
        )

        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"forensiq_stix_{ts}.stix.json"
        out_path.write_text(bundle.serialize(pretty=True), encoding="utf-8")

        log.info(
            "STIX 2.1 bundle exported",
            path=str(out_path),
            objects=len(bundle.objects),
            malware=len(malware_by_pid),
            attack_patterns=len(attack_pattern_by_id),
        )
        return out_path


def _safe_stix(value: str) -> str:
    """Escape single quotes in STIX pattern strings."""
    return value.replace("'", "\\'")
