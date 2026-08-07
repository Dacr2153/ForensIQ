# FILE: src/forensiq/yara/generator.py
"""YARA rule generation and validation for suspicious processes.

Generates YARA rules programmatically from extracted IOCs (deterministic,
guaranteed-valid syntax) and uses a local Ollama LLM only to enrich the
rule's description field. ALL generated rules are validated with yara-python
before being marked valid. Invalid rules are recorded but never exported as
working detections.

Pipeline for each suspicious process:
    1. Extract IOCs (process name, malfind hex, suspicious DLL names, cmdline fragments)
    2. Build a YARA rule programmatically from those IOCs
    3. Ask Ollama for a one-sentence description (fallback if unavailable)
    4. Compile with yara-python → mark valid/invalid
    5. Return YARAResult

Usage:
    from forensiq.yara.generator import YARAGenerator
    from forensiq.models.features import ProcessFeatureVector

    generator = YARAGenerator()
    results = await generator.generate_for_malicious(
        vectors=ranked_vectors,
        extraction_result=extraction_result,
    )
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from forensiq.llm.ollama_client import OllamaClient
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.report import YARAResult
from forensiq.utils.logger import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from forensiq.extraction.orchestrator import ExtractionResult

log = get_logger(__name__)


def _sanitize_rule_name(name: str, pid: int) -> str:
    """Create a valid YARA rule identifier from a process name.

    YARA rule names must be ASCII, start with a letter or underscore,
    and contain only alphanumeric characters and underscores.

    Args:
        name: Process image name.
        pid: Process ID (added as suffix for uniqueness).

    Returns:
        Valid YARA rule name string.
    """
    # Normalize Unicode, strip extension, replace non-alnum with _
    norm = unicodedata.normalize("NFKD", name)
    ascii_name = norm.encode("ascii", errors="ignore").decode("ascii")
    stem = re.sub(r"\.[^.]+$", "", ascii_name)  # Remove extension
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", stem).strip("_")
    safe = safe[:50] if len(safe) > 50 else safe  # Max length
    if not safe or safe[0].isdigit():
        safe = f"proc_{safe}"
    return f"forensiq_{safe}_{pid}"


def _extract_iocs(
    vector: ProcessFeatureVector,
    extraction: ExtractionResult,
) -> list[str]:
    """Extract Indicators of Compromise for a suspicious process.

    Gathers concrete IOC strings from all available artifact sources
    for use as YARA string hints.

    Args:
        vector: Classified feature vector for the process.
        extraction: Full extraction result for cross-referencing.

    Returns:
        List of IOC strings to include in the YARA prompt.
    """
    iocs: list[str] = []

    # Process name (always include)
    iocs.append(f"Process name: {vector.name}")

    # Malfind hex dumps (most valuable for YARA signatures)
    malfind_regions = extraction.malfind.get(vector.pid, [])
    for region in malfind_regions[:3]:  # Limit to first 3 regions
        if region.hexdump:
            hex_preview = " ".join(region.hexdump.split()[:24])  # First 24 bytes
            iocs.append(f"Memory bytes at 0x{region.start:x}: {hex_preview}")
        if region.has_pe_header:
            iocs.append(f"PE header found at 0x{region.start:x} (possible reflective injection)")

    # Suspicious DLL paths
    suspicious_dlls = [
        d for d in extraction.dlls.get(vector.pid, []) if d.is_suspicious and d.full_dll_name
    ]
    for dll in suspicious_dlls[:5]:
        iocs.append(f"Suspicious DLL: {dll.full_dll_name}")

    # External network connections
    external_conns = [c for c in extraction.connections.get(vector.pid, []) if c.is_external]
    for conn in external_conns[:3]:
        iocs.append(f"Network connection: {conn.remote_addr}:{conn.remote_port} ({conn.state})")

    # Command line fragments (truncated for YARA safety)
    if extraction.process_tree:
        proc = extraction.process_tree.flat_map.get(vector.pid)
        if proc and proc.cmdline:
            cmdline = proc.cmdline[:200].strip()
            iocs.append(f"Command line contains: {cmdline}")

    # SHAP top features (explain what drove the score)
    if vector.shap_values:
        top_features = sorted(
            vector.shap_values.items(),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )[:3]
        for feat_name, shap_val in top_features:
            direction = "high" if shap_val > 0 else "low"
            iocs.append(f"Anomalous feature: {feat_name} is {direction} (SHAP={shap_val:+.3f})")

    return iocs if iocs else [f"Suspicious process: {vector.name} (PID {vector.pid})"]


def _validate_yara_rule(rule_text: str, rule_name: str) -> tuple[bool, str]:
    """Compile and validate a YARA rule using yara-python.

    This is the critical validation step — only rules that yara-python
    can successfully compile are marked as valid.

    Args:
        rule_text: Full YARA rule text to validate.
        rule_name: Rule name (for error reporting).

    Returns:
        Tuple of (is_valid: bool, error_message: str).
        error_message is empty string if is_valid=True.
    """
    try:
        import yara

        if not rule_text or not rule_text.strip():
            return False, "Empty rule text"
        yara.compile(source=rule_text)
        return True, ""
    except Exception as exc:
        error_msg = str(exc)
        log.debug("YARA compilation failed", rule_name=rule_name, error=error_msg)
        return False, error_msg


def _build_yara_rule_programmatic(
    rule_name: str,
    vector: ProcessFeatureVector,
    iocs: list[str],
    description: str,
) -> str:
    """Build a syntactically valid YARA rule programmatically from IOCs.

    Uses a deterministic template — no LLM for syntax, guaranteeing compilation.

    Args:
        rule_name: Sanitized YARA rule name.
        vector: Classified feature vector.
        iocs: IOC strings from _extract_iocs().
        description: Human-readable description (from LLM or fallback).

    Returns:
        Complete YARA rule text.
    """
    strings_lines: list[str] = []
    idx = 0

    # Always include process name (escape both quotes and backslashes)
    name_safe = vector.name.replace("\\", "\\\\").replace('"', '\\"')
    strings_lines.append(f'        $proc_{idx} = "{name_safe}" nocase')
    idx += 1

    for ioc in iocs:
        if ioc.startswith("Memory bytes at"):
            # Format: "Memory bytes at 0xADDR: HH HH HH ..."
            parts = ioc.split(": ", 1)
            if len(parts) == 2:
                raw_hex = parts[1].strip()
                hex_parts = raw_hex.split()
                # Only include if we have valid hex byte tokens
                valid = [
                    h
                    for h in hex_parts[:16]
                    if len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)
                ]
                if len(valid) >= 4:
                    strings_lines.append(f"        $mem_{idx} = {{ {' '.join(valid)} }}")
                    idx += 1

        elif ioc.startswith("Suspicious DLL:"):
            dll_path = ioc.split(": ", 1)[1]
            # Use only the filename portion — avoids backslash escaping issues
            dll_name = dll_path.replace("\\", "/").split("/")[-1]
            if dll_name and dll_name not in ("", ".", ".."):
                dll_safe = dll_name.replace("\\", "\\\\").replace('"', '\\"')
                strings_lines.append(f'        $dll_{idx} = "{dll_safe}" nocase')
                idx += 1

        elif ioc.startswith("Network connection:"):
            conn_str = ioc.split(": ", 1)[1]
            # rsplit handles both "host:port" and bracketed IPv6 "[::1]:443"
            ip = conn_str.rsplit(":", 1)[0].strip().strip("[]")
            if ip and ip not in ("*", "0.0.0.0", "::") and not ip.startswith("127."):  # noqa: S104
                strings_lines.append(f'        $net_{idx} = "{ip}"')
                idx += 1

        elif ioc.startswith("Command line contains:"):
            cmdline = ioc.split(": ", 1)[1].strip()
            # Use only the executable part (first token, no paths)
            token = cmdline.replace("\\", "/").split("/")[-1].split()[0][:50]
            if token and token.isascii():
                token_safe = token.replace("\\", "\\\\").replace('"', '\\"')
                strings_lines.append(f'        $cmd_{idx} = "{token_safe}" nocase')
                idx += 1

    # Guard: always at least one string
    if not strings_lines:
        name_safe = vector.name.replace("\\", "\\\\").replace('"', '\\"')
        strings_lines.append(f'        $proc_0 = "{name_safe}" nocase')

    date_str = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    threat_int = max(1, min(10, int(vector.threat_score * 10)))
    desc_safe = (
        description.replace("\\", "\\\\").replace('"', "'").replace("\n", " ")[:200]
    )

    strings_block = "\n".join(strings_lines)
    return (
        f"rule {rule_name} {{\n"
        f"    meta:\n"
        f'        author = "ForensIQ"\n'
        f'        description = "{desc_safe}"\n'
        f'        date = "{date_str}"\n'
        f"        threat_level = {threat_int}\n"
        f"    strings:\n"
        f"{strings_block}\n"
        f"    condition:\n"
        f"        any of them\n"
        f"}}"
    )


class YARAGenerator:
    """Generates and validates YARA rules for suspicious processes.

    Rules are built programmatically from extracted IOCs (guaranteed-valid
    syntax); a local Ollama LLM is used only to enrich the description.

    Args:
        client: OllamaClient instance (creates default if None).
    """

    def __init__(self, client: OllamaClient | None = None) -> None:
        self._client = client or OllamaClient()

    async def _generate_single(
        self,
        vector: ProcessFeatureVector,
        extraction: ExtractionResult,
    ) -> YARAResult:
        """Generate and validate a YARA rule for a single process.

        Uses programmatic rule generation (guaranteed valid syntax) and
        Ollama only for enriching the description field.

        Args:
            vector: Classified feature vector for the target process.
            extraction: Full extraction result for IOC gathering.

        Returns:
            YARAResult with is_valid=True if compilation succeeded.
        """
        rule_name = _sanitize_rule_name(vector.name, vector.pid)
        iocs = _extract_iocs(vector, extraction)

        log.info(
            "Generating YARA rule",
            process=vector.name,
            pid=vector.pid,
            ioc_count=len(iocs),
        )

        # Use LLM only for the description (single line of text, no YARA syntax)
        description = (
            f"Suspicious {vector.name} (PID {vector.pid}) — "
            f"threat score {vector.threat_score:.1%}, "
            f"VAD RWX={vector.vad_rwx_count}, malfind={vector.malfind_hits}"
        )
        try:
            desc_prompt = (
                f"In one sentence (max 120 chars), describe why this Windows process "
                f"is malicious. Process: {vector.name}, PID: {vector.pid}, "
                f"VAD RWX regions: {vector.vad_rwx_count}, malfind hits: {vector.malfind_hits}, "
                f"external connections: {vector.external_connection_count}. "
                f"Reply with ONLY the sentence, no quotes."
            )
            llm_desc = await self._client.generate(desc_prompt)
            llm_desc = llm_desc.strip().replace('"', "'").replace("\n", " ")[:200]
            if llm_desc:
                description = llm_desc
        except Exception:  # noqa: S110
            pass  # Fall back to default description

        # Build rule programmatically — always valid syntax
        rule_text = _build_yara_rule_programmatic(rule_name, vector, iocs, description)
        is_valid, error = _validate_yara_rule(rule_text, rule_name)

        if is_valid:
            log.info("YARA rule generated and validated", rule_name=rule_name)
        else:
            log.warning("YARA rule failed validation", rule_name=rule_name, error=error)

        return YARAResult(
            rule_name=rule_name,
            process_name=vector.name,
            pid=vector.pid,
            rule_text=rule_text,
            is_valid=is_valid,
            validation_error=error,
            iocs_used=iocs,
            generated_at=datetime.now(tz=UTC),
        )

    async def generate_for_malicious(
        self,
        vectors: list[ProcessFeatureVector],
        extraction: ExtractionResult,
        max_rules: int = 10,
    ) -> list[YARAResult]:
        """Generate YARA rules for the top malicious processes.

        Only processes classified as malicious (is_malicious=True) get rules.
        Rules are generated sequentially by default (Ollama handles one at a time).

        Args:
            vectors: Ranked feature vectors (sorted by threat_score descending).
            extraction: Full extraction result for IOC gathering.
            max_rules: Maximum number of rules to generate.

        Returns:
            List of YARAResult objects (all results, valid and invalid).
        """
        malicious = [v for v in vectors if v.is_malicious][:max_rules]

        if not malicious:
            log.info("No malicious processes for YARA generation")
            return []

        log.info("Generating YARA rules for malicious processes", count=len(malicious))

        results: list[YARAResult] = []
        for vector in malicious:
            result = await self._generate_single(vector, extraction)
            results.append(result)

        valid_count = sum(1 for r in results if r.is_valid)
        log.info(
            "YARA generation complete",
            total=len(results),
            valid=valid_count,
            invalid=len(results) - valid_count,
        )
        return results

    def export_valid_rules(
        self,
        results: list[YARAResult],
        output_dir: Path,
    ) -> list[str]:
        """Write valid YARA rules to .yar files in the output directory.

        Only rules with is_valid=True are written to disk.

        Args:
            results: List of YARAResult objects.
            output_dir: Directory to write .yar files.

        Returns:
            List of paths to written .yar files.
        """
        from pathlib import Path as PathType

        output_path = PathType(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        written: list[str] = []
        for result in results:
            if not result.is_valid:
                continue
            yar_file = output_path / f"{result.rule_name}.yar"
            yar_file.write_text(result.rule_text, encoding="utf-8")
            written.append(str(yar_file))
            log.info("YARA rule exported", path=str(yar_file))

        log.info("YARA export complete", written=len(written))
        return written
