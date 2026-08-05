# FILE: src/forensiq/acquisition/volatility_runner.py
"""Volatility 3 subprocess runner.

Handles all communication with the Volatility 3 CLI (vol command).
All plugins are invoked as a subprocess with JSON output (-r json flag).

Volatility 3 JSON output format:
    {"columns": ["PID", "PPID", "ImageFileName", ...],
     "rows": [[4, 0, "System", ...], [8, 4, "Registry", ...], ...]}

This format is column-index-based. Rows are converted to dicts on parse.

Usage:
    runner = VolatilityRunner(dump_path=Path("/dumps/memory.raw"))
    result = runner.run_plugin("windows.pslist")
    # result: list[dict[str, Any]]  — one dict per row, keyed by column name
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from forensiq.config.settings import get_settings
from forensiq.utils.exceptions import (
    AcquisitionError,
    VolatilityParseError,
    VolatilityTimeoutError,
)
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Maximum wait time for any single Volatility 3 plugin (seconds)
# Long-running plugins (vadinfo on large dumps) may approach this
_DEFAULT_TIMEOUT = 300

# Valid Volatility 3 plugin names: lowercase words joined by dots, e.g.
# 'windows.pslist', 'linux.malware.malfind'.  Anything else (leading dashes,
# spaces, shell metacharacters) is rejected before building the command to
# prevent argument/option injection into the vol CLI.
_PLUGIN_NAME_PATTERN = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)+$")

# Valid extra argument tokens passed to a plugin.  Volatility accepts options
# like '--pid 1234' or '--dump'.  Reject any token containing whitespace or
# shell metacharacters (defense in depth; subprocess is argv-based so the real
# risk is option smuggling, not shell injection).
_EXTRA_ARG_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-:,.=+/"
)


def _validate_plugin_name(plugin: str) -> str:
    """Validate a Volatility plugin name before it is placed on the argv list.

    Args:
        plugin: Plugin name (e.g. 'windows.pslist').

    Returns:
        The validated plugin name.

    Raises:
        AcquisitionError: If the plugin name contains unsafe characters or
            does not look like a plugin path.
    """
    if not isinstance(plugin, str) or not plugin.strip():
        raise AcquisitionError(message="Volatility plugin name must be a non-empty string")
    if not _PLUGIN_NAME_PATTERN.match(plugin):
        raise AcquisitionError(
            message=(
                f"Refusing unsafe Volatility plugin name: {plugin!r}. "
                "Plugin names must look like 'windows.pslist'."
            )
        )
    return plugin


def _validate_extra_args(extra_args: list[str] | None) -> list[str] | None:
    """Validate extra CLI arguments destined for a Volatility plugin.

    Args:
        extra_args: Optional list of argument tokens.

    Returns:
        The validated argument list (or None).

    Raises:
        AcquisitionError: If any token contains unsafe characters.
    """
    if not extra_args:
        return extra_args
    for token in extra_args:
        if not isinstance(token, str) or not token:
            raise AcquisitionError(message="Volatility extra args must be non-empty strings")
        if any(ch not in _EXTRA_ARG_SAFE_CHARS for ch in token):
            raise AcquisitionError(
                message=f"Refusing unsafe Volatility extra argument: {token!r}"
            )
    return extra_args


class VolatilityRunner:
    """Runs Volatility 3 plugins against a memory dump file.

    Each call to run_plugin() invokes a fresh vol subprocess.
    Volatility 3 is NOT thread-safe when operating on the same dump file,
    so all plugins should be run sequentially (handled by ExtractionOrchestrator).

    Args:
        dump_path: Path to the memory dump file to analyze.
        timeout: Maximum seconds to wait for a plugin to complete.
    """

    def __init__(
        self,
        dump_path: Path,
        timeout: int = _DEFAULT_TIMEOUT,
        dump_sha256: str = "",
        is_linux: bool = False,
    ) -> None:
        self.dump_path = dump_path.resolve()
        self.timeout = timeout
        self.is_linux = is_linux
        self.dump_sha256 = dump_sha256  # set after hash computed to enable plugin caching
        self._settings = get_settings()
        # Lazy import to avoid circular dependency at module load time
        self._plugin_cache: Any | None = None

    def _get_cache(self) -> Any:
        """Return the PluginCache instance (lazy init)."""
        if self._plugin_cache is None:
            from forensiq.cache.plugin_cache import PluginCache

            self._plugin_cache = PluginCache()
        return self._plugin_cache

    def _build_command(self, plugin: str, extra_args: list[str] | None = None) -> list[str]:
        """Construct the vol command for a plugin invocation.

        Args:
            plugin: Volatility 3 plugin name (e.g., 'windows.pslist').
            extra_args: Additional arguments passed after the plugin name.

        Returns:
            List of command arguments ready for subprocess.run().
        """
        plugin = _validate_plugin_name(plugin)
        extra_args = _validate_extra_args(extra_args)

        # Fail fast with a clear message instead of letting `vol` exit non-zero
        # on a missing dump (which produces confusing empty JSON output).
        if not self.dump_path.is_file():
            raise AcquisitionError(
                message=f"Memory dump file not found: {self.dump_path}",
            )

        vol_path = self._settings.get_volatility_executable()

        cmd = [
            vol_path,
            "-r",
            "json",  # Request JSON output format
            "-f",
            str(self.dump_path),  # Memory dump file
            plugin,
        ]

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    def _parse_json_output(self, raw: str, plugin: str) -> list[dict[str, Any]]:
        """Parse Volatility 3 JSON output into a list of row dicts.

        Volatility 3 uses a column-index format:
            {"columns": ["col1", "col2", ...], "rows": [[v1, v2, ...], ...]}

        This method converts each row to a dict keyed by column name.

        Args:
            raw: Raw stdout string from the vol subprocess.
            plugin: Plugin name (used in error messages only).

        Returns:
            List of dicts, one per data row. Empty list if no rows.

        Raises:
            VolatilityParseError: If output cannot be parsed as valid JSON
                or does not match expected format.
        """
        if not raw or not raw.strip():
            log.debug("Empty output from plugin", plugin=plugin)
            return []

        # Volatility 3 may prefix output with log lines before the JSON blob.
        # Find the first '{' or '[' to start parsing JSON (newer vol3 uses array format).
        obj_start = raw.find("{")
        arr_start = raw.find("[")

        if obj_start == -1 and arr_start == -1:
            log.warning("No JSON found in output", plugin=plugin, preview=raw[:200])
            return []

        if obj_start == -1:
            json_start = arr_start
        elif arr_start == -1:
            json_start = obj_start
        else:
            json_start = min(obj_start, arr_start)

        json_text = raw[json_start:]

        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as exc:
            raise VolatilityParseError(
                plugin=plugin,
                raw_output=raw,
            ) from exc

        # Handle column-indexed format (primary Volatility 3 JSON format)
        if isinstance(data, dict) and "columns" in data and "rows" in data:
            columns: list[str] = data["columns"]
            rows: list[list[Any]] = data.get("rows", [])
            result = []
            for row in rows:
                if len(row) == len(columns):
                    result.append(dict(zip(columns, row, strict=False)))
                else:
                    # Partial row — include what we can, log warning
                    log.warning(
                        "Row length mismatch",
                        plugin=plugin,
                        expected=len(columns),
                        got=len(row),
                    )
                    partial = dict(zip(columns[: len(row)], row, strict=False))
                    result.append(partial)
            return result

        # Handle dict-of-rows format (some plugins may use this)
        if isinstance(data, list):
            if all(isinstance(item, dict) for item in data):
                return data  # type: ignore[return-value]

        # Unknown format — log and return empty
        log.warning(
            "Unexpected JSON structure from plugin",
            plugin=plugin,
            keys=list(data.keys()) if isinstance(data, dict) else type(data).__name__,
        )
        return []

    def run_plugin(
        self,
        plugin: str,
        extra_args: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a single Volatility 3 plugin and return parsed rows.

        Args:
            plugin: Volatility 3 plugin name (e.g., 'windows.pslist').
            extra_args: Optional additional CLI arguments for the plugin.

        Returns:
            List of row dicts, one per result row. Empty list if plugin
            produced no output (caller should handle this case).

        Raises:
            VolatilityTimeoutError: If the plugin exceeds self.timeout.
            VolatilityParseError: If JSON output cannot be parsed.
            AcquisitionError: For subprocess errors (non-zero exit, etc.).
        """
        cmd = self._build_command(plugin, extra_args)
        log.info("Running Volatility 3 plugin", plugin=plugin, dump=self.dump_path.name)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                # NOTE: Do NOT use shell=True — prevents shell injection
            )
        except subprocess.TimeoutExpired as exc:
            raise VolatilityTimeoutError(
                plugin=plugin,
                timeout_seconds=self.timeout,
            ) from exc
        except FileNotFoundError as exc:
            raise AcquisitionError(
                message=(
                    f"Volatility 3 executable not found: {cmd[0]}\n"
                    "Install with: pip install volatility3"
                ),
            ) from exc
        except OSError as exc:
            raise AcquisitionError(
                message=f"OS error invoking Volatility 3 for plugin '{plugin}': {exc}",
            ) from exc

        # NOTE: Volatility 3 writes warnings/info to stderr but still produces
        # valid JSON on stdout. We log stderr but do NOT treat it as a failure.
        if result.stderr:
            stderr_preview = result.stderr[:500]
            # Filter out common benign Volatility warnings
            benign_patterns = [
                "Volatility 3 Framework",
                "Progress:",
                "Unsatisfied requirement",
                "WARNING",
            ]
            if not any(p in result.stderr for p in benign_patterns):
                log.warning("Volatility stderr output", plugin=plugin, stderr=stderr_preview)
            else:
                log.debug("Volatility progress/warning output", plugin=plugin)

        # Non-zero exit code is logged but not always fatal
        # (Volatility sometimes exits 1 for partial results but still outputs valid JSON)
        if result.returncode != 0:
            log.warning(
                "Volatility 3 exited with non-zero code",
                plugin=plugin,
                exit_code=result.returncode,
            )

        rows = self._parse_json_output(result.stdout, plugin)
        log.info(
            "Plugin complete",
            plugin=plugin,
            rows=len(rows),
            exit_code=result.returncode,
        )
        return rows

    async def run_plugin_async(
        self,
        plugin: str,
        extra_args: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Run a Volatility 3 plugin asynchronously using asyncio subprocess.

        Checks the plugin cache first (if dump_sha256 is set). On cache miss,
        runs the plugin via asyncio.create_subprocess_exec and saves the result.

        Args:
            plugin: Volatility 3 plugin name (e.g., 'windows.pslist').
            extra_args: Optional additional CLI arguments.

        Returns:
            Parsed list of row dicts.

        Raises:
            VolatilityTimeoutError, VolatilityParseError, AcquisitionError.
        """
        import asyncio

        # ── Cache lookup ──────────────────────────────────────────────────────
        if self.dump_sha256:
            cache = self._get_cache()
            cached_rows = cache.load(self.dump_sha256, plugin)
            if cached_rows is not None:
                return cached_rows

        cmd = self._build_command(plugin, extra_args)
        log.info("Running Volatility 3 plugin (async)", plugin=plugin, dump=self.dump_path.name)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )
            except TimeoutError as exc:
                proc.kill()
                await proc.communicate()
                raise VolatilityTimeoutError(
                    plugin=plugin,
                    timeout_seconds=self.timeout,
                ) from exc
        except FileNotFoundError as exc:
            raise AcquisitionError(
                message=f"Volatility 3 executable not found: {cmd[0]}",
            ) from exc
        except OSError as exc:
            raise AcquisitionError(
                message=f"OS error invoking Volatility 3 async for plugin '{plugin}': {exc}",
            ) from exc

        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if stderr:
            log.debug("Volatility async stderr", plugin=plugin, preview=stderr[:200])

        if proc.returncode != 0:
            log.warning(
                "Volatility 3 async exited non-zero",
                plugin=plugin,
                exit_code=proc.returncode,
            )

        rows = self._parse_json_output(stdout, plugin)
        log.info("Async plugin complete", plugin=plugin, rows=len(rows))

        # ── Cache save ────────────────────────────────────────────────────────
        if self.dump_sha256 and rows is not None:
            try:
                cache = self._get_cache()
                cache.save(self.dump_sha256, plugin, rows)
            except Exception:  # noqa: S110
                pass  # Cache write failure is never fatal

        return rows

    def get_volatility_version(self) -> str:
        """Return the Volatility 3 version string.

        Volatility 3.0 uses ``--version``; 2.x accepts ``-v``.  Both are
        tried and the "Volatility 3 Framework" line is extracted so callers
        never receive usage help text.

        Returns:
            Version string (e.g., 'Volatility 3 Framework 2.7.1') or empty string on error.
        """
        try:
            settings = get_settings()
            vol_path = settings.get_volatility_executable()
            output = ""
            for flag in ("--version", "-v"):
                result = subprocess.run(
                    [vol_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                candidate = result.stdout.strip() or result.stderr.strip()
                if "Volatility 3 Framework" in candidate:
                    output = candidate
                    break
            return output
        except Exception as exc:
            log.warning("Could not determine Volatility version", error=str(exc))
            return ""
