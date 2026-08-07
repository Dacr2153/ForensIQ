# FILE: tests/unit/test_volatility_runner.py
"""Unit tests for forensiq.acquisition.volatility_runner.VolatilityRunner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.utils.exceptions import VolatilityTimeoutError


class TestCacheKey:
    def test_plain_plugin_unchanged(self) -> None:
        runner = VolatilityRunner(dump_path=Path("/tmp/x.raw"))
        assert runner._cache_key("windows.pslist") == "windows.pslist"

    def test_extra_args_produce_distinct_key(self) -> None:
        runner = VolatilityRunner(dump_path=Path("/tmp/x.raw"))
        base = runner._cache_key("windows.vadinfo")
        with_args = runner._cache_key("windows.vadinfo", ["--pid", "1234"])
        with_other = runner._cache_key("windows.vadinfo", ["--pid", "5678"])
        assert base != with_args
        assert with_args != with_other

    def test_extra_args_key_is_filesystem_safe(self) -> None:
        from forensiq.cache.plugin_cache import _sanitize_plugin_name

        runner = VolatilityRunner(dump_path=Path("/tmp/x.raw"))
        key = runner._cache_key("windows.vadinfo", ["--pid", "1234"])
        # Sanitizer must accept the derived key (no filename-breaking chars)
        assert _sanitize_plugin_name(key) == key


class TestStreamingTimeout:
    def test_wait_for_timeout_is_builtin_timeout_error(self) -> None:
        # asyncio.wait_for raises asyncio.TimeoutError which is aliased to the
        # builtin TimeoutError on 3.11+ and distinct on 3.10. The runner catches
        # the builtin; this test pins the alias so the runner's except clause
        # stays valid across versions.
        async def scenario() -> None:
            async def _never(_: object) -> bytes:
                await asyncio.sleep(10)
                return b""

            with pytest.raises(TimeoutError):
                await asyncio.wait_for(
                    asyncio.gather(_never(None), _never(None)),
                    timeout=0.01,
                )

        asyncio.run(scenario())

    def test_volatility_timeout_error_wraps_timeout(self) -> None:
        exc = VolatilityTimeoutError(timeout_seconds=1, plugin="windows.vadinfo")
        assert "vadinfo" in str(exc)
        assert "1" in str(exc)


class TestParseJsonOutput:
    def test_parse_columns_rows(self, tmp_path: Path) -> None:
        runner = VolatilityRunner(dump_path=tmp_path / "dummy.raw")
        raw = json.dumps({"columns": ["PID", "Name"], "rows": [[1, "System"]]})
        rows = runner._parse_json_output(raw, "windows.pslist")
        assert rows == [{"PID": 1, "Name": "System"}]

    def test_empty_output_returns_empty(self, tmp_path: Path) -> None:
        runner = VolatilityRunner(dump_path=tmp_path / "dummy.raw")
        assert runner._parse_json_output("", "windows.pslist") == []

    def test_non_json_output_returns_empty(self, tmp_path: Path) -> None:
        runner = VolatilityRunner(dump_path=tmp_path / "dummy.raw")
        assert runner._parse_json_output("just some log text", "windows.pslist") == []

    def test_partial_row_included(self, tmp_path: Path) -> None:
        runner = VolatilityRunner(dump_path=tmp_path / "dummy.raw")
        raw = json.dumps({"columns": ["A", "B"], "rows": [[1]]})
        rows = runner._parse_json_output(raw, "windows.pslist")
        assert rows == [{"A": 1}]


class TestBuildCommand:
    def test_missing_dump_raises_acquisition_error(self, tmp_path: Path) -> None:
        runner = VolatilityRunner(dump_path=tmp_path / "missing.raw")
        from forensiq.utils.exceptions import AcquisitionError

        with pytest.raises(AcquisitionError, match="not found"):
            runner._build_command("windows.pslist")

    def test_unsafe_plugin_name_rejected(self, tmp_path: Path) -> None:
        dump = tmp_path / "dump.raw"
        dump.write_bytes(b"MZ")
        runner = VolatilityRunner(dump_path=dump)
        from forensiq.utils.exceptions import AcquisitionError

        with pytest.raises(AcquisitionError, match="unsafe"):
            runner._build_command("windows.pslist; rm -rf /")
