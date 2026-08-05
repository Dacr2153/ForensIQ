# FILE: tests/unit/test_database.py
"""Async unit tests for ForensiqDatabase (SQLite historical storage).

Tests:
    - Database creation and schema migration
    - save_analysis / get_stats round-trip
    - save_findings with real DetectorResult objects
    - get_threat_intel / save_threat_intel cache TTL
    - save_yara_rules
    - WAL mode enabled
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_analysis_kwargs() -> dict:
    """Minimal keyword args that ForensiqDatabase.save_analysis accepts."""
    return {
        "dump_name": "MemoryDump_Lab1.raw",
        "dump_sha256": "deadbeef" * 8,
        "dump_size_bytes": 1024 * 1024 * 512,
        "forensiq_version": "dev",
        "volatility_version": "2.6.2",
        "total_processes": 42,
        "malicious_count": 3,
        "suspicious_count": 7,
        "timeline_events": 150,
        "yara_rules_count": 5,
    }


def _make_detector_finding():
    """Build a real DetectorResult for tests that call save_findings."""
    from forensiq.detectors.base import DetectorResult, FindingSeverity

    return DetectorResult(
        detector="process_anomaly",
        pid=1234,
        process_name="evil.exe",
        severity=FindingSeverity.HIGH,
        title="Masquerading Process",
        description="svchost.exe running from Temp",
        mitre_technique="T1036.005",
        mitre_technique_name="Match Legitimate Name or Location",
        evidence={"path": "C:\\Temp\\svchost.exe"},
        confidence=0.92,
    )


# ─── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_database_creation(tmp_path: Path) -> None:
    """Database file should be created automatically."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as _:
        assert db_path.exists()


@pytest.mark.asyncio
async def test_save_and_get_stats(tmp_path: Path) -> None:
    """Stats should reflect saved analysis."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        await db.save_analysis(**_make_analysis_kwargs())
        stats = await db.get_stats()

    assert stats["total_analyses"] == 1


@pytest.mark.asyncio
async def test_multiple_analyses(tmp_path: Path) -> None:
    """Multiple saved analyses accumulate correctly."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        for i in range(3):
            kwargs = _make_analysis_kwargs()
            kwargs["dump_name"] = f"dump_{i}.raw"
            kwargs["malicious_count"] = i
            await db.save_analysis(**kwargs)
        stats = await db.get_stats()

    assert stats["total_analyses"] == 3


@pytest.mark.asyncio
async def test_save_findings(tmp_path: Path) -> None:
    """Findings should be saved and counted in stats."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        analysis_id = await db.save_analysis(**_make_analysis_kwargs())
        finding = _make_detector_finding()
        await db.save_findings(analysis_id, [finding])
        stats = await db.get_stats()

    assert stats["total_findings"] >= 1


@pytest.mark.asyncio
async def test_save_findings_batch(tmp_path: Path) -> None:
    """Saving multiple findings in one call works correctly."""
    from forensiq.db.manager import ForensiqDatabase
    from forensiq.detectors.base import DetectorResult, FindingSeverity

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        analysis_id = await db.save_analysis(**_make_analysis_kwargs())
        findings = [
            DetectorResult(
                detector="test_detector",
                pid=1000 + i,
                process_name=f"proc_{i}.exe",
                severity=FindingSeverity.MEDIUM,
                title=f"Finding {i}",
                description="test",
                mitre_technique="T1055",
                evidence={},
                confidence=0.8,
            )
            for i in range(5)
        ]
        await db.save_findings(analysis_id, findings)
        stats = await db.get_stats()

    assert stats["total_findings"] == 5


@pytest.mark.asyncio
async def test_threat_intel_cache_miss(tmp_path: Path) -> None:
    """get_threat_intel returns None for unknown hash."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        result = await db.get_threat_intel("deadbeef" * 8)

    assert result is None


@pytest.mark.asyncio
async def test_threat_intel_save_and_retrieve(tmp_path: Path) -> None:
    """Saved threat intel record should be retrieved by hash."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    sha256 = "cafebabe" * 8

    async with ForensiqDatabase(db_path=db_path) as db:
        await db.save_threat_intel(
            hash_value=sha256,
            hash_type="sha256",
            source="malwarebazaar",
            verdict="malicious",
            malware_name="Mirai.B",
            malware_family="Mirai",
            tags="trojan,botnet",
            first_seen="2024-01-15",
            raw_json={"engines": 45},
        )
        cached = await db.get_threat_intel(sha256)

    assert cached is not None
    assert cached["verdict"] == "malicious"
    assert cached["source"] == "malwarebazaar"


@pytest.mark.asyncio
async def test_save_yara_rules(tmp_path: Path) -> None:
    """YARA rules should be persisted."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"

    # Build a minimal YARA result mock
    yara_result = MagicMock()
    yara_result.rule_name = "Detect_Evil_PE"
    yara_result.process_name = "evil.exe"
    yara_result.pid = 1234
    yara_result.rule_content = "rule Detect_Evil_PE { condition: uint16(0) == 0x5A4D }"
    yara_result.is_valid = True

    async with ForensiqDatabase(db_path=db_path) as db:
        analysis_id = await db.save_analysis(**_make_analysis_kwargs())
        await db.save_yara_rules(analysis_id, [yara_result])


@pytest.mark.asyncio
async def test_context_manager_closes_connection(tmp_path: Path) -> None:
    """Database connection should be closed after context manager exits."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    db = ForensiqDatabase(db_path=db_path)
    async with db:
        pass
    # After __aexit__, _conn is set to None
    assert db._conn is None


@pytest.mark.asyncio
async def test_empty_findings_list_is_noop(tmp_path: Path) -> None:
    """Saving an empty findings list should not raise."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        analysis_id = await db.save_analysis(**_make_analysis_kwargs())
        await db.save_findings(analysis_id, [])  # Should not raise


@pytest.mark.asyncio
async def test_stats_has_required_keys(tmp_path: Path) -> None:
    """get_stats() must include expected top-level keys."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        stats = await db.get_stats()

    assert "total_analyses" in stats
    assert "total_findings" in stats
    assert "threat_intel_cache_entries" in stats
    assert "db_path" in stats


@pytest.mark.asyncio
async def test_get_recent_analyses_returns_list(tmp_path: Path) -> None:
    """get_recent_analyses returns a list of dicts."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        await db.save_analysis(**_make_analysis_kwargs())
        rows = await db.get_recent_analyses(limit=5)

    assert isinstance(rows, list)
    assert len(rows) == 1
    assert rows[0]["dump_name"] == "MemoryDump_Lab1.raw"


@pytest.mark.asyncio
async def test_get_analysis_by_sha256_hit(tmp_path: Path) -> None:
    """get_analysis_by_sha256 returns record when sha256 matches."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    sha256 = "a" * 64
    kwargs = _make_analysis_kwargs()
    kwargs["dump_sha256"] = sha256

    async with ForensiqDatabase(db_path=db_path) as db:
        await db.save_analysis(**kwargs)
        result = await db.get_analysis_by_sha256(sha256)

    assert result is not None
    assert result["dump_sha256"] == sha256


@pytest.mark.asyncio
async def test_get_analysis_by_sha256_miss(tmp_path: Path) -> None:
    """get_analysis_by_sha256 returns None when not found."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        result = await db.get_analysis_by_sha256("0" * 64)

    assert result is None


@pytest.mark.asyncio
async def test_get_findings_by_analysis(tmp_path: Path) -> None:
    """get_findings_by_analysis returns saved findings."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "test_forensiq.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        analysis_id = await db.save_analysis(**_make_analysis_kwargs())
        finding = _make_detector_finding()
        await db.save_findings(analysis_id, [finding])
        rows = await db.get_findings_by_analysis(analysis_id)

    assert len(rows) == 1
    assert rows[0]["process_name"] == "evil.exe"


@pytest.mark.asyncio
async def test_default_db_path_uses_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """When no db_path given and no DB_PATH in settings, uses ~/.forensiq/forensiq.db."""
    from forensiq.db.manager import ForensiqDatabase

    db = ForensiqDatabase()
    assert db.db_path.name == "forensiq.db"


@pytest.mark.asyncio
async def test_close_without_connect_is_noop() -> None:
    """close() with _conn=None (no connect called) should be a no-op."""
    from forensiq.db.manager import ForensiqDatabase

    db = ForensiqDatabase()
    # Don't call connect — _conn is None
    await db.close()  # Must not raise


@pytest.mark.asyncio
async def test_get_threat_intel_miss_returns_none(tmp_path: Path) -> None:
    """get_threat_intel returns None when hash not in cache."""
    from forensiq.db.manager import ForensiqDatabase

    db_path = tmp_path / "ti_test.db"
    async with ForensiqDatabase(db_path=db_path) as db:
        result = await db.get_threat_intel("deadbeef" * 8)

    assert result is None
