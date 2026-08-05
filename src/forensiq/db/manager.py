# FILE: src/forensiq/db/manager.py
"""ForensIQ persistent SQLite database manager.

Stores and retrieves analysis results across multiple runs for:
    - Historical trend analysis
    - IOC intelligence caching (VirusTotal / MalwareBazaar)
    - Cross-dump process baseline comparison
    - Detector findings history

Schema:
    analyses        — One row per analysis run (dump + metadata)
    findings        — All DetectorResult findings per analysis
    threat_intel    — Cached IOC lookups (hash → VT/MB verdict, TTL 24h)
    yara_rules      — Exported YARA rules linked to analysis

Usage:
    async with ForensiqDatabase() as db:
        analysis_id = await db.save_analysis(report, findings)
        cached = await db.get_threat_intel(hash_md5="abc123")

The database file defaults to ~/.forensiq/forensiq.db and is created
automatically on first use. Override with FORENSIQ_DB_PATH env var.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from forensiq.config.settings import get_settings
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dump_name       TEXT NOT NULL,
    dump_sha256     TEXT,
    dump_size_bytes INTEGER,
    analysis_ts     TEXT NOT NULL,
    forensiq_ver    TEXT,
    volatility_ver  TEXT,
    total_processes INTEGER DEFAULT 0,
    malicious_count INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    timeline_events  INTEGER DEFAULT 0,
    yara_rules_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    detector        TEXT NOT NULL,
    pid             INTEGER,
    process_name    TEXT,
    severity        TEXT,
    title           TEXT,
    description     TEXT,
    mitre_technique TEXT,
    confidence      REAL,
    evidence_json   TEXT,
    found_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel (
    hash_value      TEXT PRIMARY KEY,
    hash_type       TEXT NOT NULL,
    source          TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    malware_name    TEXT,
    malware_family  TEXT,
    tags            TEXT,
    first_seen      TEXT,
    raw_json        TEXT,
    cached_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS yara_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER REFERENCES analyses(id) ON DELETE CASCADE,
    rule_name       TEXT NOT NULL,
    process_name    TEXT,
    pid             INTEGER,
    rule_content    TEXT NOT NULL,
    is_valid        INTEGER DEFAULT 1,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intel_hash ON threat_intel(hash_value);
CREATE INDEX IF NOT EXISTS idx_analyses_ts ON analyses(analysis_ts);
"""


class ForensiqDatabase:
    """Async SQLite database manager for forensic analysis results.

    Use as an async context manager:
        async with ForensiqDatabase() as db:
            await db.save_analysis(...)

    Or manually:
        db = ForensiqDatabase()
        await db.connect()
        ...
        await db.close()
    """

    def __init__(self, db_path: Path | None = None) -> None:
        settings = get_settings()
        if db_path is not None:
            self.db_path = db_path
        else:
            # Use configured path or default ~/.forensiq/forensiq.db
            configured = getattr(settings, "DB_PATH", None)
            if configured:
                self.db_path = Path(configured)
            else:
                self.db_path = Path.home() / ".forensiq" / "forensiq.db"

        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        """Open database connection and create schema if needed."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        # Enable WAL mode for concurrent reads
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.executescript(_SCHEMA_SQL)
        await self._conn.commit()
        log.info("Database connected", path=str(self.db_path))

    async def close(self) -> None:
        """Close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self) -> ForensiqDatabase:
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ─── Analyses ─────────────────────────────────────────────────────────────

    async def save_analysis(
        self,
        dump_name: str,
        dump_sha256: str,
        dump_size_bytes: int,
        forensiq_version: str,
        volatility_version: str,
        total_processes: int,
        malicious_count: int,
        suspicious_count: int,
        timeline_events: int,
        yara_rules_count: int,
    ) -> int:
        """Insert an analysis record and return its ID.

        Returns:
            Integer analysis ID for use in related tables.
        """
        assert self._conn is not None, "Database not connected"
        now = datetime.now(tz=UTC).isoformat()
        cursor = await self._conn.execute(
            """
            INSERT INTO analyses (
                dump_name, dump_sha256, dump_size_bytes, analysis_ts,
                forensiq_ver, volatility_ver, total_processes,
                malicious_count, suspicious_count, timeline_events, yara_rules_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dump_name,
                dump_sha256,
                dump_size_bytes,
                now,
                forensiq_version,
                volatility_version,
                total_processes,
                malicious_count,
                suspicious_count,
                timeline_events,
                yara_rules_count,
            ),
        )
        await self._conn.commit()
        analysis_id = cursor.lastrowid
        log.info(
            "Analysis saved to database",
            analysis_id=analysis_id,
            dump=dump_name,
        )
        return analysis_id  # type: ignore[return-value]

    async def get_recent_analyses(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the most recent analysis records."""
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM analyses ORDER BY analysis_ts DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_analysis_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        """Return the most recent analysis for a dump with given SHA-256.

        Args:
            sha256: Full hex SHA-256 digest of the dump file.

        Returns:
            Analysis record dict, or None if no previous analysis found.
        """
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM analyses WHERE dump_sha256 = ? ORDER BY analysis_ts DESC LIMIT 1",
            (sha256,),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ─── Findings ─────────────────────────────────────────────────────────────

    async def save_findings(
        self,
        analysis_id: int,
        findings: list[Any],  # list[DetectorResult]
    ) -> None:
        """Bulk-insert DetectorResult findings for an analysis."""
        assert self._conn is not None
        now = datetime.now(tz=UTC).isoformat()
        rows = []
        for f in findings:
            rows.append(
                (
                    analysis_id,
                    f.detector,
                    f.pid,
                    f.process_name,
                    f.severity.value,
                    f.title,
                    f.description,
                    f.mitre_technique,
                    f.confidence,
                    json.dumps(f.evidence),
                    now,
                )
            )

        await self._conn.executemany(
            """
            INSERT INTO findings (
                analysis_id, detector, pid, process_name, severity,
                title, description, mitre_technique, confidence,
                evidence_json, found_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        await self._conn.commit()
        log.info("Findings saved", analysis_id=analysis_id, count=len(rows))

    async def get_findings_by_analysis(
        self,
        analysis_id: int,
    ) -> list[dict[str, Any]]:
        """Return all findings for a given analysis."""
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM findings WHERE analysis_id = ? ORDER BY severity",
            (analysis_id,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ─── Threat Intelligence Cache ────────────────────────────────────────────

    async def get_threat_intel(self, hash_value: str) -> dict[str, Any] | None:
        """Retrieve cached threat intelligence for a hash (if not expired).

        Returns:
            Dict with verdict data, or None if not cached / expired.
        """
        assert self._conn is not None
        now = datetime.now(tz=UTC).isoformat()
        cursor = await self._conn.execute(
            "SELECT * FROM threat_intel WHERE hash_value = ? AND expires_at > ?",
            (hash_value.lower(), now),
        )
        row = await cursor.fetchone()
        if row:
            data = dict(row)
            if data.get("raw_json"):
                data["raw_json"] = json.loads(data["raw_json"])
            return data
        return None

    async def save_threat_intel(
        self,
        hash_value: str,
        hash_type: str,
        source: str,
        verdict: str,
        malware_name: str = "",
        malware_family: str = "",
        tags: str = "",
        first_seen: str = "",
        raw_json: dict[str, Any] | None = None,
        ttl_hours: int = 24,
    ) -> None:
        """Save threat intelligence result to cache.

        Args:
            hash_value: MD5/SHA256 hash.
            hash_type: "md5" or "sha256".
            source: "virustotal" or "malwarebazaar".
            verdict: "malicious", "clean", or "unknown".
            ttl_hours: How long to cache this result (default 24h).
        """
        assert self._conn is not None
        now = datetime.now(tz=UTC)
        expires = (now + timedelta(hours=ttl_hours)).isoformat()

        await self._conn.execute(
            """
            INSERT OR REPLACE INTO threat_intel (
                hash_value, hash_type, source, verdict,
                malware_name, malware_family, tags, first_seen,
                raw_json, cached_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_value.lower(),
                hash_type,
                source,
                verdict,
                malware_name,
                malware_family,
                tags,
                first_seen,
                json.dumps(raw_json) if raw_json else None,
                now.isoformat(),
                expires,
            ),
        )
        await self._conn.commit()

    # ─── YARA Rules ───────────────────────────────────────────────────────────

    async def save_yara_rules(
        self,
        analysis_id: int,
        yara_results: list[Any],  # list[YARAResult]
    ) -> None:
        """Save generated YARA rules linked to an analysis."""
        assert self._conn is not None
        now = datetime.now(tz=UTC).isoformat()
        rows = []
        for y in yara_results:
            rows.append(
                (
                    analysis_id,
                    getattr(y, "rule_name", ""),
                    getattr(y, "process_name", ""),
                    getattr(y, "pid", 0),
                    getattr(y, "rule_content", ""),
                    1 if getattr(y, "is_valid", False) else 0,
                    now,
                )
            )
        await self._conn.executemany(
            """
            INSERT INTO yara_rules (
                analysis_id, rule_name, process_name, pid,
                rule_content, is_valid, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        await self._conn.commit()

    # ─── Statistics ───────────────────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        """Return summary statistics for the entire database."""
        assert self._conn is not None
        cursor = await self._conn.execute("SELECT COUNT(*) as total_analyses FROM analyses")
        row = await cursor.fetchone()
        total_analyses = dict(row)["total_analyses"] if row else 0

        cursor = await self._conn.execute("SELECT COUNT(*) as total_findings FROM findings")
        row = await cursor.fetchone()
        total_findings = dict(row)["total_findings"] if row else 0

        cursor = await self._conn.execute("SELECT COUNT(*) as cache_entries FROM threat_intel")
        row = await cursor.fetchone()
        cache_entries = dict(row)["cache_entries"] if row else 0

        return {
            "total_analyses": total_analyses,
            "total_findings": total_findings,
            "threat_intel_cache_entries": cache_entries,
            "db_path": str(self.db_path),
        }
