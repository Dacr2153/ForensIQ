# FILE: src/forensiq/cache/plugin_cache.py
"""Volatility plugin output cache — keyed by dump SHA-256 + plugin name.

Each Volatility plugin invocation is expensive (10-120 seconds per plugin
for a 4 GB dump). This cache serializes the parsed JSON rows to disk so
that repeated analyses of the same dump skip the Volatility subprocess.

Cache layout:
    ~/.forensiq/cache/
        {dump_sha256}/
            windows.pslist.json
            windows.cmdline.json
            windows.netscan.json
            windows.dlllist.json
            windows.malfind.json
            windows.vadinfo.json
            windows.psscan.json
            windows.svcscan.json
            windows.handles.json
            ...

Each cache file contains a JSON array of row dicts (exactly what
VolatilityRunner.run_plugin_async() returns).

TTL: By default cache files never expire — the dump SHA-256 is the
uniqueness key, so the same content always produces the same output.
Use FORENSIQ_CACHE_DISABLED=1 to bypass.

Usage:
    from forensiq.cache.plugin_cache import PluginCache
    cache = PluginCache()
    rows = cache.load("windows.pslist", sha256="abc123")
    if rows is None:
        rows = await runner.run_plugin_async("windows.pslist")
        cache.save("windows.pslist", sha256="abc123", rows=rows)
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Plugin names that are safe (only alphanumeric + dot) — prevent path traversal
_SAFE_PLUGIN_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
_CACHE_VERSION = "v1"


def _sanitize_plugin_name(plugin: str) -> str:
    """Return a filesystem-safe filename for a plugin name.

    Raises ValueError if the name looks unsafe.
    """
    if not _SAFE_PLUGIN_RE.match(plugin):
        raise ValueError(f"Unsafe plugin name for cache key: {plugin!r}")
    return plugin


class PluginCache:
    """Disk-based cache for Volatility plugin output rows.

    Each cache entry is a JSON file containing the list of row dicts
    returned by VolatilityRunner.run_plugin() / run_plugin_async().

    Args:
        cache_dir: Root cache directory. Defaults to ~/.forensiq/cache/.
        disabled: If True, all operations are no-ops (always miss).
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        disabled: bool | None = None,
    ) -> None:
        if disabled is None:
            disabled = os.environ.get("FORENSIQ_CACHE_DISABLED", "0").strip() == "1"
        self._disabled = disabled

        if cache_dir is None:
            cache_dir = Path.home() / ".forensiq" / "cache"
        self._root = cache_dir

    def _entry_path(self, sha256: str, plugin: str) -> Path:
        """Return the full path for a cache entry."""
        safe_plugin = _sanitize_plugin_name(plugin)
        # First 16 chars of sha256 as subdirectory prefix (avoid huge dirs)
        subdir = self._root / sha256[:16] / sha256[16:]
        return subdir / f"{safe_plugin}.{_CACHE_VERSION}.json"

    def is_cached(self, sha256: str, plugin: str) -> bool:
        """Return True if a valid cache entry exists for this sha256 + plugin."""
        if self._disabled:
            return False
        try:
            return self._entry_path(sha256, plugin).exists()
        except ValueError:
            return False

    def load(self, sha256: str, plugin: str) -> list[dict[str, Any]] | None:
        """Load cached rows for a plugin. Returns None on miss or error.

        Args:
            sha256: SHA-256 hex digest of the dump file.
            plugin: Volatility plugin name (e.g., 'windows.pslist').

        Returns:
            List of row dicts, or None if not cached / disabled / corrupt.
        """
        if self._disabled:
            return None
        try:
            path = self._entry_path(sha256, plugin)
            if not path.exists():
                return None
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, list):
                log.warning("Cache file has unexpected format, ignoring", path=str(path))
                return None
            log.info("Plugin cache HIT", plugin=plugin, rows=len(data), sha256=sha256[:12])
            return data
        except Exception as exc:
            log.warning("Cache load failed, will re-run plugin", plugin=plugin, error=str(exc))
            return None

    def save(self, sha256: str, plugin: str, rows: list[dict[str, Any]]) -> None:
        """Persist plugin rows to disk cache.

        Args:
            sha256: SHA-256 hex digest of the dump file.
            plugin: Volatility plugin name.
            rows: Parsed row dicts to cache.
        """
        if self._disabled:
            return
        try:
            path = self._entry_path(sha256, plugin)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write atomically via a temp file to avoid partial writes
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
            log.debug("Plugin cache SAVED", plugin=plugin, rows=len(rows), path=str(path))
        except Exception as exc:
            log.warning("Cache save failed (non-fatal)", plugin=plugin, error=str(exc))

    def invalidate(self, sha256: str, plugin: str | None = None) -> None:
        """Remove cache entries for a dump.

        Args:
            sha256: SHA-256 hex digest of the dump to invalidate.
            plugin: If given, invalidate only this plugin. If None, invalidate all
                    plugins for this dump.
        """
        try:
            if plugin:
                path = self._entry_path(sha256, plugin)
                if path.exists():
                    path.unlink()
                    log.info("Cache invalidated", sha256=sha256[:12], plugin=plugin)
            else:
                # Remove all entries for this dump (the two-level subdir)
                path = self._entry_path(sha256, "dummy")
                subdir = path.parent
                if subdir.exists():
                    import shutil

                    shutil.rmtree(subdir)
                    log.info("Cache invalidated (all plugins)", sha256=sha256[:12])
        except Exception as exc:
            log.warning("Cache invalidation failed", error=str(exc))

    def get_stats(self) -> dict[str, Any]:
        """Return cache statistics (total entries, disk size)."""
        try:
            if not self._root.exists():
                return {"total_entries": 0, "disk_bytes": 0, "cache_dir": str(self._root)}
            entries = list(self._root.rglob("*.json"))
            total_bytes = sum(f.stat().st_size for f in entries if f.is_file())
            return {
                "total_entries": len(entries),
                "disk_bytes": total_bytes,
                "disk_mb": round(total_bytes / (1024 * 1024), 2),
                "cache_dir": str(self._root),
                "disabled": self._disabled,
            }
        except Exception:
            return {"total_entries": -1, "disk_bytes": -1, "cache_dir": str(self._root)}
