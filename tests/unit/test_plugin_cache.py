# FILE: tests/unit/test_plugin_cache.py
"""Unit tests for forensiq.cache.plugin_cache.PluginCache."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensiq.cache.plugin_cache import PluginCache, _sanitize_plugin_name


# ---------------------------------------------------------------------------
# _sanitize_plugin_name
# ---------------------------------------------------------------------------


def test_sanitize_valid_plugin_name():
    assert _sanitize_plugin_name("windows.pslist") == "windows.pslist"


def test_sanitize_valid_with_hyphen_and_number():
    assert _sanitize_plugin_name("linux.proc-list1") == "linux.proc-list1"


def test_sanitize_invalid_raises():
    with pytest.raises(ValueError, match="Unsafe plugin name"):
        _sanitize_plugin_name("../../etc/passwd")


def test_sanitize_slash_raises():
    with pytest.raises(ValueError, match="Unsafe plugin name"):
        _sanitize_plugin_name("windows/pslist")


# ---------------------------------------------------------------------------
# PluginCache — disabled mode
# ---------------------------------------------------------------------------


def test_disabled_cache_load_returns_none(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path, disabled=True)
    assert cache.load("abc123", "windows.pslist") is None


def test_disabled_cache_save_is_noop(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path, disabled=True)
    cache.save("abc123", "windows.pslist", [{"PID": 4}])
    # Nothing should be written
    assert list(tmp_path.rglob("*.json")) == []


def test_disabled_cache_is_cached_false(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path, disabled=True)
    assert cache.is_cached("abc123", "windows.pslist") is False


def test_disabled_env_var(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FORENSIQ_CACHE_DISABLED", "1")
    cache = PluginCache(cache_dir=tmp_path)
    assert cache.load("abc123", "windows.pslist") is None


def test_enabled_env_var(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("FORENSIQ_CACHE_DISABLED", "0")
    cache = PluginCache(cache_dir=tmp_path)
    assert cache._disabled is False


# ---------------------------------------------------------------------------
# PluginCache — save / load / is_cached round-trip
# ---------------------------------------------------------------------------


def test_save_and_load_roundtrip(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    rows = [{"PID": 4, "Name": "System"}, {"PID": 1092, "Name": "svchost.exe"}]
    sha256 = "a" * 64

    cache.save(sha256, "windows.pslist", rows)
    assert cache.is_cached(sha256, "windows.pslist")

    loaded = cache.load(sha256, "windows.pslist")
    assert loaded == rows


def test_load_miss_returns_none(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    assert cache.load("b" * 64, "windows.netscan") is None


def test_is_cached_false_before_save(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    assert cache.is_cached("c" * 64, "windows.malfind") is False


def test_save_creates_correct_directory_structure(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "d" * 64
    cache.save(sha256, "windows.pslist", [])

    # Cache splits sha256 into first 16 chars / remaining 48 chars
    expected_dir = tmp_path / sha256[:16] / sha256[16:]
    assert expected_dir.is_dir()
    assert len(list(expected_dir.glob("*.json"))) == 1


def test_load_corrupt_file_returns_none(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "e" * 64
    # Write corrupt JSON
    path = cache._entry_path(sha256, "windows.pslist")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json}", encoding="utf-8")

    assert cache.load(sha256, "windows.pslist") is None


def test_load_non_list_json_returns_none(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "f" * 64
    path = cache._entry_path(sha256, "windows.pslist")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"key": "value"}), encoding="utf-8")

    assert cache.load(sha256, "windows.pslist") is None


def test_is_cached_invalid_plugin_name(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    # Invalid plugin name should return False (not raise)
    assert cache.is_cached("a" * 64, "../evil") is False


# ---------------------------------------------------------------------------
# PluginCache — invalidate
# ---------------------------------------------------------------------------


def test_invalidate_single_plugin(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "a" * 64
    cache.save(sha256, "windows.pslist", [{"PID": 4}])

    assert cache.is_cached(sha256, "windows.pslist")
    cache.invalidate(sha256, "windows.pslist")
    assert not cache.is_cached(sha256, "windows.pslist")


def test_invalidate_all_plugins(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "b" * 64
    cache.save(sha256, "windows.pslist", [{"PID": 4}])
    cache.save(sha256, "windows.netscan", [])

    cache.invalidate(sha256)
    assert not cache.is_cached(sha256, "windows.pslist")
    assert not cache.is_cached(sha256, "windows.netscan")


def test_invalidate_nonexistent_plugin_is_noop(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    # Should not raise
    cache.invalidate("a" * 64, "windows.pslist")


# ---------------------------------------------------------------------------
# PluginCache — get_stats
# ---------------------------------------------------------------------------


def test_get_stats_empty_cache(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    stats = cache.get_stats()
    assert stats["total_entries"] == 0
    assert stats["disk_bytes"] == 0


def test_get_stats_with_entries(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path)
    sha256 = "a" * 64
    cache.save(sha256, "windows.pslist", [{"PID": 4}])
    cache.save(sha256, "windows.netscan", [])

    stats = cache.get_stats()
    assert stats["total_entries"] == 2
    assert stats["disk_bytes"] > 0
    assert "disk_mb" in stats
    assert "cache_dir" in stats


def test_get_stats_nonexistent_root(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path / "nonexistent")
    stats = cache.get_stats()
    assert stats["total_entries"] == 0


def test_get_stats_disabled_flag_shown(tmp_path: Path):
    cache = PluginCache(cache_dir=tmp_path, disabled=True)
    stats = cache.get_stats()
    assert stats.get("disabled") is True
