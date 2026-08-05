# FILE: tests/unit/test_dll_hasher.py
"""Unit tests for DLLContentHasher — Phase 3 artifact content hashing.

Verifies that genuine SHA-256 content hashes are computed from real file
bytes only, that the threat-intel candidate collection now fires on real
extraction output, and that no hash is ever fabricated from a path string.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from forensiq.extraction.dll_hasher import (
    DLLContentHasher,
    _normalize_dll_path,
    _resolve_dll_file,
    _sha256_file,
)
from forensiq.models.artifact import DLLEntry

_SUSPICIOUS_DLL = r"\Users\victim\AppData\Local\Temp\evil.dll"
_SAFE_DLL = r"\Windows\System32\ntdll.dll"


def _make_entry(full_name: str, pid: int = 100) -> DLLEntry:
    """Create a DLLEntry for the given path."""
    return DLLEntry(pid=pid, full_dll_name=full_name)


def _known_sha256(data: bytes) -> str:
    """Compute the expected SHA-256 for test bytes."""
    return hashlib.sha256(data).hexdigest()


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestNormalizeDllPath:
    def test_device_prefix_stripped(self) -> None:
        assert (
            _normalize_dll_path(r"\Device\HarddiskVolume1\Windows\evil.dll")
            == "Windows/evil.dll"
        )

    def test_drive_letter_stripped(self) -> None:
        assert _normalize_dll_path(r"C:\Users\victim\evil.dll") == "Users/victim/evil.dll"

    def test_forward_slash_normalized(self) -> None:
        assert _normalize_dll_path("C:/Users/victim/evil.dll") == "Users/victim/evil.dll"

    def test_plain_relative_kept(self) -> None:
        assert _normalize_dll_path("evil.dll") == "evil.dll"

    def test_empty_string(self) -> None:
        assert _normalize_dll_path("") == ""


class TestResolveDllFile:
    def test_returns_none_for_empty(self, tmp_path: Path) -> None:
        assert _resolve_dll_file("", tmp_path) is None

    def test_resolves_under_root(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "Users" / "victim" / "evil.dll"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"payload")
        resolved = _resolve_dll_file(r"C:\Users\victim\evil.dll", root)
        assert resolved is not None
        assert resolved == target

    def test_resolves_by_basename(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "evil.dll"
        target.write_bytes(b"payload")
        resolved = _resolve_dll_file(r"\Device\HarddiskVolume1\Temp\evil.dll", root)
        assert resolved is not None
        assert resolved == target

    def test_returns_none_when_missing(self, tmp_path: Path) -> None:
        assert _resolve_dll_file(r"C:\nope\missing.dll", tmp_path) is None

    def test_absolute_host_path_without_root(self, tmp_path: Path) -> None:
        target = tmp_path / "libevil.so"
        target.write_bytes(b"payload")
        resolved = _resolve_dll_file(str(target), None)
        assert resolved is not None
        assert resolved == target


class TestSha256File:
    def test_hashes_file_content(self, tmp_path: Path) -> None:
        target = tmp_path / "evil.dll"
        data = b"payload-bytes"
        target.write_bytes(data)
        assert _sha256_file(target) == _known_sha256(data)

    def test_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert _sha256_file(tmp_path / "missing.dll") == ""

    def test_empty_for_directory(self, tmp_path: Path) -> None:
        assert _sha256_file(tmp_path) == ""

    def test_empty_for_unreadable(self, tmp_path: Path, monkeypatch) -> None:
        target = tmp_path / "locked.dll"
        target.write_bytes(b"data")
        monkeypatch.setattr("forensiq.extraction.dll_hasher._MAX_HASH_BYTES", 2)
        assert _sha256_file(target) == ""


# ── DLLContentHasher ──────────────────────────────────────────────────────────


class TestDLLContentHasher:
    def test_hashes_suspicious_dll_from_root(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "Users" / "victim" / "AppData" / "Local" / "Temp" / "evil.dll"
        target.parent.mkdir(parents=True)
        data = b"malicious-content"
        target.write_bytes(data)
        entry = _make_entry(_SUSPICIOUS_DLL)
        hasher = DLLContentHasher(dll_root=root)
        result = hasher.hash_dlls({100: [entry]})
        updated = result[100][0]
        assert updated.content_sha256 == _known_sha256(data)
        assert len(updated.content_sha256) == 64

    def test_safe_dll_left_unhashed(self, tmp_path: Path) -> None:
        root = tmp_path
        (root / "Windows" / "System32").mkdir(parents=True)
        (root / "Windows" / "System32" / "ntdll.dll").write_bytes(b"system")
        entry = _make_entry(_SAFE_DLL)
        hasher = DLLContentHasher(dll_root=root)
        result = hasher.hash_dlls({100: [entry]})
        assert result[100][0].content_sha256 == ""

    def test_only_suspicious_false_hashes_safe_dll(self, tmp_path: Path) -> None:
        root = tmp_path
        (root / "Windows" / "System32").mkdir(parents=True)
        (root / "Windows" / "System32" / "ntdll.dll").write_bytes(b"system")
        entry = _make_entry(_SAFE_DLL)
        hasher = DLLContentHasher(dll_root=root, only_suspicious=False)
        result = hasher.hash_dlls({100: [entry]})
        assert len(result[100][0].content_sha256) == 64

    def test_missing_file_never_fabricates_hash(self, tmp_path: Path) -> None:
        entry = _make_entry(_SUSPICIOUS_DLL)
        hasher = DLLContentHasher(dll_root=tmp_path)
        result = hasher.hash_dlls({100: [entry]})
        assert result[100][0].content_sha256 == ""

    def test_existing_hash_preserved(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "evil.dll"
        target.write_bytes(b"content")
        entry = _make_entry(r"\Temp\evil.dll")
        entry = entry.model_copy(update={"content_sha256": "b" * 64})
        hasher = DLLContentHasher(dll_root=root)
        result = hasher.hash_dlls({100: [entry]})
        assert result[100][0].content_sha256 == "b" * 64

    def test_preserves_pid_grouping(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "evil.dll"
        target.write_bytes(b"payload")
        entry_a = _make_entry(r"\Temp\evil.dll", pid=100)
        entry_b = _make_entry(r"\Temp\evil.dll", pid=200)
        hasher = DLLContentHasher(dll_root=root)
        result = hasher.hash_dlls({100: [entry_a], 200: [entry_b]})
        assert set(result) == {100, 200}
        assert result[100][0].content_sha256 == result[200][0].content_sha256

    def test_hash_iterable_flat(self, tmp_path: Path) -> None:
        root = tmp_path
        target = root / "evil.dll"
        target.write_bytes(b"payload")
        entry = _make_entry(r"\Temp\evil.dll")
        hasher = DLLContentHasher(dll_root=root)
        result = hasher.hash_iterable([entry])
        assert len(result) == 1
        assert len(result[0].content_sha256) == 64

    def test_live_linux_absolute_path(self, tmp_path: Path) -> None:
        lib = tmp_path / "libevil.so.1"
        lib.write_bytes(b"shared-lib")
        entry = _make_entry(str(lib))
        hasher = DLLContentHasher(dll_root=None)
        result = hasher.hash_dlls({100: [entry]})
        assert result[100][0].content_sha256 == _known_sha256(b"shared-lib")

    def test_end_to_end_threat_intel_fires(self, tmp_path: Path) -> None:
        """A real extraction result flows into ThreatIntelDetector candidates."""
        from forensiq.detectors.threat_intel import ThreatIntelDetector
        from forensiq.extraction.orchestrator import ExtractionResult

        root = tmp_path
        target = root / "Users" / "victim" / "AppData" / "Local" / "Temp" / "evil.dll"
        target.parent.mkdir(parents=True)
        data = b"real-evil-bytes"
        target.write_bytes(data)

        entry = _make_entry(_SUSPICIOUS_DLL)
        hasher = DLLContentHasher(dll_root=root)
        dlls = hasher.hash_dlls({100: [entry]})

        extraction = ExtractionResult(
            dump_path=tmp_path / "dump.raw",
            dump_sha256="a" * 64,
            dlls=dlls,
        )

        det = ThreatIntelDetector(enabled=True, max_hashes=5)
        candidates = det._collect_content_hash_candidates(extraction)
        assert len(candidates) == 1
        assert candidates[0].sha256 == _known_sha256(data)
        assert candidates[0].pid == 100
