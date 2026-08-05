# FILE: src/forensiq/extraction/dll_hasher.py
"""DLL content hashing — populates DLLEntry.content_sha256 for threat-intel.

Phase 3 of the pipeline: the ThreatIntelDetector only queries suspicious DLLs
that carry a *genuine* SHA-256 content hash (see detectors/threat_intel.py).
Nothing in the extraction pipeline ever populated that field, so real-world
VirusTotal / MalwareBazaar lookups never fired. This module closes the gap by
hashing the actual DLL file content when a readable file is available.

Only real file bytes are ever hashed — a hash derived from the DLL *path
string* is meaningless to VT/MalwareBazaar and is never fabricated. A DLL whose
content cannot be resolved to a file keeps an empty content_sha256 and is
skipped downstream, exactly as the detector contract requires.

Resolution order for a DLL path:
    1. If FORENSIQ_DLL_ROOT is configured, resolve the (normalized) path under
       that root — the standard flow for offline Windows dump analysis where
       the suspect system's files are mounted / copied to the analysis host.
    2. Otherwise treat the DLL path as an absolute path on this host — the
       live Linux case, where /proc/PID/maps and linux.library_list yield real
       file paths.

MITRE ATT&CK:
    T1027 — Obfuscated Files or Information (artifact identification)
"""

from __future__ import annotations

import hashlib
import ntpath
import re
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath

from forensiq.models.artifact import DLLEntry
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Readable file-size cap: hashing stops beyond this size to avoid reading
# multi-GB files that would never be a loaded module.
_MAX_HASH_BYTES = 256 * 1024 * 1024  # 256 MB

# Device path prefixes to strip after normalizing to forward slashes, e.g.
# "/Device/HarddiskVolume1/", "/Volume{...}/", "/??/C:/".
_DEVICE_PREFIX_RE = re.compile(
    r"^(?:/device/[^/]+/|/volume[^/]*/|/\\\?\\)?",
    re.IGNORECASE,
)
# Windows drive letter prefix, e.g. "C:/".
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def _normalize_dll_path(path: str) -> str:
    """Normalize a DLL path to a forward-slash relative POSIX path.

    Strips device/volume prefixes and drive letters, so that a Windows path
    like ``\\Device\\HarddiskVolume1\\Windows\\evil.dll`` or
    ``C:\\Users\\victim\\evil.dll`` becomes ``Windows/evil.dll``.
    """
    if not path:
        return ""
    # Normalize backslashes to forward slashes for cross-platform resolution
    path = path.replace("\\", "/")
    # Collapse the redundant leading-slash device path used by Volatility
    stripped = _DEVICE_PREFIX_RE.sub("", path)
    stripped = _DRIVE_RE.sub("", stripped)
    return stripped.lstrip("/")


def _sha256_file(path: Path) -> str:
    """Compute the SHA-256 of a file, streaming, capped at _MAX_HASH_BYTES.

    Args:
        path: Path to a readable file.

    Returns:
        Lowercase hex SHA-256 digest, or empty string if the file cannot be
        read or exceeds the size cap.
    """
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > _MAX_HASH_BYTES:
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError, ValueError):
        return ""


def _resolve_dll_file(
    full_dll_name: str,
    dll_root: Path | None,
    exists: Callable[[Path], bool] = lambda p: p.is_file(),
) -> Path | None:
    """Resolve a DLL path to a readable file on the analysis host.

    Args:
        full_dll_name: The DLL path as reported by Volatility.
        dll_root: Optional root directory (FORENSIQ_DLL_ROOT). When set, the
            normalized path is resolved under it.
        exists: Predicate used to test candidates (injectable for tests).

    Returns:
        A Path to the DLL file if resolvable, else None.
    """
    if not full_dll_name:
        return None

    if dll_root is not None:
        rel = _normalize_dll_path(full_dll_name)
        if not rel:
            return None
        candidate = dll_root / PurePosixPath(rel)
        if exists(candidate):
            return candidate
        # Fall back to the raw basename under the root (matches by filename)
        base = ntpath.basename(full_dll_name.replace("\\", "/"))
        if base:
            by_name = dll_root / base
            if exists(by_name):
                return by_name
        return None

    # No DLL_ROOT: treat as an absolute path on this host (live Linux).
    candidate = Path(full_dll_name.replace("\\", "/"))
    if exists(candidate):
        return candidate
    return None


class DLLContentHasher:
    """Computes genuine SHA-256 content hashes for DLL artifacts.

    Args:
        dll_root: Optional root directory under which DLL paths are resolved.
            Falls back to the configured FORENSIQ_DLL_ROOT setting.
        only_suspicious: When True (default), only suspicious DLLs are hashed
            — matching the threat-intel detector's collection optimization.
    """

    def __init__(
        self,
        dll_root: Path | None = None,
        only_suspicious: bool = True,
    ) -> None:
        if dll_root is None:
            from forensiq.config.settings import get_settings

            dll_root = get_settings().get_dll_root()
        self._dll_root = dll_root
        self._only_suspicious = only_suspicious

    def hash_dlls(
        self,
        dlls_by_pid: dict[int, list[DLLEntry]],
    ) -> dict[int, list[DLLEntry]]:
        """Return a new dict with content_sha256 populated for hashable DLLs.

        Entries that already carry a valid content hash are left untouched
        (an upstream artifact may have pre-computed it). Never fabricates a
        hash: unresolvable files keep an empty content_sha256.

        Args:
            dlls_by_pid: DLL entries grouped by PID (as produced by
                DLLExtractor).

        Returns:
            A new dict with the same keys and updated DLLEntry instances.
        """
        hashed = 0
        skipped = 0
        result: dict[int, list[DLLEntry]] = {}

        for pid, entries in dlls_by_pid.items():
            new_entries: list[DLLEntry] = []
            for entry in entries:
                if self._only_suspicious and not entry.is_suspicious:
                    new_entries.append(entry)
                    continue
                # Already carries a genuine hash — keep it as-is.
                if re.fullmatch(r"[0-9a-f]{64}", entry.content_sha256):
                    new_entries.append(entry)
                    continue

                file_path = _resolve_dll_file(
                    entry.full_dll_name,
                    self._dll_root,
                )
                if file_path is None:
                    skipped += 1
                    new_entries.append(entry)
                    continue

                digest = _sha256_file(file_path)
                if not digest:
                    skipped += 1
                    new_entries.append(entry)
                    continue

                new_entries.append(
                    entry.model_copy(update={"content_sha256": digest})
                )
                hashed += 1

            result[pid] = new_entries

        if hashed or skipped:
            log.info(
                "DLL content hashing complete",
                hashed=hashed,
                skipped=skipped,
                root=str(self._dll_root) if self._dll_root else "none",
            )
        return result

    def hash_iterable(
        self,
        entries: Iterable[DLLEntry],
    ) -> list[DLLEntry]:
        """Hash an iterable of DLL entries without PID grouping.

        Convenience wrapper used by pipeline stages that operate on flat
        collections of DLLs.

        Args:
            entries: Any iterable of DLLEntry objects.

        Returns:
            A list of updated DLLEntry objects.
        """
        grouped: dict[int, list[DLLEntry]] = {}
        for entry in entries:
            grouped.setdefault(entry.pid, []).append(entry)
        updated = self.hash_dlls(grouped)
        return [entry for entries in updated.values() for entry in entries]

    # Public alias for discoverability; delegates to hash_dlls.
    def hash_entries(
        self,
        dlls_by_pid: dict[int, list[DLLEntry]],
    ) -> dict[int, list[DLLEntry]]:
        """Alias of :meth:`hash_dlls`."""
        return self.hash_dlls(dlls_by_pid)


__all__ = [
    "DLLContentHasher",
    "_normalize_dll_path",
    "_resolve_dll_file",
    "_sha256_file",
]
