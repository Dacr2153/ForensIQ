# FILE: src/forensiq/models/artifact.py
"""Pydantic v2 models for memory forensic artifacts from Volatility 3.

Models:
    DLLEntry      — Loaded DLL from windows.dlllist plugin
    VADEntry      — Virtual Address Descriptor from windows.vadinfo plugin
    MalfindRegion — Suspicious memory region from windows.malfind plugin

Each model includes computed fields for suspicion indicators used during
feature engineering and report generation.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field, computed_field, field_validator

# ─── Suspicious DLL Heuristics ───────────────────────────────────────────────
# Directories commonly used for DLL planting and reflective loading (Windows)
_SUSPICIOUS_DLL_DIRS: tuple[str, ...] = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\users\\",
    "\\public\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
    "\\recycler\\",
    "$recycle.bin",
    "\\programdata\\",
    "\\windows\\temp\\",
)

# Legitimate Windows DLL extensions (absence is suspicious for loaded modules)
_DLL_EXTENSIONS: frozenset[str] = frozenset({".dll", ".ocx", ".sys", ".drv", ".cpl", ".ax"})

# Linux suspicious directories for shared libraries / executables
_LINUX_SUSPICIOUS_DIRS: tuple[str, ...] = (
    "/tmp/",  # noqa: S108
    "/dev/shm/",  # noqa: S108
    "/var/tmp/",  # noqa: S108
    "/run/user/",
)

# Linux shared library extension pattern: .so, .so.6, .so.6.0.1, etc.
_LINUX_SO_RE = re.compile(r"\.so(\.\d+)*$", re.IGNORECASE)


def _is_suspicious_dll_path(full_path: str) -> bool:
    """Heuristic: is this DLL/shared-library loaded from a suspicious location?

    Handles both Windows-style paths (backslash) and Linux-style paths (forward slash).

    Args:
        full_path: Full path of the loaded module from Volatility.

    Returns:
        True if any suspicion heuristic matches.
    """
    if not full_path:
        # No path at all — reflective injection or PEB unlinking
        return True

    # Special Linux pseudo-paths: memfd (anonymous executable mapping), [anon]
    if full_path.startswith("[") or "memfd:" in full_path:
        return True

    path_lower = full_path.lower()

    # ── Linux path (starts with /) ────────────────────────────────────────────
    if full_path.startswith("/"):
        # Check Linux suspicious directories
        for sus_dir in _LINUX_SUSPICIOUS_DIRS:
            if path_lower.startswith(sus_dir) or sus_dir in path_lower:
                return True
        # Verify it has a legitimate .so extension (.so, .so.6, .so.6.0.1, …)
        return not bool(_LINUX_SO_RE.search(path_lower))

    # ── Windows path ──────────────────────────────────────────────────────────
    # Check suspicious directories
    for suspicious_dir in _SUSPICIOUS_DLL_DIRS:
        if suspicious_dir in path_lower:
            return True

    # Check for missing .dll extension (legitimate system DLLs always have one)
    ext = Path(path_lower).suffix
    if ext and ext not in _DLL_EXTENSIONS:
        return True

    return False


# ─── VAD Protection Constants ─────────────────────────────────────────────────
# PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY are the primary IOCs for
# process injection and shellcode staging.
_RWX_PROTECTIONS: frozenset[str] = frozenset(
    {
        "PAGE_EXECUTE_READWRITE",
        "PAGE_EXECUTE_WRITECOPY",
        # Volatility sometimes uses numeric codes or abbreviated forms
        "EXECUTE_READWRITE",
        "EXECUTE_WRITECOPY",
    }
)


class DLLEntry(BaseModel):
    """A single DLL (loaded module) entry from windows.dlllist plugin.

    Represents one entry in the Process Environment Block (PEB) InMemoryOrderModuleList.
    Malware often injects DLLs from temp directories or uses reflective DLL loading
    (which results in no path or a suspicious path).
    """

    pid: int = Field(..., description="Owning process ID", ge=0)
    base: int = Field(default=0, description="Base virtual address of the loaded module")
    size: int = Field(default=0, description="Size of the mapped module in bytes", ge=0)
    full_dll_name: str = Field(
        default="",
        description="Full Windows path of the loaded DLL. "
        "Empty string indicates possible reflective injection.",
    )
    load_count: int = Field(
        default=1,
        description=(
            "Reference count. 0xFFFF (65535) is the 'load-order' sentinel value."
            " -1 means unknown (Volatility sentinel)."
        ),
        ge=-1,
    )
    content_sha256: str = Field(
        default="",
        description="SHA-256 hex digest of the DLL file *content*, when known. "
        "Empty string means the content hash is unavailable — threat-intel "
        "lookups are skipped for such entries rather than fabricating a hash "
        "from the path.",
    )

    @field_validator("full_dll_name")
    @classmethod
    def normalize_dll_path(cls, v: str) -> str:
        """Strip null bytes and normalize path string."""
        return v.strip().rstrip("\x00")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_suspicious(self) -> bool:
        """True if this DLL is loaded from a suspicious location or has no path.

        Heuristics:
            1. No path (reflective DLL injection bypasses disk)
            2. Loaded from TEMP, APPDATA, Users, Public, Downloads, etc.
            3. Non-standard file extension for a loaded module
        """
        return _is_suspicious_dll_path(self.full_dll_name)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def basename(self) -> str:
        """Return the filename component of the DLL path."""
        import ntpath

        return ntpath.basename(self.full_dll_name) if self.full_dll_name else ""

    def __repr__(self) -> str:
        return f"DLLEntry(pid={self.pid}, name={self.basename!r}, suspicious={self.is_suspicious})"


class VADEntry(BaseModel):
    """A Virtual Address Descriptor (VAD) entry from windows.vadinfo plugin.

    VADs describe memory regions in the process's virtual address space.
    RWX (read-write-execute) regions without a backing file on disk are
    the strongest indicator of shellcode staging or injected code.
    """

    pid: int = Field(..., description="Owning process ID", ge=0)
    start: int = Field(default=0, description="Start virtual address of the VAD region")
    end: int = Field(default=0, description="End virtual address of the VAD region")
    tag: str = Field(
        default="",
        description="VAD tag from the kernel pool (e.g., 'VadS' for private, 'Vad' for mapped).",
    )
    protection: str = Field(
        default="",
        description="Memory protection flags string (e.g., 'PAGE_EXECUTE_READWRITE').",
    )
    vad_type: str = Field(
        default="",
        description="VAD type: 'VadNone', 'VadImageMap', 'VadSectionView', etc.",
    )
    mapped_file: str | None = Field(
        None,
        description="File mapped into this VAD region. None for anonymous (private) memory.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_rwx(self) -> bool:
        """True if this VAD region has execute + write permissions simultaneously.

        An RWX region without a mapped file is the strongest single indicator
        of in-memory code injection or shellcode staging.
        """
        prot_upper = self.protection.upper()
        return any(rwx in prot_upper for rwx in _RWX_PROTECTIONS)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def size_bytes(self) -> int:
        """Return the size of this VAD region in bytes."""
        if self.end < self.start:
            return 0
        return self.end - self.start + 1

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_anonymous_rwx(self) -> bool:
        """True if this is an RWX region with NO backing file (strongest IOC).

        Private, executable, writable memory is the hallmark of shellcode.
        """
        return self.is_rwx and self.mapped_file is None

    def __repr__(self) -> str:
        return (
            f"VADEntry(pid={self.pid}, "
            f"start=0x{self.start:x}, "
            f"size={self.size_bytes // 1024}KB, "
            f"prot={self.protection!r}, "
            f"rwx={self.is_rwx})"
        )


class MalfindRegion(BaseModel):
    """A suspicious memory region flagged by windows.malfind plugin.

    windows.malfind identifies regions that are executable, were not mapped
    from disk, and optionally contain PE header signatures or shellcode patterns.

    Note: malfind can produce false positives (e.g., JIT-compiled code in
    .NET/Java processes). The ML model helps disambiguate these cases.
    """

    pid: int = Field(..., description="Owning process ID", ge=0)
    start: int = Field(default=0, description="Start virtual address of the suspicious region")
    end: int = Field(default=0, description="End virtual address of the suspicious region")
    protection: str = Field(
        default="",
        description="Memory protection flags at the time of the dump.",
    )
    tag: str = Field(
        default="",
        description="VAD tag for this region.",
    )
    hexdump: str = Field(
        default="",
        description="Hex dump of the first bytes of the suspicious region. "
        "PE headers start with '4d 5a' (MZ magic bytes).",
    )
    disassembly: str = Field(
        default="",
        description="Disassembly of the first instructions in the region.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_pe_header(self) -> bool:
        """True if the region starts with MZ magic bytes (PE executable header).

        An MZ header in a non-file-backed memory region strongly indicates
        reflective DLL loading or process hollowing.
        """
        if not self.hexdump:
            return False
        # Normalize hex dump: remove spaces, check for 4d5a at start
        cleaned = re.sub(r"\s+", "", self.hexdump.lower())
        return cleaned.startswith("4d5a")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def size_bytes(self) -> int:
        """Return the size of this suspicious region in bytes."""
        if self.end <= self.start:
            return 0
        return self.end - self.start

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_shellcode_indicators(self) -> bool:
        """True if the disassembly contains common shellcode instruction patterns.

        Checks for:
            - NOP sleds (common shellcode padding)
            - INT3 breakpoints (anti-debug / shellcode marker)
            - Common prologue bytes used in position-independent shellcode
        """
        if not self.disassembly:
            return False
        disasm_lower = self.disassembly.lower()
        shellcode_patterns = [
            "nop",  # NOP sled
            "int 3",  # Breakpoint
            "int3",  # Breakpoint (alternate notation)
            "call $+5",  # Common PIC shellcode pattern
            "push ebp",  # Function prologue (may indicate injected PE)
        ]
        return any(pattern in disasm_lower for pattern in shellcode_patterns)

    def __repr__(self) -> str:
        return (
            f"MalfindRegion(pid={self.pid}, "
            f"start=0x{self.start:x}, "
            f"size={self.size_bytes}B, "
            f"has_pe={self.has_pe_header})"
        )
