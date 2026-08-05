# FILE: src/forensiq/pipeline/dump_context.py
"""Runtime context for a single ForensIQ analysis run.

:class:`DumpContext` is computed **once** at the start of the pipeline from
the dump path and user-supplied parameters, then passed to every internal
stage.  This replaces the pattern of threading a bare ``is_linux: bool``
flag through every method signature.

Benefits:
* OS detection logic lives in one place — adding macOS support means adding
  one attribute here, nowhere else.
* Method signatures are cleaner (one ``ctx`` argument instead of three).
* Future attributes (``is_macos``, ``kernel_version``, ``arch``) can be
  added without touching the pipeline or any method signatures.

Usage:
    from forensiq.pipeline.dump_context import DumpContext

    ctx = DumpContext.from_path(dump_path, threshold=0.65, correlation_id="abc123")
    if ctx.is_linux:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

#: File suffixes that unambiguously identify Linux memory dumps.
_LINUX_DUMP_SUFFIXES: frozenset[str] = frozenset({".lime", ".kcore"})


@dataclass(frozen=True)
class DumpContext:
    """Immutable runtime context for one analysis run.

    Attributes:
        dump_path: Absolute path to the memory dump file.
        is_linux: ``True`` when the dump originates from a Linux system.
        threshold: Threat score threshold for the malicious/benign decision.
        correlation_id: Short string used to correlate log entries for this run.
    """

    dump_path: Path
    is_linux: bool
    threshold: float
    correlation_id: str

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_path(
        cls,
        dump_path: Path,
        threshold: float,
        correlation_id: str,
    ) -> DumpContext:
        """Create a :class:`DumpContext` by inspecting the dump file path.

        OS detection rules (in priority order):

        1. ``/proc/kcore``       → Linux (kernel virtual address space)
        2. ``.lime`` extension   → Linux (LiME acquisition)
        3. ``.kcore`` extension  → Linux (ELF core dump)
        4. Everything else       → Windows (raw / vmem / dmp / img / …)

        Args:
            dump_path: Path to the memory dump (need not exist yet — detection
                is purely path-based).
            threshold: Malicious classification threshold ∈ [0.0, 1.0].
            correlation_id: Short unique ID for log correlation.

        Returns:
            A fully initialised, immutable :class:`DumpContext`.
        """
        is_linux = (
            dump_path.resolve() == Path("/proc/kcore")
            or dump_path.suffix.lower() in _LINUX_DUMP_SUFFIXES
        )
        return cls(
            dump_path=dump_path,
            is_linux=is_linux,
            threshold=threshold,
            correlation_id=correlation_id,
        )

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def os_label(self) -> str:
        """Human-readable OS label — ``"linux"`` or ``"windows"``."""
        return "linux" if self.is_linux else "windows"
