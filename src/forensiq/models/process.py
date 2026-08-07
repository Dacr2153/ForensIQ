# FILE: src/forensiq/models/process.py
"""Pydantic v2 models for Windows process artifacts from Volatility 3.

Models:
    ProcessArtifact — Single process entry (pslist/cmdline data)
    ProcessNode     — Tree node wrapping a ProcessArtifact with children
    ProcessTree     — Full process hierarchy with lookup methods
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ProcessArtifact(BaseModel):
    """A single Windows process extracted from a memory dump via Volatility 3.

    Fields correspond directly to columns from windows.pslist and windows.cmdline
    Volatility 3 plugins. All fields are optional where Volatility may return None
    (e.g., terminated processes may not have a cmdline).
    """

    # Core identifiers
    pid: int = Field(..., description="Process ID", ge=0)
    ppid: int = Field(..., description="Parent Process ID", ge=0)

    # Process name — ImageFileName from EPROCESS (limited to 15 chars in kernel)
    # image_file_name is the full path from PEB (more complete, may be None)
    name: str = Field(
        ..., description="Process image name (from EPROCESS.ImageFileName, max 15 chars)"
    )
    image_file_name: str = Field(
        default="",
        description="Full executable path from PEB (empty string if not available)",
    )

    # Command line — from windows.cmdline plugin (separate from pslist)
    cmdline: str | None = Field(
        None,
        description=(
            "Command line arguments from PEB. None if process is terminated or"
            " cmdline unavailable."
        ),
    )

    # Timestamps
    create_time: datetime | None = Field(
        None,
        description="Process creation UTC timestamp. None for some system processes.",
    )
    exit_time: datetime | None = Field(
        None,
        description="Process exit UTC timestamp. None if process is still running.",
    )

    # State
    is_active: bool = Field(
        default=True,
        description="True if the process is still running (ExitTime is null in dump).",
    )

    # Thread and handle counts — high values can indicate malicious activity
    threads: int = Field(default=0, description="Number of active threads", ge=0)
    handles: int = Field(default=0, description="Number of open handles", ge=0)
    session_id: int = Field(default=0, description="Windows Session ID", ge=0)

    # Architecture flags
    wow64: bool = Field(
        default=False,
        description="True if this is a 32-bit process running under WoW64 on a 64-bit OS. "
        "Injecting 64-bit code into a WoW64 process is an anomaly.",
    )

    # Memory addresses (used for cross-referencing with VAD/malfind output)
    peb_base: int = Field(
        default=0,
        description="Virtual address of the Process Environment Block (PEB).",
    )
    dtb: int = Field(
        default=0,
        description="Directory Table Base — physical address of page directory.",
    )

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        """Strip null bytes and whitespace from process name (Volatility raw output)."""
        return v.strip().rstrip("\x00")

    @field_validator("image_file_name")
    @classmethod
    def normalize_image_path(cls, v: str) -> str:
        """Normalize Windows path separators for cross-platform comparison."""
        return v.strip().rstrip("\x00")

    def is_terminated(self) -> bool:
        """Return True if the process had exited at dump time."""
        return self.exit_time is not None

    def __repr__(self) -> str:
        return f"ProcessArtifact(pid={self.pid}, name={self.name!r}, ppid={self.ppid})"

    def __hash__(self) -> int:
        return hash(self.pid)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProcessArtifact):
            return NotImplemented
        return self.pid == other.pid


class ProcessNode(BaseModel):
    """A node in the process tree, wrapping a ProcessArtifact with its children.

    Used to represent the full parent-child hierarchy of processes in a memory dump.
    Orphaned processes (whose PPID is not in the process list) are placed as roots.
    """

    artifact: ProcessArtifact = Field(..., description="The process artifact at this node.")
    children: list[ProcessNode] = Field(
        default_factory=list,
        description="Direct child processes spawned by this process.",
    )
    depth: int = Field(
        default=0,
        description="Depth in the tree (0 = root process like System or smss.exe).",
        ge=0,
    )

    model_config = {"arbitrary_types_allowed": True}

    def __repr__(self) -> str:
        return (
            f"ProcessNode(pid={self.artifact.pid}, "
            f"name={self.artifact.name!r}, "
            f"depth={self.depth}, "
            f"children={len(self.children)})"
        )


# Enable self-referential model (children: list[ProcessNode])
ProcessNode.model_rebuild()


class ProcessTree(BaseModel):
    """The complete process hierarchy extracted from a memory dump.

    Provides:
        - roots: Top-level processes (System, smss.exe, orphans)
        - flat_map: Fast pid → ProcessArtifact lookup for all processes
        - get_parent(): Find a process's parent
        - get_children(): List all direct children of a process
        - get_ancestors(): Walk up the tree to the root
    """

    roots: list[ProcessNode] = Field(
        default_factory=list,
        description="Root-level process nodes (no parent in the dump).",
    )
    flat_map: dict[int, ProcessArtifact] = Field(
        default_factory=dict,
        description="Fast lookup: pid → ProcessArtifact for all processes in the dump.",
    )

    def get_parent(self, pid: int) -> ProcessArtifact | None:
        """Return the parent ProcessArtifact for the given PID, or None.

        Args:
            pid: The process ID to look up.

        Returns:
            Parent ProcessArtifact, or None if not found / PID is a root.
        """
        process = self.flat_map.get(pid)
        if process is None:
            return None
        if process.ppid == 0 or process.ppid == pid:
            # PID 0 (Idle) and self-referencing PPIDs are roots
            return None
        return self.flat_map.get(process.ppid)

    def get_children(self, pid: int) -> list[ProcessArtifact]:
        """Return all direct child processes of the given PID.

        Args:
            pid: The parent process ID.

        Returns:
            List of ProcessArtifacts whose PPID == pid (excluding self-reference).
        """
        return [p for p in self.flat_map.values() if p.ppid == pid and p.pid != pid]

    def get_ancestors(self, pid: int) -> list[ProcessArtifact]:
        """Walk up the process tree from pid to root, returning ancestors.

        Args:
            pid: Starting process ID.

        Returns:
            Ordered list of ancestors, from immediate parent to root.
            Empty list if pid is a root or not found.
        """
        ancestors: list[ProcessArtifact] = []
        current_pid = pid
        # NOTE: visited set prevents infinite loops from DKOM-manipulated PPIDs
        visited: set[int] = {pid}

        while True:
            parent = self.get_parent(current_pid)
            if parent is None or parent.pid in visited:
                break
            ancestors.append(parent)
            visited.add(parent.pid)
            current_pid = parent.pid

        return ancestors

    def get_all_processes(self) -> list[ProcessArtifact]:
        """Return all processes in the dump as a flat list.

        Returns:
            All ProcessArtifacts sorted by PID.
        """
        return sorted(self.flat_map.values(), key=lambda p: p.pid)

    @property
    def name_map(self) -> dict[int, str]:
        """Fast pid → process name lookup for all processes in the dump.

        Returns:
            Mapping of pid → ProcessArtifact.name for every process.
        """
        return {pid: proc.name for pid, proc in self.flat_map.items()}

    def __len__(self) -> int:
        return len(self.flat_map)

    def __repr__(self) -> str:
        return f"ProcessTree(processes={len(self.flat_map)}, roots={len(self.roots)})"
