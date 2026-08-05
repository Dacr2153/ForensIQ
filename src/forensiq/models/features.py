# FILE: src/forensiq/models/features.py
"""Pydantic v2 model for the per-process ML feature vector.

ProcessFeatureVector holds the 15 engineered features derived from
Volatility 3 plugin output for a single process. It is the direct
input to the XGBoost classifier.

Feature engineering logic lives in forensiq.features.* modules.
This model only stores and validates the pre-computed values.

The 20 features are ordered canonically in FEATURE_NAMES. Any change
to this list requires retraining the model.
"""

from __future__ import annotations

from typing import ClassVar

import numpy as np
from pydantic import BaseModel, Field


class ProcessFeatureVector(BaseModel):
    """Per-process feature vector for the ForensIQ XGBoost classifier.

    Features are computed from Volatility 3 plugin output and cover:
        - Process name and path entropy (information-theoretic)
        - Parent-child relationship validation (MITRE T1036.005)
        - DLL load patterns (MITRE T1055)
        - Network behavior (MITRE T1055, T1071)
        - Memory injection indicators (MITRE T1055, T1055.012)
        - Thread and handle counts (process hollowing heuristic)
        - Command-line encoding (MITRE T1059.001, T1027)
    """

    # ─── Process Identity ──────────────────────────────────────────────────────
    pid: int = Field(..., description="Process ID", ge=0)
    name: str = Field(..., description="Process image name (from EPROCESS.ImageFileName)")
    ppid: int = Field(..., description="Parent Process ID", ge=0)

    # ─── Feature 1: Process name entropy ──────────────────────────────────────
    # Shannon entropy of the process executable name.
    # Legitimate system processes have low entropy (e.g., 'svchost.exe' = 3.12 bits).
    # Randomly-named malware payloads have high entropy (e.g., 'xqkR9mBz.exe' ≈ 3.8+ bits).
    process_name_entropy: float = Field(
        default=0.0,
        description="Shannon entropy of the process name [0.0, 8.0]",
        ge=0.0,
        le=8.0,
    )

    # ─── Feature 2: Image path entropy ────────────────────────────────────────
    # Shannon entropy of the full executable path.
    # Temp directories and randomly-named paths have higher entropy.
    path_entropy: float = Field(
        default=0.0,
        description="Shannon entropy of the full image file path [0.0, 8.0]",
        ge=0.0,
        le=8.0,
    )

    # ─── Feature 3: Path depth ────────────────────────────────────────────────
    # Number of directory components in the executable path.
    # System executables are typically at depth 2-3 (e.g., \Windows\System32\).
    # Malware often executes from shallow paths or temp dirs.
    path_depth: int = Field(
        default=0,
        description="Number of directory components in the executable path",
        ge=0,
    )

    # ─── Feature 4: Is system path ────────────────────────────────────────────
    # True if the executable is in a known-legitimate Windows system directory.
    # \Windows\System32\, \Windows\SysWOW64\, \Windows\, \Program Files\
    is_system_path: bool = Field(
        default=False,
        description="True if the executable runs from a known Windows system directory",
    )

    # ─── Feature 5: Parent-child legitimacy ───────────────────────────────────
    # True if the process-parent relationship matches known-good Windows patterns.
    # e.g., services.exe → svchost.exe is legitimate.
    #       explorer.exe → lsass.exe is suspicious (MITRE T1003.001).
    parent_child_legit: bool = Field(
        default=True,
        description="True if parent-child relationship is consistent with normal Windows behavior",
    )

    # ─── Feature 6: DLL count ─────────────────────────────────────────────────
    # Total number of DLLs loaded by the process.
    # Very high counts can indicate DLL injection.
    dll_count: int = Field(
        default=0,
        description="Total number of DLLs loaded by this process",
        ge=0,
    )

    # ─── Feature 7: Suspicious DLL count ──────────────────────────────────────
    # Count of DLLs loaded from suspicious paths (TEMP, APPDATA, etc.) or with no path.
    suspicious_dll_count: int = Field(
        default=0,
        description="Number of DLLs loaded from suspicious directories or with no path",
        ge=0,
    )

    # ─── Feature 8: Has network connection ────────────────────────────────────
    # Boolean: does this process have at least one network connection?
    # Many system processes should NOT have network connections.
    has_network_connection: bool = Field(
        default=False,
        description="True if the process has any TCP/UDP network socket",
    )

    # ─── Feature 9: Network connection count ──────────────────────────────────
    # Total TCP/UDP connections for this process.
    network_connection_count: int = Field(
        default=0,
        description="Total number of TCP/UDP sockets for this process",
        ge=0,
    )

    # ─── Feature 10: External connection count ────────────────────────────────
    # Connections to non-RFC1918 (internet-routable) IPs.
    # Legitimate system processes rarely make direct external connections.
    external_connection_count: int = Field(
        default=0,
        description="Number of connections to non-RFC1918 internet addresses",
        ge=0,
    )

    # ─── Feature 11: Malfind hits ─────────────────────────────────────────────
    # Number of regions flagged by windows.malfind for this process.
    # Strong indicator of code injection when > 0 (with false positive caveat for JIT).
    malfind_hits: int = Field(
        default=0,
        description="Number of suspicious memory regions flagged by windows.malfind",
        ge=0,
    )

    # ─── Feature 12: VAD RWX count ────────────────────────────────────────────
    # Number of Virtual Address Descriptor entries with PAGE_EXECUTE_READWRITE.
    # Injected shellcode and reflectively-loaded DLLs require RWX memory.
    vad_rwx_count: int = Field(
        default=0,
        description="Number of VAD entries with PAGE_EXECUTE_READWRITE protection",
        ge=0,
    )

    # ─── Feature 13: Thread count ─────────────────────────────────────────────
    # Total threads in this process.
    # Anomalously high thread counts can indicate thread-injection techniques.
    thread_count: int = Field(
        default=0,
        description="Number of active threads in this process",
        ge=0,
    )

    # ─── Feature 14: Handle count ─────────────────────────────────────────────
    # Total kernel handles (files, registry, processes, events, etc.).
    # High handle counts can indicate process monitors or rootkit behavior.
    handle_count: int = Field(
        default=0,
        description="Number of open kernel handles",
        ge=0,
    )

    # ─── Feature 15: Encoded command line ─────────────────────────────────────
    # True if the command line contains Base64 or hex-encoded payloads.
    # Strongly correlated with PowerShell download cradles (MITRE T1059.001).
    has_encoded_cmdline: bool = Field(
        default=False,
        description="True if the command line contains Base64 or hex-encoded strings",
    )

    # ─── Feature 16: VAD execute-write page count ─────────────────────────────
    # Total number of PAGES (not just regions) with RWX protection across all VADs.
    # A single shellcode injection may span hundreds of pages — this gives a
    # stronger signal than just counting regions (vad_rwx_count, feature 12).
    vad_execute_write_page_count: int = Field(
        default=0,
        description="Total memory pages with PAGE_EXECUTE_READWRITE across all VAD regions",
        ge=0,
    )

    # ─── Feature 17: Parent name mismatch ─────────────────────────────────────
    # True if the PPID field points to a process with a name that is NOT the
    # expected parent for this process name. Detects DKOM PPID spoofing and
    # process masquerading where malware forges its apparent parent chain.
    # E.g., cmd.exe claiming explorer.exe as parent but PPID resolves to svchost.exe.
    parent_name_mismatch: bool = Field(
        default=False,
        description="True if the PPID resolves to an unexpected parent process name",
    )

    # ─── Feature 18: Thread start address in heap ─────────────────────────────
    # True if any thread in this process has its start address in a heap/private
    # memory region rather than in a .text or DLL section. Shellcode injected
    # via CreateRemoteThread, NtCreateThread, etc., typically starts in private
    # memory — a strong indicator of process hollowing or thread injection.
    thread_start_in_heap: bool = Field(
        default=False,
        description="True if any thread starts from a heap/private memory region (not .text/DLL)",
    )

    # ─── Feature 19: Import table entropy ─────────────────────────────────────
    # Shannon entropy of the import table function names.
    # Legitimate DLLs import human-readable API names (low entropy).
    # Packed/obfuscated binaries may have encrypted or minimal import tables,
    # or import many unusual APIs that together have higher entropy.
    import_table_entropy: float = Field(
        default=0.0,
        description="Shannon entropy of the import table function names [0.0, 8.0]",
        ge=0.0,
        le=8.0,
    )

    # ─── Feature 20: Time delta from suspicious parent ─────────────────────────
    # Seconds between this process's creation and its parent's creation.
    # A near-zero delta (e.g., < 2 seconds) when the parent is already known
    # malicious or suspicious indicates a malware chain-of-execution launch.
    # Capped at 3600 (1 hour) to bound the feature range.
    time_delta_from_parent_seconds: float = Field(
        default=0.0,
        description="Seconds between this process creation and its parent's creation [0, 3600]",
        ge=0.0,
        le=3600.0,
    )

    # ─── Classification Results (filled post-inference) ───────────────────────
    threat_score: float = Field(
        default=0.0,
        description="Calibrated probability of maliciousness from the XGBoost classifier [0.0, 1.0]",
        ge=0.0,
        le=1.0,
    )
    isolation_score: float = Field(
        default=0.0,
        description="IsolationForest anomaly score normalized to [0.0, 1.0] (higher = more anomalous)",
        ge=0.0,
        le=1.0,
    )
    ensemble_score: float = Field(
        default=0.0,
        description="Combined score: 0.6 * xgboost_score + 0.4 * isolation_score",
        ge=0.0,
        le=1.0,
    )
    is_malicious: bool = Field(
        default=False,
        description="True if ensemble_score >= THREAT_THRESHOLD (configured via FORENSIQ_THREAT_THRESHOLD)",
    )
    shap_values: dict[str, float] = Field(
        default_factory=dict,
        description="SHAP feature importances for this prediction: feature_name → contribution",
    )

    # ─── Feature Name Registry ────────────────────────────────────────────────
    # CRITICAL: This ordering must match to_numpy_row() exactly.
    # Any change requires model retraining.
    FEATURE_NAMES: ClassVar[list[str]] = [
        "process_name_entropy",
        "path_entropy",
        "path_depth",
        "is_system_path",
        "parent_child_legit",
        "dll_count",
        "suspicious_dll_count",
        "has_network_connection",
        "network_connection_count",
        "external_connection_count",
        "malfind_hits",
        "vad_rwx_count",
        "thread_count",
        "handle_count",
        "has_encoded_cmdline",
        # New features (v2)
        "vad_execute_write_page_count",
        "parent_name_mismatch",
        "thread_start_in_heap",
        "import_table_entropy",
        "time_delta_from_parent_seconds",
    ]

    def to_numpy_row(self) -> list[float]:
        """Return the feature vector as a list of floats for numpy/XGBoost.

        Boolean features are cast to 1.0 / 0.0. The order matches FEATURE_NAMES
        exactly. This is the canonical input format for the ML classifier.

        Returns:
            20-element list of float values in FEATURE_NAMES order.
        """
        return [
            float(self.process_name_entropy),
            float(self.path_entropy),
            float(self.path_depth),
            1.0 if self.is_system_path else 0.0,
            1.0 if self.parent_child_legit else 0.0,
            float(self.dll_count),
            float(self.suspicious_dll_count),
            1.0 if self.has_network_connection else 0.0,
            float(self.network_connection_count),
            float(self.external_connection_count),
            float(self.malfind_hits),
            float(self.vad_rwx_count),
            float(self.thread_count),
            float(self.handle_count),
            1.0 if self.has_encoded_cmdline else 0.0,
            # New features (v2)
            float(self.vad_execute_write_page_count),
            1.0 if self.parent_name_mismatch else 0.0,
            1.0 if self.thread_start_in_heap else 0.0,
            float(self.import_table_entropy),
            float(self.time_delta_from_parent_seconds),
        ]

    def to_numpy_array(self) -> np.ndarray[tuple[int], np.dtype[np.float32]]:
        """Return the feature vector as a numpy float32 array (shape: (20,)).

        Used by XGBoost predict() and SHAP explainer.

        Returns:
            1D numpy array of shape (20,) with dtype float32.
        """
        return np.array(self.to_numpy_row(), dtype=np.float32)

    def __repr__(self) -> str:
        return (
            f"ProcessFeatureVector("
            f"pid={self.pid}, "
            f"name={self.name!r}, "
            f"threat_score={self.threat_score:.3f}, "
            f"is_malicious={self.is_malicious})"
        )
