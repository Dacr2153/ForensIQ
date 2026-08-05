# FILE: tests/conftest.py
"""Shared pytest fixtures for ForensIQ test suite.

Provides:
  - Sample Volatility 3 plugin output (as dicts)
  - Mock VolatilityRunner
  - Sample ExtractionResult
  - Sample ProcessFeatureVectors (clean and malicious)
  - Temporary directory fixtures
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from forensiq.acquisition.volatility_runner import VolatilityRunner
from forensiq.extraction.orchestrator import ExtractionResult
from forensiq.models.artifact import DLLEntry, MalfindRegion, VADEntry
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.network import ConnectionState, NetworkConnection
from forensiq.models.process import ProcessArtifact, ProcessTree

# ── Fixture data paths ────────────────────────────────────────────────────────
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VOL_OUTPUTS_DIR = FIXTURES_DIR / "volatility_outputs"


# ══════════════════════════════════════════════════════════════════════════════
# Sample Process Artifacts
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_processes() -> list[ProcessArtifact]:
    """Three sample processes: System (clean), svchost (clean), injected_payload (malicious)."""
    return [
        ProcessArtifact(
            pid=4,
            ppid=0,
            name="System",
            image_file_name=r"",
            cmdline=None,
            create_time=datetime(2023, 1, 1, tzinfo=UTC),
            exit_time=None,
            is_active=True,
            threads=200,
            handles=4000,
            session_id=0,
            wow64=False,
            peb_base=0,
            dtb=0x1AA000,
        ),
        ProcessArtifact(
            pid=1092,
            ppid=636,
            name="svchost.exe",
            image_file_name=r"\Device\HarddiskVolume2\Windows\System32\svchost.exe",
            cmdline="svchost.exe -k netsvcs -p -s Browser",
            create_time=datetime(2023, 1, 1, 8, 0, tzinfo=UTC),
            exit_time=None,
            is_active=True,
            threads=12,
            handles=350,
            session_id=0,
            wow64=False,
            peb_base=0x7FF9C000,
            dtb=0x2A0000,
        ),
        ProcessArtifact(
            pid=3388,
            ppid=1092,
            name="payload.exe",
            image_file_name=r"\Device\HarddiskVolume2\Users\victim\AppData\Local\Temp\payload.exe",
            cmdline=r"payload.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA==",
            create_time=datetime(2023, 1, 1, 10, 30, tzinfo=UTC),
            exit_time=None,
            is_active=True,
            threads=4,
            handles=80,
            session_id=1,
            wow64=False,
            peb_base=0x400000,
            dtb=0x3F0000,
        ),
    ]


@pytest.fixture
def sample_process_tree(sample_processes: list[ProcessArtifact]) -> ProcessTree:
    """Build a ProcessTree from sample processes."""
    flat_map = {p.pid: p for p in sample_processes}
    return ProcessTree(roots=[], flat_map=flat_map)


# ══════════════════════════════════════════════════════════════════════════════
# Sample Network Connections
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_connections() -> dict[int, list[NetworkConnection]]:
    """Return network connections for svchost (clean) and payload (suspicious external)."""
    return {
        1092: [
            NetworkConnection(
                pid=1092,
                proto="TCPv4",
                local_addr="192.168.1.10",
                local_port=445,
                remote_addr="192.168.1.20",
                remote_port=49200,
                state=ConnectionState.ESTABLISHED,
            ),
        ],
        3388: [
            NetworkConnection(
                pid=3388,
                proto="TCPv4",
                local_addr="192.168.1.10",
                local_port=54321,
                remote_addr="185.220.101.45",  # External (not RFC1918)
                remote_port=4444,
                state=ConnectionState.ESTABLISHED,
            ),
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Sample DLL Entries
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_dlls() -> dict[int, list[DLLEntry]]:
    """DLLs for svchost (clean system DLLs) and payload (suspicious Temp DLL)."""
    return {
        1092: [
            DLLEntry(
                pid=1092,
                base=0x7FF900000000,
                size=0x100000,
                full_dll_name=r"\Windows\System32\ntdll.dll",
                load_count=65535,
            ),
            DLLEntry(
                pid=1092,
                base=0x7FF800000000,
                size=0x80000,
                full_dll_name=r"\Windows\System32\kernel32.dll",
                load_count=65535,
            ),
        ],
        3388: [
            DLLEntry(
                pid=3388,
                base=0x10000000,
                size=0x20000,
                full_dll_name=r"\Users\victim\AppData\Local\Temp\malicious.dll",
                load_count=1,
            ),
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Sample VAD and Malfind
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_vads() -> dict[int, list[VADEntry]]:
    """VAD entries: payload.exe has an anonymous RWX region."""
    return {
        3388: [
            VADEntry(
                pid=3388,
                start=0x400000,
                end=0x41FFFF,
                tag="VadS",
                protection="PAGE_EXECUTE_READWRITE",
                vad_type="VadNone",
                mapped_file=None,
            ),
            VADEntry(
                pid=3388,
                start=0x7FF000000000,
                end=0x7FF000020000,
                tag="Vad",
                protection="PAGE_READONLY",
                vad_type="VadImageMap",
                mapped_file=r"\Windows\System32\ntdll.dll",
            ),
        ],
    }


@pytest.fixture
def sample_malfind() -> dict[int, list[MalfindRegion]]:
    """Malfind regions: payload.exe has a PE-header-bearing injection."""
    return {
        3388: [
            MalfindRegion(
                pid=3388,
                start=0x400000,
                end=0x41FFFF,
                protection="PAGE_EXECUTE_READWRITE",
                tag="VadS",
                hexdump="4d5a 9000 0300 0000 0400 0000 ffff 0000 b800 0000",
                disassembly="0x400000  push ebp\n0x400001  mov esp, ebp",
            ),
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# ExtractionResult
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def sample_extraction(
    sample_process_tree: ProcessTree,
    sample_connections: dict,
    sample_dlls: dict,
    sample_vads: dict,
    sample_malfind: dict,
) -> ExtractionResult:
    """Complete ExtractionResult with all sample data."""
    return ExtractionResult(
        dump_path="/tmp/test_dump.raw",
        dump_sha256="a" * 64,
        dump_size_bytes=1024 * 1024 * 512,  # 512 MB
        process_tree=sample_process_tree,
        connections=sample_connections,
        dlls=sample_dlls,
        vads=sample_vads,
        malfind=sample_malfind,
        volatility_version="Volatility 3 Framework 2.5.0",
        failed_plugins=[],
    )


# ══════════════════════════════════════════════════════════════════════════════
# Feature Vectors
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def clean_vector() -> ProcessFeatureVector:
    """ProcessFeatureVector for a clean svchost process."""
    return ProcessFeatureVector(
        pid=1092,
        ppid=636,
        name="svchost.exe",
        image_file_name=r"\Windows\System32\svchost.exe",
        process_name_entropy=2.52,
        path_entropy=3.20,
        path_depth=4,
        is_system_path=True,
        parent_child_legit=True,
        dll_count=12,
        suspicious_dll_count=0,
        has_network_connection=True,
        network_connection_count=1,
        external_connection_count=0,
        malfind_hits=0,
        vad_rwx_count=0,
        thread_count=12,
        handle_count=350,
        has_encoded_cmdline=False,
        threat_score=0.05,
        is_malicious=False,
        shap_values={},
    )


@pytest.fixture
def malicious_vector() -> ProcessFeatureVector:
    """ProcessFeatureVector for a malicious payload process."""
    return ProcessFeatureVector(
        pid=3388,
        ppid=1092,
        name="payload.exe",
        image_file_name=r"\Users\victim\AppData\Local\Temp\payload.exe",
        process_name_entropy=3.78,
        path_entropy=4.10,
        path_depth=7,
        is_system_path=False,
        parent_child_legit=False,
        dll_count=1,
        suspicious_dll_count=1,
        has_network_connection=True,
        network_connection_count=1,
        external_connection_count=1,
        malfind_hits=1,
        vad_rwx_count=1,
        thread_count=4,
        handle_count=80,
        has_encoded_cmdline=True,
        threat_score=0.92,
        is_malicious=True,
        shap_values={
            "malfind_hits": 1.2,
            "has_encoded_cmdline": 0.8,
            "external_connection_count": 0.6,
            "is_system_path": -0.5,
            "parent_child_legit": -0.3,
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# Mock VolatilityRunner
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def mock_vol_runner() -> MagicMock:
    """Mock VolatilityRunner that returns fixture-based data."""
    runner = MagicMock(spec=VolatilityRunner)
    runner.dump_path = "/tmp/test_dump.raw"
    runner.timeout = 300
    runner.is_linux = False  # default to Windows for existing fixture-based tests

    def _run_plugin(plugin: str, extra_args: list[str] | None = None) -> list[dict]:
        fixture_file = VOL_OUTPUTS_DIR / f"{plugin.replace('.', '_')}.json"
        if fixture_file.exists():
            with fixture_file.open() as f:
                return json.load(f)
        return []

    runner.run_plugin.side_effect = _run_plugin
    runner.get_volatility_version.return_value = "Volatility 3 Framework 2.5.0"
    return runner


# ══════════════════════════════════════════════════════════════════════════════
# Temp directories
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def reports_dir(tmp_path: Path) -> Path:
    """Temporary reports directory."""
    d = tmp_path / "reports"
    d.mkdir()
    return d


@pytest.fixture
def model_dir(tmp_path: Path) -> Path:
    """Temporary ML model directory."""
    d = tmp_path / "models"
    d.mkdir()
    return d


@pytest.fixture
def yara_dir(tmp_path: Path) -> Path:
    """Temporary YARA rules directory."""
    d = tmp_path / "yara_rules"
    d.mkdir()
    return d
