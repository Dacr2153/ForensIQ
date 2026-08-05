# FILE: tests/integration/test_extraction.py
"""Integration tests for the extraction pipeline using mock VolatilityRunner.

These tests verify end-to-end extraction from fixture JSON data through
all extractors, without requiring Volatility 3 or a real memory dump.
"""

from __future__ import annotations

from forensiq.extraction.dll_extractor import DLLExtractor
from forensiq.extraction.network_extractor import NetworkExtractor
from forensiq.extraction.process_extractor import ProcessExtractor
from forensiq.extraction.vad_extractor import VADExtractor


class TestProcessExtractor:
    """Tests for ProcessExtractor with mock VolatilityRunner."""

    def test_extracts_all_processes(self, mock_vol_runner) -> None:
        extractor = ProcessExtractor(mock_vol_runner)
        tree = extractor.extract()
        assert tree is not None
        assert len(tree.flat_map) >= 3

    def test_system_process_has_pid_4(self, mock_vol_runner) -> None:
        extractor = ProcessExtractor(mock_vol_runner)
        tree = extractor.extract()
        assert 4 in tree.flat_map
        assert tree.flat_map[4].name.lower() == "system"

    def test_payload_has_encoded_cmdline(self, mock_vol_runner) -> None:
        extractor = ProcessExtractor(mock_vol_runner)
        tree = extractor.extract()
        payload = tree.flat_map.get(3388)
        assert payload is not None
        assert payload.cmdline is not None
        assert "-enc" in payload.cmdline.lower() or "SQBFAFgA" in payload.cmdline

    def test_tree_ppid_relationships(self, mock_vol_runner) -> None:
        extractor = ProcessExtractor(mock_vol_runner)
        tree = extractor.extract()
        svchost = tree.flat_map.get(1092)
        assert svchost is not None
        assert svchost.ppid == 636

    def test_parent_lookup_works(self, mock_vol_runner) -> None:
        extractor = ProcessExtractor(mock_vol_runner)
        tree = extractor.extract()
        parent = tree.get_parent(1092)
        assert parent is not None
        assert parent.pid == 636


class TestNetworkExtractor:
    """Tests for NetworkExtractor with mock VolatilityRunner."""

    def test_extracts_connections(self, mock_vol_runner) -> None:
        extractor = NetworkExtractor(mock_vol_runner)
        connections = extractor.extract()
        assert len(connections) > 0

    def test_payload_has_external_connection(self, mock_vol_runner) -> None:
        extractor = NetworkExtractor(mock_vol_runner)
        connections = extractor.extract()
        payload_conns = connections.get(3388, [])
        assert len(payload_conns) > 0
        assert any(c.is_external for c in payload_conns)

    def test_external_connection_has_suspicious_port(self, mock_vol_runner) -> None:
        extractor = NetworkExtractor(mock_vol_runner)
        connections = extractor.extract()
        payload_conns = connections.get(3388, [])
        assert any(c.is_suspicious_port for c in payload_conns)


class TestDLLExtractor:
    """Tests for DLLExtractor with mock VolatilityRunner."""

    def test_extracts_dlls(self, mock_vol_runner) -> None:
        extractor = DLLExtractor(mock_vol_runner)
        dlls = extractor.extract()
        assert len(dlls) > 0

    def test_svchost_has_system_dlls(self, mock_vol_runner) -> None:
        extractor = DLLExtractor(mock_vol_runner)
        dlls = extractor.extract()
        svchost_dlls = dlls.get(1092, [])
        assert len(svchost_dlls) >= 2
        # Should include ntdll and kernel32
        names = [d.basename.lower() for d in svchost_dlls]
        assert "ntdll.dll" in names

    def test_payload_has_suspicious_dll(self, mock_vol_runner) -> None:
        extractor = DLLExtractor(mock_vol_runner)
        dlls = extractor.extract()
        payload_dlls = dlls.get(3388, [])
        assert len(payload_dlls) >= 1
        assert any(d.is_suspicious for d in payload_dlls)


class TestVADExtractor:
    """Tests for VADExtractor with mock VolatilityRunner."""

    def test_extracts_vad_entries(self, mock_vol_runner) -> None:
        extractor = VADExtractor(mock_vol_runner)
        vads = extractor.extract_vad()
        assert len(vads) > 0

    def test_payload_has_rwx_vad(self, mock_vol_runner) -> None:
        extractor = VADExtractor(mock_vol_runner)
        vads = extractor.extract_vad()
        payload_vads = vads.get(3388, [])
        assert len(payload_vads) >= 1
        assert any(v.is_rwx for v in payload_vads)

    def test_extracts_malfind_regions(self, mock_vol_runner) -> None:
        extractor = VADExtractor(mock_vol_runner)
        malfind = extractor.extract_malfind()
        assert len(malfind) > 0

    def test_payload_malfind_has_pe_header(self, mock_vol_runner) -> None:
        extractor = VADExtractor(mock_vol_runner)
        malfind = extractor.extract_malfind()
        payload_regions = malfind.get(3388, [])
        assert len(payload_regions) >= 1
        assert any(r.has_pe_header for r in payload_regions)
