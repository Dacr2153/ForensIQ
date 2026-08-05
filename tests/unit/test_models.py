# FILE: tests/unit/test_models.py
"""Unit tests for Pydantic data models."""

from __future__ import annotations

from forensiq.models.artifact import DLLEntry, MalfindRegion, VADEntry
from forensiq.models.features import ProcessFeatureVector
from forensiq.models.network import ConnectionState, NetworkConnection
from forensiq.models.process import ProcessArtifact, ProcessTree


class TestNetworkConnection:
    """Tests for NetworkConnection computed fields."""

    def test_external_ip_is_external(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="185.220.101.45",
            remote_port=443,
            state=ConnectionState.ESTABLISHED,
        )
        assert conn.is_external is True

    def test_rfc1918_is_not_external(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="10.0.0.1",
            remote_port=80,
            state=ConnectionState.ESTABLISHED,
        )
        assert conn.is_external is False

    def test_suspicious_port_4444(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="185.220.101.45",
            remote_port=4444,
            state=ConnectionState.ESTABLISHED,
        )
        assert conn.is_suspicious_port is True

    def test_standard_port_not_suspicious(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="8.8.8.8",
            remote_port=443,
            state=ConnectionState.ESTABLISHED,
        )
        assert conn.is_suspicious_port is False

    def test_established_is_active(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="8.8.8.8",
            remote_port=443,
            state=ConnectionState.ESTABLISHED,
        )
        assert conn.is_active is True

    def test_close_wait_not_active(self) -> None:
        conn = NetworkConnection(
            pid=100,
            proto="TCPv4",
            local_addr="192.168.1.10",
            local_port=12345,
            remote_addr="8.8.8.8",
            remote_port=443,
            state=ConnectionState.CLOSE_WAIT,
        )
        assert conn.is_active is False


class TestDLLEntry:
    """Tests for DLLEntry computed fields."""

    def test_temp_dll_is_suspicious(self) -> None:
        dll = DLLEntry(
            pid=100,
            base=0x10000000,
            size=0x10000,
            full_dll_name=r"\Users\user\AppData\Local\Temp\evil.dll",
            load_count=1,
        )
        assert dll.is_suspicious is True

    def test_system32_dll_not_suspicious(self) -> None:
        dll = DLLEntry(
            pid=100,
            base=0x7FF000000000,
            size=0x100000,
            full_dll_name=r"\Windows\System32\ntdll.dll",
            load_count=65535,
        )
        assert dll.is_suspicious is False

    def test_basename_extraction(self) -> None:
        dll = DLLEntry(
            pid=100,
            base=0x10000000,
            size=0x10000,
            full_dll_name=r"\Windows\System32\kernel32.dll",
            load_count=1,
        )
        assert dll.basename == "kernel32.dll"

    def test_empty_dll_name_not_suspicious(self) -> None:
        # Empty DLL name indicates reflective DLL injection (no path on disk).
        # This is intentionally flagged as suspicious by design.
        dll = DLLEntry(
            pid=100,
            base=0x10000000,
            size=0x10000,
            full_dll_name="",
            load_count=0,
        )
        assert dll.is_suspicious is True  # Reflective injection — no path = suspicious


class TestVADEntry:
    """Tests for VADEntry computed fields."""

    def test_rwx_vad_detected(self) -> None:
        vad = VADEntry(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            tag="VadS",
            protection="PAGE_EXECUTE_READWRITE",
            vad_type="VadNone",
            mapped_file=None,
        )
        assert vad.is_rwx is True

    def test_readonly_vad_not_rwx(self) -> None:
        vad = VADEntry(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            tag="Vad",
            protection="PAGE_READONLY",
            vad_type="VadImageMap",
            mapped_file=r"\ntdll.dll",
        )
        assert vad.is_rwx is False

    def test_anonymous_rwx(self) -> None:
        vad = VADEntry(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            tag="VadS",
            protection="PAGE_EXECUTE_READWRITE",
            vad_type="VadNone",
            mapped_file=None,
        )
        assert vad.is_anonymous_rwx is True

    def test_size_bytes(self) -> None:
        vad = VADEntry(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            tag="VadS",
            protection="PAGE_EXECUTE_READWRITE",
            vad_type="VadNone",
            mapped_file=None,
        )
        assert vad.size_bytes == 0x41FFFF - 0x400000 + 1


class TestMalfindRegion:
    """Tests for MalfindRegion computed fields."""

    def test_pe_header_detection(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            protection="PAGE_EXECUTE_READWRITE",
            tag="VadS",
            hexdump="4d5a 9000 0300 0000",
            disassembly="",
        )
        assert region.has_pe_header is True

    def test_no_pe_header(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            protection="PAGE_EXECUTE_READWRITE",
            tag="VadS",
            hexdump="5060 7080 9000 abcd",
            disassembly="",
        )
        assert region.has_pe_header is False

    def test_shellcode_indicators_nop(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x400000,
            end=0x41FFFF,
            protection="PAGE_EXECUTE_READWRITE",
            tag="VadS",
            hexdump="9090 9090 9090 9090",
            disassembly="NOP\nNOP\nNOP\nNOP",
        )
        assert region.has_shellcode_indicators is True

    def test_has_pe_header_false_when_empty_hexdump(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x1000,
            end=0x2000,
            protection="PAGE_EXECUTE_READWRITE",
            hexdump="",
        )
        assert region.has_pe_header is False

    def test_size_bytes_when_end_equal_start(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x1000,
            end=0x1000,
            protection="PAGE_EXECUTE_READWRITE",
        )
        assert region.size_bytes == 0

    def test_has_shellcode_indicators_false_when_empty_disassembly(self) -> None:
        region = MalfindRegion(
            pid=100,
            start=0x1000,
            end=0x2000,
            protection="PAGE_EXECUTE_READWRITE",
            disassembly="",
        )
        assert region.has_shellcode_indicators is False


class TestProcessTree:
    """Tests for ProcessTree traversal methods."""

    def _make_tree(self) -> ProcessTree:
        processes = {
            4: ProcessArtifact(
                pid=4,
                ppid=0,
                name="System",
                image_file_name="",
                is_active=True,
                threads=100,
                handles=1000,
                session_id=0,
                wow64=False,
                peb_base=0,
                dtb=0,
            ),
            636: ProcessArtifact(
                pid=636,
                ppid=4,
                name="services.exe",
                image_file_name=r"\Windows\System32\services.exe",
                is_active=True,
                threads=5,
                handles=200,
                session_id=0,
                wow64=False,
                peb_base=0x7FF0000,
                dtb=0x1000,
            ),
            1092: ProcessArtifact(
                pid=1092,
                ppid=636,
                name="svchost.exe",
                image_file_name=r"\Windows\System32\svchost.exe",
                is_active=True,
                threads=12,
                handles=350,
                session_id=0,
                wow64=False,
                peb_base=0x7FF1000,
                dtb=0x2000,
            ),
        }
        return ProcessTree(roots=[], flat_map=processes)

    def test_get_parent(self) -> None:
        tree = self._make_tree()
        parent = tree.get_parent(1092)
        assert parent is not None
        assert parent.pid == 636

    def test_get_parent_of_root(self) -> None:
        tree = self._make_tree()
        parent = tree.get_parent(4)
        assert parent is None

    def test_get_children(self) -> None:
        tree = self._make_tree()
        children = tree.get_children(636)
        assert any(c.pid == 1092 for c in children)

    def test_get_ancestors(self) -> None:
        tree = self._make_tree()
        ancestors = tree.get_ancestors(1092)
        assert any(a.pid == 636 for a in ancestors)
        assert any(a.pid == 4 for a in ancestors)

    def test_get_all_processes(self) -> None:
        tree = self._make_tree()
        all_procs = tree.get_all_processes()
        assert len(all_procs) == 3
        pids = {p.pid for p in all_procs}
        assert pids == {4, 636, 1092}


class TestProcessFeatureVector:
    """Tests for ProcessFeatureVector."""

    def test_to_numpy_row_length(self, malicious_vector: ProcessFeatureVector) -> None:
        row = malicious_vector.to_numpy_row()
        assert len(row) == 20

    def test_to_numpy_array_shape(self, malicious_vector: ProcessFeatureVector) -> None:
        arr = malicious_vector.to_numpy_array()
        assert arr.shape == (20,)

    def test_bool_features_cast_to_float(self, malicious_vector: ProcessFeatureVector) -> None:
        row = malicious_vector.to_numpy_row()
        # All values should be floats
        for val in row:
            assert isinstance(val, float)

    def test_feature_names_count(self) -> None:
        assert len(ProcessFeatureVector.FEATURE_NAMES) == 20

    def test_new_v2_fields_have_defaults(self) -> None:
        """New v2 fields must have sane defaults (no required params)."""
        vec = ProcessFeatureVector(pid=1, name="test.exe", ppid=0)
        assert vec.vad_execute_write_page_count == 0
        assert vec.parent_name_mismatch is False
        assert vec.thread_start_in_heap is False
        assert vec.import_table_entropy == 0.0
        assert vec.time_delta_from_parent_seconds == 0.0
        assert vec.isolation_score == 0.0
        assert vec.ensemble_score == 0.0

    def test_ensemble_score_in_range(self, malicious_vector: ProcessFeatureVector) -> None:
        """ensemble_score must be in [0, 1]."""
        updated = malicious_vector.model_copy(update={"ensemble_score": 0.85})
        assert 0.0 <= updated.ensemble_score <= 1.0


# ── Artifact model uncovered branches ────────────────────────────────────────


class TestDLLEntryIsSuspiciousPath:
    def test_empty_path_is_suspicious(self) -> None:
        dll = DLLEntry(pid=100, full_dll_name="")
        assert dll.is_suspicious is True

    def test_linux_anon_bracket_is_suspicious(self) -> None:
        dll = DLLEntry(pid=100, full_dll_name="[anon:libc]")
        assert dll.is_suspicious is True

    def test_linux_memfd_is_suspicious(self) -> None:
        dll = DLLEntry(pid=100, full_dll_name="/memfd:/evil")
        assert dll.is_suspicious is True

    def test_linux_so_legit_path(self) -> None:
        dll = DLLEntry(pid=100, full_dll_name="/usr/lib/libc.so.6")
        assert dll.is_suspicious is False

    def test_linux_proc_path_no_so_ext(self) -> None:
        dll = DLLEntry(pid=100, full_dll_name="/tmp/evil_payload")
        assert dll.is_suspicious is True


class TestVADEntrySizeBytes:
    def test_size_when_end_less_than_start(self) -> None:
        vad = VADEntry(pid=100, start=0x2000, end=0x1000, protection="PAGE_NOACCESS")
        assert vad.size_bytes == 0


# ── Network model uncovered branches ──────────────────────────────────────────


class TestNetworkConnectionUncovered:
    def _make_conn(self, **kwargs) -> NetworkConnection:
        defaults = {
            "pid": 100,
            "proto": "TCPv4",
            "local_addr": "192.168.1.1",
            "local_port": 12345,
            "remote_addr": "8.8.8.8",
            "remote_port": 80,
            "state": ConnectionState.ESTABLISHED,
        }
        defaults.update(kwargs)
        return NetworkConnection(**defaults)

    def test_unresolved_remote_addr_is_not_external(self) -> None:
        conn = self._make_conn(remote_addr="N/A")
        assert conn.is_external is False

    def test_empty_remote_addr_is_not_external(self) -> None:
        conn = self._make_conn(remote_addr="")
        assert conn.is_external is False

    def test_hostname_remote_addr_is_not_external(self) -> None:
        conn = self._make_conn(remote_addr="DESKTOP-XYZ")
        assert conn.is_external is False

    def test_state_none_normalizes_to_unknown(self) -> None:
        conn = self._make_conn(state=None)
        assert conn.state == ConnectionState.UNKNOWN

    def test_state_dash_normalizes_to_unknown(self) -> None:
        conn = self._make_conn(state="-")
        assert conn.state == ConnectionState.UNKNOWN

    def test_non_suspicious_port_returns_false(self) -> None:
        conn = self._make_conn(local_port=12345, remote_port=80)
        assert conn.is_suspicious_port is False


# ── ProcessArtifact and ProcessTree uncovered branches ────────────────────────


class TestProcessArtifactUncovered:
    def _make_proc(self, pid=100, ppid=4, name="svchost.exe", exit_time=None):
        from forensiq.models.process import ProcessArtifact
        return ProcessArtifact(pid=pid, name=name, ppid=ppid, exit_time=exit_time)

    def test_is_terminated_false_when_no_exit_time(self):
        proc = self._make_proc()
        assert proc.is_terminated() is False

    def test_is_terminated_true_when_exit_time_set(self):
        from datetime import UTC, datetime
        proc = self._make_proc(exit_time=datetime(2024, 1, 1, tzinfo=UTC))
        assert proc.is_terminated() is True

    def test_repr_contains_pid_and_name(self):
        proc = self._make_proc(pid=1234, name="evil.exe")
        r = repr(proc)
        assert "1234" in r
        assert "evil.exe" in r

    def test_hash_is_based_on_pid(self):
        from forensiq.models.process import ProcessArtifact
        p1 = ProcessArtifact(pid=100, name="svchost.exe", ppid=4)
        p2 = ProcessArtifact(pid=100, name="different.exe", ppid=99)
        assert hash(p1) == hash(p2)

    def test_eq_returns_not_implemented_for_non_process(self):
        proc = self._make_proc()
        result = proc.__eq__("not a process")
        assert result is NotImplemented

    def test_get_parent_returns_none_when_pid_not_in_flat_map(self):
        from forensiq.models.process import ProcessTree
        tree = ProcessTree(roots=[], flat_map={})
        result = tree.get_parent(9999)
        assert result is None
