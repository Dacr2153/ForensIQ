# FILE: tests/unit/test_handles_and_services.py
"""Unit tests for HandlesMutexDetector and ServicesScanDetector."""

from __future__ import annotations

from unittest.mock import patch

from forensiq.detectors.base import FindingSeverity
from forensiq.detectors.handles_mutex import HandlesMutexDetector
from forensiq.detectors.services_scan import ServicesScanDetector
from forensiq.extraction.handles_extractor import HandleEntry
from forensiq.extraction.services_extractor import ServiceEntry
from forensiq.models.features import ProcessFeatureVector

# ── Helpers ───────────────────────────────────────────────────────────────────


def _vec(**kwargs) -> ProcessFeatureVector:
    defaults = {
        "pid": 100,
        "ppid": 4,
        "name": "test.exe",
        "image_file_name": r"\Windows\System32\test.exe",
        "process_name_entropy": 2.5,
        "path_entropy": 3.0,
        "path_depth": 4,
        "is_system_path": True,
        "parent_child_legit": True,
        "dll_count": 5,
        "suspicious_dll_count": 0,
        "has_network_connection": False,
        "network_connection_count": 0,
        "external_connection_count": 0,
        "malfind_hits": 0,
        "vad_rwx_count": 0,
        "thread_count": 5,
        "handle_count": 100,
        "has_encoded_cmdline": False,
        "threat_score": 0.05,
        "is_malicious": False,
        "shap_values": {},
    }
    defaults.update(kwargs)
    return ProcessFeatureVector(**defaults)


def _handle(
    pid: int = 3388,
    process_name: str = "payload.exe",
    handle_type: str = "Mutant",
    name: str = "global\\njrat_mutex",
    handle_value: str = "0x1a0",
    granted_access: str = "0x1f0001",
) -> HandleEntry:
    return HandleEntry(
        pid=pid,
        process_name=process_name,
        handle_value=handle_value,
        handle_type=handle_type,
        name=name,
        granted_access=granted_access,
    )


def _service(
    service_name: str = "EvilSvc",
    display_name: str = "Evil Service",
    binary_path: str = r"C:\Users\victim\AppData\Local\Temp\evil.exe",
    service_type: str = "SERVICE_WIN32_OWN_PROCESS",
    service_state: str = "SERVICE_RUNNING",
    pid: int = 3388,
    order: int = 1,
) -> ServiceEntry:
    return ServiceEntry(
        order=order,
        pid=pid,
        service_name=service_name,
        display_name=display_name,
        service_type=service_type,
        service_state=service_state,
        binary_path=binary_path,
    )


# ── HandlesMutexDetector ──────────────────────────────────────────────────────


class TestHandlesMutexDetector:
    def test_name(self):
        assert HandlesMutexDetector.name == "handles_mutex"

    def test_extract_failure_returns_empty(self, sample_extraction):
        """If handles extraction fails, detect returns []."""
        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.side_effect = RuntimeError("plugin failed")
            results = det.detect(sample_extraction, [])
        assert results == []

    def test_no_handles_returns_empty(self, sample_extraction):
        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = {}
            results = det.detect(sample_extraction, [])
        assert results == []

    def test_suspicious_mutex_found(self, sample_extraction):
        mutex_handle = _handle(handle_type="Mutant", name="global\\njrat_mutex")
        assert mutex_handle.is_suspicious_mutex

        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = {3388: [mutex_handle]}
            results = det.detect(sample_extraction, [_vec(pid=3388, name="payload.exe")])

        assert len(results) == 1
        assert results[0].detector == "handles_mutex"
        assert results[0].severity == FindingSeverity.HIGH
        assert "mutex" in results[0].title.lower()
        assert results[0].mitre_technique == "T1480"

    def test_suspicious_registry_found(self, sample_extraction):
        reg_handle = _handle(
            handle_type="Key",
            name=r"HKLM\software\microsoft\windows\currentversion\run",
        )
        assert reg_handle.is_suspicious_registry

        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = {3388: [reg_handle]}
            results = det.detect(sample_extraction, [_vec(pid=3388)])

        assert len(results) == 1
        assert "persistence" in results[0].title.lower() or "registry" in results[0].title.lower()
        assert results[0].mitre_technique == "T1547.001"

    def test_both_mutex_and_registry_gives_two_findings(self, sample_extraction):
        mutex_handle = _handle(handle_type="Mutant", name="global\\njrat_mutex")
        reg_handle = _handle(
            handle_type="Key",
            name=r"HKLM\software\microsoft\windows\currentversion\run",
        )

        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = {
                3388: [mutex_handle, reg_handle]
            }
            results = det.detect(sample_extraction, [_vec(pid=3388)])

        assert len(results) == 2

    def test_non_suspicious_handle_ignored(self, sample_extraction):
        clean_handle = _handle(
            handle_type="File",
            name=r"\Device\HarddiskVolume2\Windows\system32\ntdll.dll",
        )

        det = HandlesMutexDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.handles_mutex.HandlesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = {3388: [clean_handle]}
            results = det.detect(sample_extraction, [])

        assert results == []


# ── HandleEntry property tests ────────────────────────────────────────────────


class TestHandleEntry:
    def test_mutant_type_with_known_pattern(self):
        h = _handle(handle_type="Mutant", name="global\\gh0st_mutex")
        assert h.is_suspicious_mutex is True

    def test_mutant_type_clean_name(self):
        h = _handle(handle_type="Mutant", name="MyApp_Instance")
        assert h.is_suspicious_mutex is False

    def test_file_type_not_suspicious_mutex(self):
        h = _handle(handle_type="File", name="global\\njrat")
        assert h.is_suspicious_mutex is False

    def test_key_type_run_path_suspicious(self):
        h = _handle(
            handle_type="Key",
            name=r"HKLM\software\microsoft\windows\currentversion\run\evil",
        )
        assert h.is_suspicious_registry is True

    def test_key_type_clean_path_not_suspicious(self):
        h = _handle(
            handle_type="Key",
            name=r"HKLM\software\microsoft\windows\currentversion\uninstall\foo",
        )
        assert h.is_suspicious_registry is False


# ── ServicesScanDetector ──────────────────────────────────────────────────────


class TestServicesScanDetector:
    def test_name(self):
        assert ServicesScanDetector.name == "services_scan"

    def test_extract_failure_returns_empty(self, sample_extraction):
        det = ServicesScanDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.services_scan.ServicesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.side_effect = RuntimeError("svcscan failed")
            results = det.detect(sample_extraction, [])
        assert results == []

    def test_clean_service_not_flagged(self, sample_extraction):
        clean_svc = _service(
            binary_path=r"C:\Windows\System32\svchost.exe -k netsvcs",
            service_state="SERVICE_RUNNING",
        )
        assert not clean_svc.is_suspicious_path

        det = ServicesScanDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.services_scan.ServicesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = [clean_svc]
            results = det.detect(sample_extraction, [])
        assert results == []

    def test_suspicious_path_running_service_flagged(self, sample_extraction):
        evil_svc = _service(
            binary_path=r"C:\Users\victim\AppData\Local\Temp\evil.exe",
            service_state="SERVICE_RUNNING",
        )
        assert evil_svc.is_suspicious_path
        assert evil_svc.is_running

        det = ServicesScanDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.services_scan.ServicesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = [evil_svc]
            results = det.detect(sample_extraction, [])

        assert len(results) == 1
        assert results[0].mitre_technique == "T1543.003"
        assert results[0].severity == FindingSeverity.HIGH

    def test_suspicious_path_with_malicious_pid_is_critical(self, sample_extraction):
        evil_svc = _service(
            pid=3388,
            binary_path=r"C:\Users\victim\AppData\Local\Temp\evil.exe",
            service_state="SERVICE_RUNNING",
        )
        vectors = [_vec(pid=3388, is_malicious=True, threat_score=0.9)]

        det = ServicesScanDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.services_scan.ServicesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = [evil_svc]
            results = det.detect(sample_extraction, vectors)

        assert len(results) == 1
        assert results[0].severity == FindingSeverity.CRITICAL

    def test_malicious_pid_service_flagged(self, sample_extraction):
        """Service linked to a malicious PID (even if path is clean) is flagged."""
        clean_path_svc = _service(
            pid=3388,
            binary_path=r"C:\Windows\System32\svchost.exe",
            service_state="SERVICE_RUNNING",
        )
        vectors = [_vec(pid=3388, is_malicious=True, threat_score=0.9)]

        det = ServicesScanDetector()
        with (
            patch("forensiq.acquisition.volatility_runner.VolatilityRunner"),
            patch(
                "forensiq.detectors.services_scan.ServicesExtractor"
            ) as mock_ext_cls,
        ):
            mock_ext_cls.return_value.extract.return_value = [clean_path_svc]
            results = det.detect(sample_extraction, vectors)

        assert len(results) == 1
        assert results[0].severity == FindingSeverity.CRITICAL
        assert "malicious" in results[0].description


# ── ServiceEntry property tests ───────────────────────────────────────────────


class TestServiceEntry:
    def test_suspicious_path_temp(self):
        s = _service(binary_path=r"C:\Users\victim\AppData\Local\Temp\evil.exe")
        assert s.is_suspicious_path is True

    def test_clean_path(self):
        s = _service(binary_path=r"C:\Windows\System32\svchost.exe")
        assert s.is_suspicious_path is False

    def test_no_path_is_suspicious(self):
        s = _service(binary_path="")
        assert s.is_suspicious_path is True

    def test_is_running(self):
        s = _service(service_state="SERVICE_RUNNING")
        assert s.is_running is True

    def test_is_not_running(self):
        s = _service(service_state="SERVICE_STOPPED")
        assert s.is_running is False

    def test_no_display_name(self):
        s = _service(display_name="", service_name="EvilSvc")
        assert s.has_no_display_name is True

    def test_display_name_same_as_service_name(self):
        s = _service(display_name="EvilSvc", service_name="EvilSvc")
        assert s.has_no_display_name is True
