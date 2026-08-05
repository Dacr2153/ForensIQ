# FILE: tests/unit/test_threat_intel_and_ml.py
"""Unit tests for ThreatIntelDetector, BaseClassifier, and SHAPExplainer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from forensiq.detectors.threat_intel import ThreatIntelDetector
from forensiq.ml.base import BaseClassifier
from forensiq.ml.explainer import SHAPExplainer
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


# ── ThreatIntelDetector ───────────────────────────────────────────────────────


class TestThreatIntelDetector:
    def test_disabled_by_default(self):
        det = ThreatIntelDetector()
        assert det._enabled is False

    def test_disabled_detect_returns_empty(self, sample_extraction):
        det = ThreatIntelDetector(enabled=False)
        results = det.detect(sample_extraction, [])
        assert results == []

    def test_enabled_flag(self):
        det = ThreatIntelDetector(enabled=True)
        assert det._enabled is True

    def test_name_and_description(self):
        det = ThreatIntelDetector()
        assert det.name == "threat_intel"
        assert "VirusTotal" in det.description

    def test_enabled_by_default_is_false(self):
        assert ThreatIntelDetector.enabled_by_default is False

    def test_instance_shadows_enabled_by_default_when_enabled(self):
        det = ThreatIntelDetector(enabled=True)
        assert det.enabled_by_default is True
        assert ThreatIntelDetector.enabled_by_default is False

    def test_detect_exception_returns_empty(self, sample_extraction):
        """If async detection raises unexpectedly, detect() returns []."""
        det = ThreatIntelDetector(enabled=True)
        # Patch asyncio.run to raise a generic exception
        with patch(
            "forensiq.detectors.threat_intel.asyncio.run",
            side_effect=Exception("network error"),
        ):
            results = det.detect(sample_extraction, [])
        assert results == []


# ── BaseClassifier (concrete stub) ────────────────────────────────────────────


class _StubClassifier(BaseClassifier):
    """Minimal concrete implementation of BaseClassifier for testing."""

    def __init__(self):
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load_model(self, model_path=None) -> None:
        self._loaded = True

    def predict_batch(self, vectors: list[ProcessFeatureVector]) -> list[ProcessFeatureVector]:
        annotated = []
        for v in vectors:
            annotated.append(v.model_copy(update={"threat_score": 0.1, "is_malicious": False}))
        return sorted(annotated, key=lambda x: x.threat_score, reverse=True)


class TestBaseClassifier:
    def test_is_loaded_false_before_load(self):
        clf = _StubClassifier()
        assert clf.is_loaded is False

    def test_load_model_sets_loaded(self):
        clf = _StubClassifier()
        clf.load_model()
        assert clf.is_loaded is True

    def test_predict_single_returns_annotated_vector(self):
        clf = _StubClassifier()
        v = _vec(pid=42)
        result = clf.predict_single(v)
        assert result.pid == 42
        assert result.threat_score == 0.1

    def test_predict_single_pads_to_min_batch(self):
        """predict_single should still work with a single vector (padding happens internally)."""
        clf = _StubClassifier()
        v = _vec(pid=99)
        result = clf.predict_single(v)
        assert isinstance(result, ProcessFeatureVector)

    def test_threshold_default(self):
        clf = _StubClassifier()
        assert clf.threshold == 0.65

    def test_threshold_can_be_set(self):
        clf = _StubClassifier()
        clf.threshold = 0.75
        assert clf.threshold == 0.75


# ── SHAPExplainer ────────────────────────────────────────────────────────────


class TestSHAPExplainer:
    def test_get_top_features_empty_shap(self):
        explainer = SHAPExplainer(MagicMock())
        v = _vec(shap_values={})
        assert explainer.get_top_features(v) == []

    def test_get_top_features_returns_sorted_by_abs(self):
        explainer = SHAPExplainer(MagicMock())
        shap_vals = {
            "malfind_hits": 1.5,
            "has_encoded_cmdline": -2.0,
            "external_connection_count": 0.3,
            "is_system_path": -0.1,
        }
        v = _vec(shap_values=shap_vals)
        result = explainer.get_top_features(v, top_n=2)

        assert len(result) == 2
        # Sorted by absolute value descending
        assert result[0][0] == "has_encoded_cmdline"  # abs(-2.0) = 2.0
        assert result[1][0] == "malfind_hits"  # abs(1.5)

    def test_get_top_features_top_n_capped(self):
        explainer = SHAPExplainer(MagicMock())
        shap_vals = {f"feat_{i}": float(i) for i in range(10)}
        v = _vec(shap_values=shap_vals)
        result = explainer.get_top_features(v, top_n=3)
        assert len(result) == 3

    def test_get_top_features_returns_tuples(self):
        explainer = SHAPExplainer(MagicMock())
        v = _vec(shap_values={"malfind_hits": 0.5})
        result = explainer.get_top_features(v)
        assert isinstance(result, list)
        assert isinstance(result[0], tuple)
        assert result[0][0] == "malfind_hits"
        assert isinstance(result[0][1], float)

    def test_explain_batch_empty_returns_empty(self):
        mock_model = MagicMock()
        explainer = SHAPExplainer(mock_model)
        result = explainer.explain_batch([])
        assert result == []

    def test_explain_batch_failure_returns_original_vectors(self):
        """On SHAP failure, explain_batch returns original vectors without raising."""
        mock_model = MagicMock()
        # Make _get_explainer raise
        explainer = SHAPExplainer(mock_model)
        explainer._explainer = MagicMock()
        explainer._explainer.shap_values.side_effect = RuntimeError("shap failed")

        vectors = [_vec(pid=1), _vec(pid=2)]
        result = explainer.explain_batch(vectors)

        assert len(result) == 2
        assert result[0].shap_values == {}

    def test_explain_batch_2d_numpy_format(self):
        """Test that 2D numpy shap_values output is handled correctly."""
        mock_model = MagicMock()
        explainer = SHAPExplainer(mock_model)

        n_features = len(ProcessFeatureVector.FEATURE_NAMES)
        shap_matrix = np.zeros((2, n_features))
        shap_matrix[0, 0] = 0.5  # first vector, first feature

        mock_tree_explainer = MagicMock()
        mock_tree_explainer.shap_values.return_value = shap_matrix
        explainer._explainer = mock_tree_explainer

        vectors = [_vec(pid=1), _vec(pid=2)]
        result = explainer.explain_batch(vectors)

        assert len(result) == 2
        # First feature should have shap value 0.5 for first vector
        first_feature = ProcessFeatureVector.FEATURE_NAMES[0]
        assert result[0].shap_values[first_feature] == pytest.approx(0.5)


class TestSHAPExplainerAdditional:
    def test_explain_batch_list_format_two_arrays(self):
        """Test the binary classification list-of-2-arrays SHAP format (line 113)."""
        mock_model = MagicMock()
        explainer = SHAPExplainer(mock_model)

        n_features = len(ProcessFeatureVector.FEATURE_NAMES)
        # Binary classification format: list of 2 arrays
        shap_class0 = np.zeros((2, n_features))
        shap_class1 = np.zeros((2, n_features))
        shap_class1[0, 0] = 0.9

        mock_tree_explainer = MagicMock()
        mock_tree_explainer.shap_values.return_value = [shap_class0, shap_class1]
        explainer._explainer = mock_tree_explainer

        vectors = [_vec(pid=1), _vec(pid=2)]
        result = explainer.explain_batch(vectors)

        first_feature = ProcessFeatureVector.FEATURE_NAMES[0]
        assert result[0].shap_values[first_feature] == pytest.approx(0.9)

    def test_explain_batch_unexpected_shap_format_returns_original(self):
        """When SHAP returns unexpected format, vectors returned unchanged (lines 117-118)."""
        mock_model = MagicMock()
        explainer = SHAPExplainer(mock_model)

        mock_tree_explainer = MagicMock()
        # Return something unexpected (list of 1 array, or 3D array)
        mock_tree_explainer.shap_values.return_value = [np.zeros((2, 20))]  # only 1 class array
        explainer._explainer = mock_tree_explainer

        vectors = [_vec(pid=1), _vec(pid=2)]
        result = explainer.explain_batch(vectors)
        assert result == vectors

    def test_get_explainer_uses_calibrated_classifiers(self):
        """_get_explainer uses calibrated_classifiers_[0].estimator when present (lines 56-62)."""

        mock_estimator = MagicMock()
        mock_calibrator = MagicMock()
        mock_calibrator.estimator = mock_estimator

        mock_model = MagicMock()
        mock_model.calibrated_classifiers_ = [mock_calibrator]

        # Remove the estimator attribute so hasattr check on model falls through
        del mock_model.estimator

        explainer = SHAPExplainer(mock_model)

        with patch("forensiq.ml.explainer.shap") as mock_shap:
            mock_shap.TreeExplainer.return_value = MagicMock()
            explainer._get_explainer()
            mock_shap.TreeExplainer.assert_called_once_with(mock_estimator)

    def test_get_explainer_uses_estimator_attribute(self):
        """_get_explainer uses model.estimator when calibrated_classifiers_ is absent."""
        mock_base = MagicMock()
        mock_model = MagicMock()

        # Don't have calibrated_classifiers_
        del mock_model.calibrated_classifiers_
        mock_model.estimator = mock_base

        explainer = SHAPExplainer(mock_model)

        with patch("forensiq.ml.explainer.shap") as mock_shap:
            mock_shap.TreeExplainer.return_value = MagicMock()
            explainer._get_explainer()
            mock_shap.TreeExplainer.assert_called_once_with(mock_base)


class TestThreatIntelDetectorAsync:
    """Tests for _detect_async coverage."""

    def _make_extraction_no_suspicious_dlls(self):
        """ExtractionResult with DLLs from safe paths (not suspicious)."""
        from forensiq.models.artifact import DLLEntry
        extraction = MagicMock()
        extraction.process_tree = None
        safe_dll = DLLEntry(pid=4, full_dll_name=r"\Windows\System32\ntdll.dll")
        extraction.dlls = {4: [safe_dll]}
        return extraction

    def _make_suspicious_dll(self, sha256=None):
        """A suspicious DLL mock carrying a genuine content hash."""
        dll_mock = MagicMock()
        dll_mock.is_suspicious = True
        dll_mock.full_dll_name = r"\Users\victim\AppData\Local\Temp\evil.dll"
        dll_mock.content_sha256 = sha256 or ("a" * 64)
        return dll_mock

    def test_detect_inside_running_loop(self, sample_extraction):
        """detect() bridges to a worker thread when called inside an event loop."""
        det = ThreatIntelDetector(enabled=True)

        async def _probe():
            return det.detect(sample_extraction, [])

        import asyncio

        results = asyncio.run(_probe())
        assert results == []

    @pytest.mark.asyncio
    async def test_detect_async_no_suspicious_dlls_returns_empty(self):
        """_detect_async returns [] when no suspicious DLLs are present."""
        det = ThreatIntelDetector(enabled=True)
        extraction = self._make_extraction_no_suspicious_dlls()
        results = await det._detect_async(extraction, [])
        assert results == []

    @pytest.mark.asyncio
    async def test_detect_async_skips_dll_without_content_hash(self):
        """Suspicious DLLs without a content hash are skipped (no path-hash fabrication)."""
        det = ThreatIntelDetector(enabled=True)
        extraction = MagicMock()
        extraction.process_tree = None
        dll_mock = MagicMock()
        dll_mock.is_suspicious = True
        dll_mock.full_dll_name = r"\Users\victim\AppData\Local\Temp\evil.dll"
        dll_mock.content_sha256 = ""
        extraction.dlls = {1234: [dll_mock]}

        results = await det._detect_async(extraction, [])
        assert results == []

    @pytest.mark.asyncio
    async def test_detect_async_cached_malicious_dll(self):
        """_detect_async uses cached malicious verdict from DB."""
        det = ThreatIntelDetector(enabled=True)
        extraction = MagicMock()
        extraction.process_tree = None
        extraction.dlls = {1234: [self._make_suspicious_dll()]}

        cached_result = {"verdict": "malicious", "malware_name": "Emotet", "source": "cache"}

        # ForensiqDatabase is imported locally inside _detect_async, so patch at the source module
        from unittest.mock import AsyncMock
        mock_db_instance = MagicMock()
        mock_db_instance.__aenter__ = AsyncMock(return_value=mock_db_instance)
        mock_db_instance.__aexit__ = AsyncMock(return_value=None)
        mock_db_instance.get_threat_intel = AsyncMock(return_value=cached_result)

        with patch("forensiq.db.manager.ForensiqDatabase", return_value=mock_db_instance), \
             patch("forensiq.integrations.malwarebazaar.MalwareBazaarClient"):
            results = await det._detect_async(extraction, [])
        assert len(results) >= 1
        assert results[0].pid == 1234

    @pytest.mark.asyncio
    async def test_detect_async_virustotal_first(self):
        """When VT resolves a hash as malicious, VT is the source (no MB query)."""
        det = ThreatIntelDetector(enabled=True, vt_api_key="test_key", vt_delay_ms=0)
        extraction = MagicMock()
        extraction.process_tree = None
        extraction.dlls = {1234: [self._make_suspicious_dll()]}

        from unittest.mock import AsyncMock

        from forensiq.integrations.virustotal import VTResult

        vt_result = VTResult(
            hash_value="a" * 64,
            hash_type="sha256",
            source="virustotal",
            is_malicious=True,
            verdict="malicious",
            malware_name="Trojan.Emotet",
            positives=25,
            total=70,
        )

        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)
        mock_db.get_threat_intel = AsyncMock(return_value=None)
        mock_db.save_threat_intel = AsyncMock()

        mock_vt_client = MagicMock()
        mock_vt_client.is_configured.return_value = True
        mock_vt_client.__aenter__ = AsyncMock(return_value=mock_vt_client)
        mock_vt_client.__aexit__ = AsyncMock(return_value=None)
        mock_vt_client.lookup_batch = AsyncMock(return_value={"a" * 64: vt_result})

        mock_mb = MagicMock()
        mock_mb.__aenter__ = AsyncMock(return_value=mock_mb)
        mock_mb.__aexit__ = AsyncMock(return_value=None)
        mock_mb.lookup_batch = AsyncMock(return_value={})

        with patch("forensiq.db.manager.ForensiqDatabase", return_value=mock_db), \
             patch(
                 "forensiq.integrations.virustotal.VirusTotalClient",
                 return_value=mock_vt_client,
             ), \
             patch("forensiq.integrations.malwarebazaar.MalwareBazaarClient", return_value=mock_mb):
            results = await det._detect_async(extraction, [])

        assert len(results) == 1
        assert results[0].evidence["source"] == "virustotal"
        assert results[0].evidence["sha256"] == "a" * 64
        mock_mb.lookup_batch.assert_not_called()
        mock_db.save_threat_intel.assert_awaited()

    @pytest.mark.asyncio
    async def test_detect_async_malwarebazaar_fallback(self):
        """When VT is unconfigured, MalwareBazaar is used as the source."""
        det = ThreatIntelDetector(enabled=True, vt_delay_ms=0, mb_delay_ms=0)
        extraction = MagicMock()
        extraction.process_tree = None
        extraction.dlls = {1234: [self._make_suspicious_dll()]}

        from unittest.mock import AsyncMock

        from forensiq.integrations.malwarebazaar import ThreatIntelResult

        mb_result = ThreatIntelResult(
            hash_value="a" * 64,
            hash_type="sha256",
            source="malwarebazaar",
            is_malicious=True,
            verdict="malicious",
            malware_name="RedLine",
        )

        mock_db = MagicMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)
        mock_db.get_threat_intel = AsyncMock(return_value=None)
        mock_db.save_threat_intel = AsyncMock()

        mock_vt_client = MagicMock()
        mock_vt_client.is_configured.return_value = False
        mock_vt_client.__aenter__ = AsyncMock(return_value=mock_vt_client)
        mock_vt_client.__aexit__ = AsyncMock(return_value=None)

        mock_mb = MagicMock()
        mock_mb.__aenter__ = AsyncMock(return_value=mock_mb)
        mock_mb.__aexit__ = AsyncMock(return_value=None)
        mock_mb.lookup_batch = AsyncMock(return_value={"a" * 64: mb_result})

        with patch("forensiq.db.manager.ForensiqDatabase", return_value=mock_db), \
             patch(
                 "forensiq.integrations.virustotal.VirusTotalClient",
                 return_value=mock_vt_client,
             ), \
             patch("forensiq.integrations.malwarebazaar.MalwareBazaarClient", return_value=mock_mb):
            results = await det._detect_async(extraction, [])

        assert len(results) == 1
        assert results[0].evidence["source"] == "malwarebazaar"

    @pytest.mark.asyncio
    async def test_detect_async_no_suspicious_dlls_with_process_tree(self):
        """_detect_async handles process_tree with flat_map when no suspicious DLLs."""
        det = ThreatIntelDetector(enabled=True)
        extraction = MagicMock()
        # Provide process_tree with flat_map
        proc = MagicMock()
        proc.name = "svchost.exe"
        extraction.process_tree = MagicMock()
        extraction.process_tree.flat_map = {1234: proc}

        from forensiq.models.artifact import DLLEntry
        safe_dll = DLLEntry(pid=1234, full_dll_name=r"\Windows\System32\ntdll.dll")
        extraction.dlls = {1234: [safe_dll]}

        results = await det._detect_async(extraction, [])
        assert results == []
