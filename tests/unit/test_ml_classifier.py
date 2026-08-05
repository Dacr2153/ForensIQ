# FILE: tests/unit/test_ml_classifier.py
"""Unit tests for ForensiqClassifier (model loading and basic properties)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from forensiq.ml.classifier import ForensiqClassifier
from forensiq.utils.exceptions import ClassificationError, ModelNotLoadedError


class TestForensiqClassifierProperties:
    def setup_method(self):
        self.clf = ForensiqClassifier()

    def test_is_loaded_false_on_init(self):
        assert self.clf.is_loaded is False

    def test_model_is_none_on_init(self):
        assert self.clf.model is None

    def test_threshold_is_float(self):
        assert isinstance(self.clf.threshold, float)
        assert 0.0 < self.clf.threshold < 1.0


class TestLoadModel:
    def test_load_model_raises_when_file_missing(self, tmp_path: Path):
        clf = ForensiqClassifier()
        with pytest.raises(ModelNotLoadedError):
            clf.load_model(model_path=tmp_path / "no_such_model.joblib")

    def test_load_model_raises_on_corrupt_file(self, tmp_path: Path):
        bad_file = tmp_path / "forensiq_model.joblib"
        bad_file.write_bytes(b"this is not a valid joblib file")
        clf = ForensiqClassifier()
        with pytest.raises(ClassificationError):
            clf.load_model(model_path=bad_file)

    def test_load_model_success(self, tmp_path: Path):
        import joblib

        # Use a simple serializable object (dict) to simulate model artifact
        mock_model = {"type": "fake_model", "version": 1}
        model_path = tmp_path / "forensiq_model_v1.joblib"
        joblib.dump(mock_model, model_path)

        clf = ForensiqClassifier()
        clf.load_model(model_path=model_path)
        assert clf.is_loaded is True
        assert clf.model is not None

    def test_load_model_uses_default_path_when_none(self):
        clf = ForensiqClassifier()
        # When no model file at default location, should raise ModelNotLoadedError
        with patch.object(clf, "_model_path", Path("/nonexistent/model.joblib")):
            with pytest.raises(ModelNotLoadedError):
                clf.load_model()
