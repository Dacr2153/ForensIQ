# FILE: tests/unit/test_ml_training_paths.py
"""Unit tests for the IsolationForest companion-path derivation.

Covers the regression where a custom classifier ``--output`` filename caused
the IsolationForest model to overwrite the XGBoost classifier (the old
``stem.replace("forensiq_model", "forensiq_isolation")`` only matched the
default ``forensiq_model.joblib`` name).
"""

from __future__ import annotations

from pathlib import Path

from forensiq.ml.base import isolation_path


class TestIsolationOutputPath:
    def test_default_model_name(self) -> None:
        out = isolation_path(Path("ml/data/forensiq_model.joblib"))
        assert out.name == "forensiq_isolation.joblib"

    def test_custom_model_name_appends_isolation(self) -> None:
        out = isolation_path(Path("/tmp/smoke_model.joblib"))
        assert out.name == "smoke_isolation.joblib"

    def test_custom_name_without_model_suffix(self) -> None:
        out = isolation_path(Path("/tmp/custom.joblib"))
        assert out.name == "custom_isolation.joblib"

    def test_never_collides_with_classifier_path(self) -> None:
        classifier = Path("/tmp/whatever_model.joblib")
        iso = isolation_path(classifier)
        assert iso != classifier
        assert iso.parent == classifier.parent

    def test_already_isolation_name_is_kept(self) -> None:
        out = isolation_path(Path("/tmp/foo_isolation.joblib"))
        assert out.name == "foo_isolation.joblib"

    def test_plain_name(self) -> None:
        p = isolation_path(Path("/x/custom.joblib"))
        assert p.name == "custom_isolation.joblib"
