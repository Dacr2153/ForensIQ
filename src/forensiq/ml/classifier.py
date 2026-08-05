# FILE: src/forensiq/ml/classifier.py
"""ForensIQ XGBoost classifier for per-process malware detection.

Model: XGBoost binary classifier calibrated with isotonic regression.
       Trained on CIC-MalMem2022 dataset features extracted from Volatility 3.

Input:  ProcessFeatureVector.to_numpy_array() — float32 array, shape (20,)
Output: Calibrated probability [0.0, 1.0] of maliciousness

Usage:
    from forensiq.ml.classifier import ForensiqClassifier
    from forensiq.config.settings import get_settings

    clf = ForensiqClassifier()
    clf.load_model()  # Load from settings.MODEL_PATH
    vectors = [...]   # list[ProcessFeatureVector]
    results = clf.predict_batch(vectors)  # annotates threat_score + is_malicious
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np

from forensiq.config.settings import get_settings
from forensiq.ml.base import BaseClassifier
from forensiq.models.features import ProcessFeatureVector
from forensiq.utils.exceptions import (
    ClassificationError,
    InsufficientDataError,
    ModelNotLoadedError,
)
from forensiq.utils.logger import get_logger

log = get_logger(__name__)

# Minimum number of processes needed for a meaningful classification run.
# Below this, the classifier may produce unreliable results.
_MIN_PROCESSES_FOR_CLASSIFICATION = 3


class ForensiqClassifier(BaseClassifier):
    """XGBoost-based malware classifier for Windows process feature vectors.

    The model is loaded lazily from disk via load_model().
    predict_batch() annotates ProcessFeatureVectors in-place with:
        - threat_score: calibrated probability of maliciousness
        - is_malicious: True if threat_score >= threshold

    Attributes:
        model: The loaded calibrated XGBoost classifier (joblib-serialized).
        threshold: Probability threshold for malicious classification.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._model: Any | None = None
        self._isolation_model: Any | None = None  # IsolationForest for zero-day detection
        self._model_path: Path = self._settings.get_model_path()
        self.threshold: float = self._settings.THREAT_THRESHOLD
        # Ensemble weights: XGBoost supervised + IsolationForest unsupervised
        self._xgb_weight: float = 0.6
        self._isolation_weight: float = 0.4

    @property
    def is_loaded(self) -> bool:
        """Return True if the model has been loaded successfully."""
        return self._model is not None

    @property
    def model(self) -> Any:
        """Return the underlying model object."""
        return self._model

    def load_model(self, model_path: Path | None = None) -> None:
        """Load the trained XGBoost model from disk.

        Args:
            model_path: Override path to the joblib model file.
                        Defaults to settings.MODEL_PATH.

        Raises:
            ModelNotLoadedError: If the model file does not exist.
            ClassificationError: If the model file cannot be loaded (corrupted).
        """
        path = (model_path or self._model_path).resolve()
        path_str = str(path)

        if not path.is_file():
            raise ModelNotLoadedError(model_path=path_str)

        try:
            self._model = joblib.load(path)
            log.info(
                "ML model loaded",
                model_path=path_str,
                model_type=type(self._model).__name__,
            )
        except Exception as exc:
            raise ClassificationError(
                message=f"Failed to load model from {path_str}: {exc}",
                context={"model_path": path_str},
            ) from exc

        # Try to load the IsolationForest model (same dir, *_isolation.joblib)
        isolation_path = path.with_name(
            path.stem.replace("forensiq_model", "forensiq_isolation") + ".joblib"
        )
        if not isolation_path.exists():
            # Fallback: look for any *_isolation*.joblib in the same directory
            candidates = sorted(path.parent.glob("*isolation*.joblib"), reverse=True)
            isolation_path = candidates[0] if candidates else isolation_path

        if isolation_path.is_file():
            try:
                self._isolation_model = joblib.load(isolation_path)
                log.info("IsolationForest model loaded", path=str(isolation_path))
            except Exception as exc:
                log.warning("IsolationForest model failed to load (non-fatal)", error=str(exc))
                self._isolation_model = None
        else:
            log.info("No IsolationForest model found — ensemble will use XGBoost only")

    def predict_batch(
        self,
        vectors: list[ProcessFeatureVector],
    ) -> list[ProcessFeatureVector]:
        """Classify all processes and annotate with threat scores.

        Each vector is updated with:
            - threat_score: calibrated probability ∈ [0.0, 1.0]
            - is_malicious: True if threat_score >= self.threshold

        Args:
            vectors: List of feature vectors to classify.

        Returns:
            Same list of vectors, annotated with scores and maliciousness flag.
            Returned in the same order, sorted by threat_score descending.

        Raises:
            ModelNotLoadedError: If load_model() has not been called.
            InsufficientDataError: If fewer than 3 processes are provided.
            ClassificationError: If numpy array construction or prediction fails.
        """
        if not self.is_loaded:
            raise ModelNotLoadedError(model_path=str(self._model_path))

        if len(vectors) < _MIN_PROCESSES_FOR_CLASSIFICATION:
            raise InsufficientDataError(
                count=len(vectors),
                minimum=_MIN_PROCESSES_FOR_CLASSIFICATION,
            )

        log.info("Classifying processes", count=len(vectors), threshold=self.threshold)

        # Build feature matrix: shape (N, 20)
        try:
            feature_matrix = np.stack(
                [v.to_numpy_array() for v in vectors],
                axis=0,
            )
        except Exception as exc:
            raise ClassificationError(
                message=f"Failed to build feature matrix: {exc}",
            ) from exc

        # Get calibrated probabilities for the malicious class (XGBoost)
        try:
            proba = self._model.predict_proba(feature_matrix)
        except Exception as exc:
            raise ClassificationError(
                message=f"Model prediction failed: {exc}",
            ) from exc

        # proba shape: (N, 2) where column 1 = probability of malicious class
        if proba.ndim == 2 and proba.shape[1] == 2:
            xgb_scores = proba[:, 1]
        elif proba.ndim == 1:
            xgb_scores = proba
        else:
            raise ClassificationError(
                message=f"Unexpected predict_proba output shape: {proba.shape}",
            )

        # IsolationForest anomaly scores (unsupervised, optional)
        # IsolationForest.score_samples() returns negative anomaly scores:
        # more negative → more anomalous. We normalize to [0, 1].
        isolation_scores = np.zeros(len(vectors), dtype=np.float64)
        if self._isolation_model is not None:
            try:
                raw_iso = self._isolation_model.score_samples(feature_matrix)
                # Normalize: most negative maps to 1.0 (anomalous), 0+ maps to 0.0
                # IsolationForest scores are typically in [-0.5, 0.5] range
                iso_min = raw_iso.min()
                iso_max = raw_iso.max()
                if iso_max > iso_min:
                    isolation_scores = 1.0 - (raw_iso - iso_min) / (iso_max - iso_min)
                else:
                    isolation_scores = np.zeros(len(vectors))
            except Exception as exc:
                log.warning("IsolationForest scoring failed (using zeros)", error=str(exc))

        # Ensemble: weighted combination
        use_ensemble = self._isolation_model is not None and np.any(isolation_scores > 0)
        if use_ensemble:
            ensemble_raw = self._xgb_weight * xgb_scores + self._isolation_weight * isolation_scores
        else:
            ensemble_raw = xgb_scores

        # Annotate vectors with scores
        annotated: list[ProcessFeatureVector] = []
        for i, vector in enumerate(vectors):
            xgb_score = float(np.clip(xgb_scores[i], 0.0, 1.0))
            iso_score = float(np.clip(isolation_scores[i], 0.0, 1.0))
            ens_score = float(np.clip(ensemble_raw[i], 0.0, 1.0))
            annotated.append(
                vector.model_copy(
                    update={
                        "threat_score": round(xgb_score, 4),
                        "isolation_score": round(iso_score, 4),
                        "ensemble_score": round(ens_score, 4),
                        "is_malicious": ens_score >= self.threshold,
                    }
                )
            )

        # Sort by ensemble_score descending for report ranking
        annotated.sort(key=lambda v: v.ensemble_score, reverse=True)

        malicious_count = sum(1 for v in annotated if v.is_malicious)
        log.info(
            "Classification complete",
            total=len(annotated),
            malicious=malicious_count,
            threshold=self.threshold,
            ensemble=use_ensemble,
        )
        return annotated

    def predict_single(self, vector: ProcessFeatureVector) -> ProcessFeatureVector:
        """Classify a single process feature vector.

        Convenience wrapper around predict_batch for single-process use.
        NOTE: Less efficient than batch prediction for multiple processes.

        Args:
            vector: Feature vector to classify.

        Returns:
            Annotated feature vector with threat_score and is_malicious.
        """
        dummy = ProcessFeatureVector(pid=0, name="<placeholder>", ppid=0)
        padding = [dummy] * (_MIN_PROCESSES_FOR_CLASSIFICATION - 1)
        results = self.predict_batch([vector, *padding])
        for result in results:
            if result.pid == vector.pid:
                return result
        return results[0]
