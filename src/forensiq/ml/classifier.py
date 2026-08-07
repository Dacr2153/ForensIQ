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

import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from forensiq.config.settings import get_settings
from forensiq.ml.base import BaseClassifier, isolation_path
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

# Schema hash of the canonical FEATURE_NAMES order. Models whose metadata record
# a feature_schema_hash are rejected on load if this does not match, so a
# reordered/renamed feature vector can never silently desync from the model.
_SCHEMA_HASH: str = hashlib.sha256(
    "\n".join(ProcessFeatureVector.FEATURE_NAMES).encode("utf-8")
).hexdigest()


def _file_sha256(path: Path) -> str:
    """Stream the SHA-256 digest of a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_model_integrity(path: Path) -> dict[str, Any] | None:
    """Verify a joblib model file against its companion metadata JSON.

    ``joblib.load`` executes arbitrary code (pickle). A model file delivered
    with a case is therefore an RCE vector, so we refuse to load a model whose
    SHA-256 does not match the hash recorded by the trainer at ``model_sha256``.

    Args:
        path: Path to the ``*.joblib`` model file.

    Returns:
        The metadata dict when present and verified, else ``None``.

    Raises:
        ClassificationError: If the metadata records a hash and it does not
            match the on-disk model file.
    """
    meta_path = path.with_suffix(".json")
    if not meta_path.is_file():
        log.warning(
            "No metadata JSON — model integrity cannot be verified",
            model_path=str(path),
        )
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning(
            "Unreadable model metadata — integrity cannot be verified",
            model_path=str(path),
            error=str(exc),
        )
        return None

    expected = meta.get("model_sha256")
    if not expected:
        log.warning(
            "Model metadata has no model_sha256 — integrity cannot be verified",
            model_path=str(path),
        )
        return meta

    actual = _file_sha256(path)
    if actual.lower() != str(expected).lower():
        raise ClassificationError(
            message=(
                f"Model integrity check failed for {path}: SHA-256 mismatch — "
                "refusing to load a possibly tampered or corrupted model"
            ),
            context={"model_path": str(path), "expected_sha256": str(expected)[:16]},
        )
    log.debug("Model integrity verified", model_path=str(path))
    return meta


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
        # Fixed IsolationForest score normalization bounds, loaded from the
        # isolation model's metadata at load_model() time.
        self._iso_ref_min: float | None = None
        self._iso_ref_max: float | None = None
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

        # Verify the model against its metadata hash before unpickling.
        meta = _verify_model_integrity(path)
        if meta is not None and meta.get("n_features") != len(
            ProcessFeatureVector.FEATURE_NAMES
        ):
            raise ClassificationError(
                message=(
                    f"Model was trained on {meta.get('n_features')} features but "
                    f"inference expects {len(ProcessFeatureVector.FEATURE_NAMES)} "
                    f"({path_str}) — refusing to load a schema-mismatched model"
                ),
                context={"model_path": path_str},
            )
        # If the trainer recorded a schema hash, it must match ours — guards
        # against a model trained on reordered/renamed features of the same count.
        recorded_schema = meta.get("feature_schema_hash") if meta is not None else None
        if recorded_schema and recorded_schema != _SCHEMA_HASH:
            raise ClassificationError(
                message=(
                    f"Model feature schema hash mismatch ({path_str}) — "
                    "refusing to load a model trained on a different feature schema"
                ),
                context={"model_path": path_str},
            )

        try:
            self._model = joblib.load(path)
            log.info(
                "ML model loaded",
                model_path=path_str,
                model_type=type(self._model).__name__,
            )
        except ClassificationError:
            raise
        except Exception as exc:
            raise ClassificationError(
                message=f"Failed to load model from {path_str}: {exc}",
                context={"model_path": path_str},
            ) from exc

        # Try to load the IsolationForest model (same dir, *_isolation.joblib)
        iso_path = isolation_path(path)
        if iso_path.is_file():
            try:
                iso_meta = _verify_model_integrity(iso_path)
                self._isolation_model = joblib.load(iso_path)
                self._load_iso_reference_bounds(iso_meta)
                log.info("IsolationForest model loaded", path=str(iso_path))
            except ClassificationError as exc:
                log.warning(
                    "IsolationForest model rejected (non-fatal)",
                    error=str(exc),
                    path=str(iso_path),
                )
                self._isolation_model = None
            except Exception as exc:
                log.warning("IsolationForest model failed to load (non-fatal)", error=str(exc))
                self._isolation_model = None
        else:
            log.info("No IsolationForest model found — ensemble will use XGBoost only")

    def _load_iso_reference_bounds(self, meta: dict[str, Any] | None) -> None:
        """Load the fixed IsolationForest normalization bounds from metadata.

        Stored by the trainer as ``score_reference_min``/``score_reference_max``
        (computed over the benign training profile). When absent, bounds stay
        ``None`` and inference falls back to per-batch normalization.
        """
        self._iso_ref_min = None
        self._iso_ref_max = None
        if not isinstance(meta, dict):
            return
        lo, hi = meta.get("score_reference_min"), meta.get("score_reference_max")
        if isinstance(lo, (int, float)) and isinstance(hi, (int, float)):
            if hi > lo:
                self._iso_ref_min = float(lo)
                self._iso_ref_max = float(hi)

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

        return self._predict_internal(vectors)

    def predict_single(self, vector: ProcessFeatureVector) -> ProcessFeatureVector:
        """Classify a single process feature vector.

        Unlike :meth:`predict_batch`, this does not require a minimum number of
        processes — no placeholder padding is needed, so the returned vector is
        exactly the input vector annotated (never a padded dummy).

        Args:
            vector: Feature vector to classify.

        Returns:
            Annotated feature vector with threat_score and is_malicious.

        Raises:
            ModelNotLoadedError: If load_model() has not been called.
        """
        if not self.is_loaded:
            raise ModelNotLoadedError(model_path=str(self._model_path))
        return self._predict_internal([vector])[0]

    def _predict_internal(
        self,
        vectors: list[ProcessFeatureVector],
    ) -> list[ProcessFeatureVector]:
        """Core classification logic shared by predict_batch and predict_single.

        Assumes ``self._model`` is loaded. Does not enforce the minimum-process
        guard (the public predict_batch does).
        """
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
            if self._model is None:
                raise ClassificationError(
                    message="Model not loaded — call load_model() before classify().",
                )
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
                # Normalize with the FIXED reference bounds recorded at training
                # time (over the benign "normal profile"). Fixed bounds keep
                # scores comparable across runs; the old per-batch min/max made
                # the same process score differently depending on batch content.
                if self._iso_ref_min is not None and self._iso_ref_max is not None:
                    span = self._iso_ref_max - self._iso_ref_min
                    if span > 1e-12:
                        isolation_scores = np.clip(
                            1.0 - (raw_iso - self._iso_ref_min) / span, 0.0, 1.0
                        )
                # Fallback: normalize against this batch's own range.
                if not np.any(isolation_scores):
                    iso_min = raw_iso.min()
                    iso_max = raw_iso.max()
                    if iso_max > iso_min:
                        isolation_scores = 1.0 - (raw_iso - iso_min) / (iso_max - iso_min)
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
