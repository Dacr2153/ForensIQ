# FILE: src/forensiq/ml/explainer.py
"""SHAP-based explainability for ForensIQ XGBoost classifier.

Provides feature importance attribution for each process prediction using
SHAP (SHapley Additive exPlanations) values.

SHAP values explain WHY the model assigned a particular threat score,
showing which of the 15 features contributed most to the decision.
This is critical for forensic analysts who need to understand and validate
the model's predictions.

Reference: Lundberg, S.M. & Lee, S-I. (2017). "A Unified Approach to
           Interpreting Model Predictions." NIPS 2017.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import shap

from forensiq.models.features import ProcessFeatureVector
from forensiq.utils.exceptions import ClassificationError
from forensiq.utils.logger import get_logger

log = get_logger(__name__)


class SHAPExplainer:
    """Computes SHAP feature importances for ForensIQ XGBoost predictions.

    Uses TreeExplainer for XGBoost models (exact SHAP computation via tree
    traversal — much faster than model-agnostic KernelExplainer).

    Args:
        model: The loaded calibrated XGBoost model (same object as ForensiqClassifier._model).
    """

    def __init__(self, model: Any) -> None:
        self._model = model
        self._explainer: shap.TreeExplainer | None = None

    def _get_explainer(self) -> shap.TreeExplainer:
        """Get or create the cached SHAP TreeExplainer.

        TreeExplainer creation is relatively expensive — we cache it.

        Returns:
            Configured SHAP TreeExplainer instance.

        Raises:
            ClassificationError: If explainer creation fails.
        """
        if self._explainer is None:
            try:
                # For CalibratedClassifierCV wrapping XGBoost,
                # we extract the base estimator if needed
                base_model = self._model
                if hasattr(self._model, "calibrated_classifiers_"):
                    # CalibratedClassifierCV — use the first calibrator's estimator
                    base_model = self._model.calibrated_classifiers_[0].estimator
                elif hasattr(self._model, "estimator"):
                    base_model = self._model.estimator

                self._explainer = shap.TreeExplainer(base_model)
                log.debug("SHAP TreeExplainer initialized")
            except Exception as exc:
                raise ClassificationError(
                    message=f"Failed to initialize SHAP explainer: {exc}",
                ) from exc
        return self._explainer

    def explain_batch(
        self,
        vectors: list[ProcessFeatureVector],
    ) -> list[ProcessFeatureVector]:
        """Add SHAP values to a batch of ProcessFeatureVectors.

        SHAP values are stored in vector.shap_values as a dict:
            {"feature_name": shap_contribution_float, ...}

        Positive SHAP values push toward malicious classification.
        Negative SHAP values push toward benign classification.

        Args:
            vectors: Annotated feature vectors (after classifier.predict_batch()).

        Returns:
            Same vectors with shap_values populated.
            On failure, shap_values is set to empty dict (non-fatal).
        """
        if not vectors:
            return vectors

        try:
            explainer = self._get_explainer()

            # Build feature matrix
            feature_matrix = np.stack(
                [v.to_numpy_array() for v in vectors],
                axis=0,
            )

            # Compute SHAP values
            # For binary classification: shap_values returns list of 2 arrays
            # (one per class). We use index 1 (malicious class).
            raw_shap = explainer.shap_values(feature_matrix)

            # Handle different output formats from different SHAP + model combinations
            if isinstance(raw_shap, list) and len(raw_shap) == 2:
                # Binary classification — use malicious class SHAP values
                shap_matrix = raw_shap[1]
            elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 2:
                shap_matrix = raw_shap
            else:
                log.warning("Unexpected SHAP output format, skipping attribution")
                return vectors

            # Map SHAP values to feature names for each vector
            feature_names = ProcessFeatureVector.FEATURE_NAMES
            annotated: list[ProcessFeatureVector] = []

            for vector, shap_row in zip(vectors, shap_matrix, strict=True):
                shap_dict = {
                    name: round(float(val), 6) for name, val in zip(feature_names, shap_row, strict=False)
                }
                annotated.append(vector.model_copy(update={"shap_values": shap_dict}))

            log.debug("SHAP attribution complete", processes=len(annotated))
            return annotated

        except Exception as exc:
            log.warning(
                "SHAP explanation failed, returning vectors without attribution",
                error=str(exc),
            )
            # Non-fatal: return original vectors without SHAP values
            return vectors

    def get_top_features(
        self,
        vector: ProcessFeatureVector,
        top_n: int = 5,
    ) -> list[tuple[str, float]]:
        """Return the top N features driving a process's threat score.

        Args:
            vector: Classified feature vector with shap_values populated.
            top_n: Number of top features to return.

        Returns:
            List of (feature_name, shap_value) tuples, sorted by absolute
            contribution (highest first). Empty list if shap_values not set.
        """
        if not vector.shap_values:
            return []

        sorted_features = sorted(
            vector.shap_values.items(),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        return sorted_features[:top_n]
