# FILE: src/forensiq/ml/base.py
"""Abstract base interface for ForensIQ classifiers.

Any classifier that scores memory processes must implement
:class:`BaseClassifier`.  This decouples the pipeline from the concrete
XGBoost implementation so that alternative backends (e.g. a LightGBM model,
a rule-based scorer, or a stub for testing) can be dropped in without
modifying ``analysis_pipeline.py``.

Usage:
    from forensiq.ml.base import BaseClassifier

    class MyClassifier(BaseClassifier):
        def load_model(self, model_path=None) -> None: ...
        def predict_batch(self, vectors) -> list[ProcessFeatureVector]: ...

    pipeline = AnalysisPipeline(classifier=MyClassifier())
"""

from __future__ import annotations

import abc
from pathlib import Path

from forensiq.models.features import ProcessFeatureVector


def isolation_path(model_path: Path) -> Path:
    """Derive the companion IsolationForest path for a classifier model path.

    Ensures the isolation model never collides with the classifier model even
    when the classifier uses a custom filename.

    Args:
        model_path: Path to the calibrated classifier model.

    Returns:
        Companion ``<stem>_isolation.joblib`` path for the IsolationForest.
    """
    stem = model_path.stem
    if stem.endswith("_model"):
        iso_stem = stem[: -len("_model")] + "_isolation"
    elif stem.endswith("_isolation"):
        iso_stem = stem
    else:
        iso_stem = f"{stem}_isolation"
    return model_path.with_name(f"{iso_stem}.joblib")


class BaseClassifier(abc.ABC):
    """Abstract interface for per-process malware classifiers.

    All classifiers receive a list of :class:`~forensiq.models.features.ProcessFeatureVector`
    objects and must annotate each one with:

    * ``threat_score``  — calibrated probability ∈ [0.0, 1.0]
    * ``is_malicious``  — ``True`` if ``threat_score >= threshold``

    Sub-classes may also populate ``isolation_score``, ``ensemble_score``, and
    ``shap_values`` when applicable.

    The :attr:`threshold` attribute controls the malicious/benign cut-off and
    must be settable so the pipeline can propagate user-supplied overrides.
    """

    #: Probability threshold above which a process is classified as malicious.
    threshold: float = 0.65

    @property
    @abc.abstractmethod
    def is_loaded(self) -> bool:
        """Return ``True`` if the underlying model is ready to predict."""

    @abc.abstractmethod
    def load_model(self, model_path: Path | None = None) -> None:
        """Load (or initialise) the model from *model_path*.

        Args:
            model_path: Path to the serialised model file.  If ``None``, the
                implementation should fall back to a default configured path.

        Raises:
            :exc:`~forensiq.utils.exceptions.ModelNotLoadedError`: If the model
                file is missing.
            :exc:`~forensiq.utils.exceptions.ClassificationError`: If the file
                cannot be deserialised.
        """

    @abc.abstractmethod
    def predict_batch(
        self,
        vectors: list[ProcessFeatureVector],
    ) -> list[ProcessFeatureVector]:
        """Classify *vectors* and return annotated copies sorted by threat score.

        Args:
            vectors: Feature vectors to classify (must have ≥ 3 entries).

        Returns:
            The same vectors annotated with ``threat_score`` and
            ``is_malicious``, sorted descending by threat score.

        Raises:
            :exc:`~forensiq.utils.exceptions.ModelNotLoadedError`: If
                :meth:`load_model` has not been called.
            :exc:`~forensiq.utils.exceptions.InsufficientDataError`: If fewer
                than the minimum required processes are supplied.
            :exc:`~forensiq.utils.exceptions.ClassificationError`: If
                prediction fails.
        """

    def predict_single(self, vector: ProcessFeatureVector) -> ProcessFeatureVector:
        """Classify a single process vector.

        Default implementation pads the input to the minimum batch size and
        delegates to :meth:`predict_batch`.  Sub-classes may override for
        efficiency.

        Args:
            vector: Feature vector to classify.

        Returns:
            Annotated copy with ``threat_score`` and ``is_malicious`` set.
        """
        min_processes = 3
        dummy = ProcessFeatureVector(pid=0, name="<placeholder>", ppid=0)
        padding = [dummy] * (min_processes - 1)
        results = self.predict_batch([vector, *padding])
        for result in results:
            if result.pid == vector.pid:
                return result
        return results[0]
