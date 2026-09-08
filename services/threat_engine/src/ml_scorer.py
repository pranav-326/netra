"""Learned scoring layer (Layer 4).

A logistic-regression model trained offline on labelled email corpora, shipped as a
plain JSON file of coefficients and evaluated here in pure Python. There is no
scikit-learn, numpy, or pickle in the production image:

* The artifact is **readable**. An analyst — or a sceptical reviewer — can open the
  model file and see every weight. A pickle would be opaque and a code-execution risk.
* Inference is **deterministic**. Same email, same features, same score, forever. The
  model is a fixed table of numbers, not a service call.
* The explanation is **exact**. For a linear model the per-feature contribution is
  `coefficient x value`, and those terms sum to the logit by definition — the same
  additive property the rule engine's waterfall already relies on. No SHAP or LIME
  approximation is needed, because there is nothing opaque to approximate.

The model is a *second signal*, never an override, but the cap alone does not deliver
that symmetrically. `+max_points` cannot lift a sub-threshold score past MALICIOUS,
yet `-max_points` would drag a score of 61 down to 36 and quietly downgrade the
verdict. The guarantee is completed in `scorer.apply_ml_contribution`, which floors the
model at zero whenever a hard-evidence rule has fired — see `HARD_EVIDENCE_RULES`.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from math import exp
from typing import Any, Dict, List, Optional

from .features import FEATURE_LABELS, extract_features, to_vector

logger = logging.getLogger("netra.threat_engine.ml")

# Hard bound on how far a single standardised feature may travel from the training
# mean. Production email will not match the training distribution exactly, and without
# this a feature that barely varied during training can dominate a live prediction.
# Defence in depth alongside the trainer's near-constant feature guard.
MAX_ABS_Z = 5.0

DEFAULT_MODEL_PATH = os.getenv(
    "NETRA_ML_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "models", "phish_lr.json"),
)


@dataclass
class FeatureContribution:
    """One feature's signed contribution to the model's logit."""

    name: str
    label: str
    value: float
    coefficient: float
    contribution: float


@dataclass
class MLPrediction:
    """The model's verdict for one email, with its full decomposition."""

    probability: float
    logit: float
    points: int
    contributions: List[FeatureContribution] = field(default_factory=list)
    model_version: str = "unknown"
    threshold: float = 0.5

    @property
    def is_phishing(self) -> bool:
        return self.probability >= self.threshold

    def top_drivers(self, n: int = 3, positive_only: bool = True) -> List[FeatureContribution]:
        """The features that moved this prediction the most."""
        items = [c for c in self.contributions if c.contribution > 0] if positive_only else self.contributions
        return sorted(items, key=lambda c: abs(c.contribution), reverse=True)[:n]


def _sigmoid(z: float) -> float:
    """Numerically stable logistic function."""
    if z >= 0:
        return 1.0 / (1.0 + exp(-z))
    e = exp(z)
    return e / (1.0 + e)


class MLScorer:
    """Loads the trained artifact and scores AnalyzedEmail objects.

    A missing or malformed model is not fatal: `available` goes False, the pipeline
    keeps running on rules alone, and the report says the model did not contribute.
    Shipping a broken artifact must never take email analysis offline.
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.available = False
        self.unavailable_reason: Optional[str] = None

        self.feature_order: List[str] = []
        self.coefficients: List[float] = []
        self.intercept: float = 0.0
        self.means: List[float] = []
        self.scales: List[float] = []
        self.threshold: float = 0.5
        self.max_points: int = 25
        self.version: str = "unknown"
        self.metrics: Dict[str, Any] = {}

        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.model_path):
            self.unavailable_reason = f"no model artifact at {self.model_path}"
            logger.info(
                "No trained model found; Layer 4 scoring runs on rules only. "
                f"({self.unavailable_reason})"
            )
            return

        try:
            with open(self.model_path, "r", encoding="utf-8") as handle:
                artifact = json.load(handle)

            self.feature_order = list(artifact["feature_order"])
            self.coefficients = [float(c) for c in artifact["coefficients"]]
            self.intercept = float(artifact["intercept"])
            # Standardisation parameters captured at training time; applying them here
            # is what keeps train and serve numerically identical.
            self.means = [float(m) for m in artifact.get("means", [0.0] * len(self.feature_order))]
            self.scales = [float(s) or 1.0 for s in artifact.get("scales", [1.0] * len(self.feature_order))]
            self.threshold = float(artifact.get("threshold", 0.5))
            self.max_points = int(artifact.get("max_points", 25))
            self.version = str(artifact.get("version", "unknown"))
            self.metrics = artifact.get("metrics", {})

            if not (len(self.coefficients) == len(self.feature_order) == len(self.means) == len(self.scales)):
                raise ValueError("coefficient/feature/scaler lengths disagree")

            self.available = True
            logger.info(
                f"Loaded scoring model '{self.version}' with {len(self.feature_order)} features "
                f"(threshold={self.threshold:.3f}, cap=±{self.max_points} pts)"
            )
        except Exception as exc:
            self.unavailable_reason = f"failed to load model: {exc}"
            logger.error(f"Model artifact at {self.model_path} could not be loaded: {exc}")
            self.available = False

    def predict(self, analyzed) -> Optional[MLPrediction]:
        """Score an AnalyzedEmail. Returns None when no model is loaded."""
        if not self.available:
            return None

        try:
            features = extract_features(analyzed)
            raw = to_vector(features, self.feature_order)

            contributions: List[FeatureContribution] = []
            logit = self.intercept

            for idx, name in enumerate(self.feature_order):
                # Standardise with the training statistics, clip, then weight.
                z = (raw[idx] - self.means[idx]) / self.scales[idx]
                scaled = max(-MAX_ABS_Z, min(MAX_ABS_Z, z))
                term = self.coefficients[idx] * scaled
                logit += term
                contributions.append(
                    FeatureContribution(
                        name=name,
                        label=FEATURE_LABELS.get(name, name),
                        value=raw[idx],
                        coefficient=self.coefficients[idx],
                        contribution=term,
                    )
                )

            probability = _sigmoid(logit)

            return MLPrediction(
                probability=probability,
                logit=logit,
                points=self._to_points(probability),
                contributions=contributions,
                model_version=self.version,
                threshold=self.threshold,
            )
        except Exception as exc:
            # A model failure must degrade to rules-only, never drop the email.
            logger.error(f"Model inference failed; continuing on rules alone: {exc}")
            return None

    def _to_points(self, probability: float) -> int:
        """Map a probability onto a bounded, signed point contribution.

        Centred on the decision threshold so the model only pushes the score when it
        actually disagrees with a coin flip, and clamped to `max_points` so it can
        never overturn hard evidence from the rule engine.
        """
        if probability >= self.threshold:
            # Scale the interval [threshold, 1] onto [0, max_points].
            span = max(1.0 - self.threshold, 1e-6)
            fraction = (probability - self.threshold) / span
        else:
            span = max(self.threshold, 1e-6)
            fraction = (probability - self.threshold) / span

        return int(round(max(-1.0, min(1.0, fraction)) * self.max_points))


# Process-wide scorer; the artifact is read once at import, not per email.
_scorer: Optional[MLScorer] = None


def get_scorer(model_path: str = DEFAULT_MODEL_PATH) -> MLScorer:
    global _scorer
    if _scorer is None or _scorer.model_path != model_path:
        _scorer = MLScorer(model_path)
    return _scorer
