"""Learned text channel (ML-TEXT) for Layer 4, evaluated in pure Python.

A logistic regression over TF-IDF word and character n-grams, trained offline by
ml/train_text_model.py and shipped as readable JSON. Like the structured model in
ml_scorer.py there is no scikit-learn, numpy or pickle here, and the explanation is
exact: each term contributes coefficient x tf-idf weight to the logit, and those terms
sum to the logit by definition.

A missing, malformed or mismatched artifact disables the channel; the pipeline keeps
scoring on everything else.
"""

import json
import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from math import log, sqrt
from typing import Dict, List, Optional, Tuple

from .ml_scorer import MLScorer, _sigmoid
from .text_features import CHAR_NGRAM_SIZES, DATASET_ARTIFACTS, MAX_WORDS, clean_text, tokenize

logger = logging.getLogger("netra.threat_engine.text")

DEFAULT_TEXT_MODEL_PATH = os.getenv(
    "NETRA_TEXT_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "models", "text_lr.json"),
)


@dataclass
class TextPrediction:
    probability: float
    logit: float
    points: int
    threshold: float
    model_version: str
    # (readable term, contribution to the logit), largest magnitude first.
    term_contributions: List[Tuple[str, float]] = field(default_factory=list)

    def top_terms(self, n: int = 5, positive: bool = True) -> List[Tuple[str, float]]:
        items = [(t, c) for t, c in self.term_contributions if (c > 0) == positive]
        return sorted(items, key=lambda tc: abs(tc[1]), reverse=True)[:n]


def _readable(token: str) -> Optional[str]:
    """Word and bigram tokens are shown to analysts; character n-grams are not."""
    if token.startswith("w:") or token.startswith("w2:"):
        return token.split(":", 1)[1]
    return None


class TextScorer:
    def __init__(self, model_path: str = DEFAULT_TEXT_MODEL_PATH):
        self.model_path = model_path
        self.available = False
        self.unavailable_reason: Optional[str] = None
        self.terms: Dict[str, Tuple[float, float]] = {}
        self.intercept = 0.0
        self.threshold = 0.5
        self.max_points = 15
        self.version = "unknown"
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.model_path):
            self.unavailable_reason = f"no text model artifact at {self.model_path}"
            logger.info(f"Text channel disabled: {self.unavailable_reason}")
            return
        try:
            with open(self.model_path, "r", encoding="utf-8") as handle:
                artifact = json.load(handle)

            tok = artifact["tokenizer"]
            expected = {
                "max_words": MAX_WORDS,
                "char_ngram_sizes": list(CHAR_NGRAM_SIZES),
                "dataset_artifacts": sorted(DATASET_ARTIFACTS),
            }
            drift = [k for k, v in expected.items() if tok.get(k) != v]
            if drift:
                # Scoring with a different tokeniser than the model was trained on would
                # be silently wrong, so refuse instead.
                raise ValueError(f"tokenizer settings differ from training: {', '.join(drift)}")

            self.terms = {t: (float(v[0]), float(v[1])) for t, v in artifact["terms"].items()}
            self.intercept = float(artifact["intercept"])
            self.threshold = float(artifact["threshold"])
            self.max_points = int(artifact.get("max_points", 15))
            self.version = str(artifact.get("version", "unknown"))
            self.available = True
            logger.info(f"Loaded text model '{self.version}' ({len(self.terms)} terms, cap ±{self.max_points} pts)")
        except Exception as exc:
            self.unavailable_reason = f"failed to load text model: {exc}"
            logger.error(f"Text model at {self.model_path} could not be loaded: {exc}")
            self.available = False

    def _logit(self, tokens: List[str]) -> Tuple[float, Dict[str, float]]:
        counts = Counter(t for t in tokens if t in self.terms)
        # sublinear tf x idf, then l2 normalisation: TfidfVectorizer(sublinear_tf=True).
        weights = {t: (1.0 + log(c)) * self.terms[t][0] for t, c in counts.items()}
        norm = sqrt(sum(w * w for w in weights.values()))
        if norm == 0.0:
            return self.intercept, {}
        contributions = {t: self.terms[t][1] * w / norm for t, w in weights.items()}
        return self.intercept + sum(contributions.values()), contributions

    def probability_from_tokens(self, tokens: List[str]) -> float:
        return _sigmoid(self._logit(tokens)[0])

    def predict(self, parsed_email) -> Optional[TextPrediction]:
        if not self.available:
            return None
        try:
            text = clean_text(parsed_email.headers.subject, parsed_email.body_plain, parsed_email.body_html)
            logit, contributions = self._logit(tokenize(text))
            probability = _sigmoid(logit)
            readable = [(_readable(t), c) for t, c in contributions.items()]
            return TextPrediction(
                probability=probability,
                logit=logit,
                points=MLScorer._to_points(self, probability),
                threshold=self.threshold,
                model_version=self.version,
                term_contributions=[(t, c) for t, c in readable if t],
            )
        except Exception as exc:
            logger.error(f"Text model inference failed; continuing without it: {exc}")
            return None


_text_scorer: Optional[TextScorer] = None


def get_text_scorer(model_path: str = DEFAULT_TEXT_MODEL_PATH) -> TextScorer:
    global _text_scorer
    if _text_scorer is None or _text_scorer.model_path != model_path:
        _text_scorer = TextScorer(model_path)
    return _text_scorer
