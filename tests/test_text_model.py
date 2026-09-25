"""Tests for the learned text channel (ML-TEXT): tokeniser, serving scorer, and scoring."""

import json
import os
from types import SimpleNamespace

import pytest

from netra_common.models.email import RuleContribution
from services.threat_engine.src import text_features
from services.threat_engine.src.scorer import apply_text_contribution
from services.threat_engine.src.text_features import clean_text, tokenize
from services.threat_engine.src.text_scorer import DEFAULT_TEXT_MODEL_PATH, TextPrediction, TextScorer


def email(subject="", plain="", html=""):
    return SimpleNamespace(headers=SimpleNamespace(subject=subject), body_plain=plain, body_html=html)


def write_artifact(tmp_path, terms, intercept=0.0, threshold=0.5, **tokenizer_overrides):
    tokenizer = {
        "max_words": text_features.MAX_WORDS,
        "char_ngram_sizes": list(text_features.CHAR_NGRAM_SIZES),
        "dataset_artifacts": sorted(text_features.DATASET_ARTIFACTS),
        "sublinear_tf": True,
        "norm": "l2",
    }
    tokenizer.update(tokenizer_overrides)
    path = tmp_path / "text_lr.json"
    path.write_text(json.dumps({
        "version": "test", "tokenizer": tokenizer, "intercept": intercept,
        "threshold": threshold, "max_points": 15, "terms": terms,
    }))
    return str(path)


# --- Cleaning and tokenisation ----------------------------------------------------

def test_clean_text_removes_era_and_dataset_structure():
    body = (
        "Please verify your account on 12 Aug 2002.\n"
        "> quoted reply that should vanish\n"
        "Visit http://evil.example/login or mail billing@evil.example\n"
        "-- \n"
        "signature that should vanish\n"
    )
    text = clean_text("Urgent", body, None)

    assert "quoted reply" not in text
    assert "signature" not in text
    assert "2002" not in text and "12" not in text
    assert "urltoken" in text and "emailtoken" in text
    assert "evil.example" not in text


def test_clean_text_stops_at_mailing_list_footer():
    body = "Real content here\n_______________________________________________\nList footer text\n"
    assert "footer" not in clean_text("", body, None)


def test_clean_text_falls_back_to_html():
    text = clean_text("", "", "<p>Confirm your <b>password</b></p><style>p{color:red}</style>")
    assert "confirm your password" in " ".join(text.split())
    assert "color" not in text


def test_tokenize_emits_words_bigrams_and_char_ngrams():
    tokens = tokenize("verify account")
    assert "w:verify" in tokens and "w:account" in tokens
    assert "w2:verify account" in tokens
    assert "c: ve" in tokens and "c:ount " in tokens


def test_tokenize_drops_dataset_artifacts_before_ngrams():
    tokens = tokenize("re wrote sep verify")
    assert not any("wrote" in t or t == "w:re" or "sep" in t for t in tokens)
    assert "w:verify" in tokens


def test_tokenize_caps_word_count():
    tokens = tokenize("word " * (text_features.MAX_WORDS + 500))
    assert tokens.count("w:word") == text_features.MAX_WORDS


def test_training_and_serving_share_one_tokeniser():
    pytest.importorskip("sklearn")
    from ml import train_text_model
    from services.threat_engine.src import text_scorer

    assert train_text_model.text_features.tokenize is text_scorer.tokenize
    assert train_text_model.text_features.clean_text is text_scorer.clean_text


def test_serving_math_matches_sklearn(tmp_path):
    sklearn = pytest.importorskip("sklearn")  # noqa: F841
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    docs = ["verify your account now", "meeting notes attached", "confirm your bank password",
            "lunch on friday team", "your account is suspended verify", "quarterly report draft"] * 3
    labels = [1, 0, 1, 0, 1, 0] * 3
    tokens = [tokenize(clean_text("", d, None)) for d in docs]

    tfidf = TfidfVectorizer(analyzer=lambda t: t, sublinear_tf=True)
    lr = LogisticRegression(max_iter=1000).fit(tfidf.fit_transform(tokens), labels)
    terms = {t: [float(i), float(c)] for t, i, c in zip(tfidf.get_feature_names_out(), tfidf.idf_, lr.coef_[0])}
    scorer = TextScorer(write_artifact(tmp_path, terms, intercept=float(lr.intercept_[0])))

    expected = lr.predict_proba(tfidf.transform(tokens))[:, 1]
    for tok, want in zip(tokens, expected):
        assert scorer.probability_from_tokens(tok) == pytest.approx(want, abs=1e-12)


# --- Serving scorer ---------------------------------------------------------------

def test_missing_artifact_disables_channel(tmp_path):
    scorer = TextScorer(str(tmp_path / "absent.json"))

    assert not scorer.available
    assert scorer.predict(email("hi", "verify your account")) is None


def test_malformed_artifact_disables_channel(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")

    assert not TextScorer(str(bad)).available


def test_tokenizer_drift_disables_channel(tmp_path):
    path = write_artifact(tmp_path, {"w:verify": [1.0, 1.0]}, dataset_artifacts=["something-else"])
    scorer = TextScorer(path)

    assert not scorer.available
    assert "tokenizer settings differ" in scorer.unavailable_reason


def test_points_are_capped_in_both_directions(tmp_path):
    strong = TextScorer(write_artifact(tmp_path, {"w:verify": [1.0, 50.0]}))
    assert strong.predict(email("", "verify")).points == 15

    weak = TextScorer(write_artifact(tmp_path, {"w:verify": [1.0, -50.0]}))
    assert weak.predict(email("", "verify")).points == -15


def test_text_without_known_terms_uses_intercept_only(tmp_path):
    scorer = TextScorer(write_artifact(tmp_path, {"w:verify": [1.0, 50.0]}, intercept=0.0))
    prediction = scorer.predict(email("", "completely unrelated words"))

    assert prediction.probability == pytest.approx(0.5)
    assert prediction.points == 0


# --- Scoring contribution ---------------------------------------------------------

def prediction(points, terms=(("verify your", 0.9), ("account", 0.4), ("meeting", -0.3))):
    return TextPrediction(probability=0.97, logit=3.5, points=points, threshold=0.22,
                          model_version="text-lr-test", term_contributions=list(terms))


def test_contribution_names_top_terms_in_evidence():
    result = apply_text_contribution([], prediction(12))

    assert len(result) == 1
    bar = result[0]
    assert (bar.rule_id, bar.category, bar.points) == ("ML-TEXT", "ml", 12)
    assert "'verify your' (+0.90)" in bar.evidence
    assert "'account' (+0.40)" in bar.evidence
    assert "meeting" not in bar.evidence
    assert "text-lr-test" in bar.evidence


def test_no_prediction_or_zero_points_adds_nothing():
    rules = [RuleContribution(rule_id="URL-TYPOSQUAT", category="url", label="x", points=40)]

    assert apply_text_contribution(rules, None) == rules
    assert apply_text_contribution(rules, prediction(0)) == rules


def test_negative_text_score_cannot_talk_down_hard_evidence():
    rules = [RuleContribution(rule_id="ATT-EXEC", category="attachment", label="x", points=50)]

    bar = apply_text_contribution(rules, prediction(-15))[-1]

    assert bar.points == 0
    assert "floored to 0" in bar.evidence and "ATT-EXEC" in bar.evidence


def test_negative_text_score_applies_without_hard_evidence():
    rules = [RuleContribution(rule_id="CNT-URGENCY", category="content", label="x", points=15)]

    assert apply_text_contribution(rules, prediction(-10))[-1].points == -10


# --- Shipped artifact -------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(DEFAULT_TEXT_MODEL_PATH), reason="no shipped text model")
def test_shipped_model_ranks_phishing_language_above_routine_mail():
    scorer = TextScorer()
    assert scorer.available

    phish = scorer.predict(email(
        "Your account has been suspended",
        "Dear customer, we detected unusual activity on your bank account. "
        "Verify your identity and confirm your password within 24 hours or your account will be closed.",
    ))
    routine = scorer.predict(email(
        "Build failing on the test branch",
        "The integration tests broke after the last merge, I think the config loader is the culprit. "
        "Can someone look at the patch before the release?",
    ))

    assert phish.probability > routine.probability
    assert -15 <= phish.points <= 15 and -15 <= routine.points <= 15
