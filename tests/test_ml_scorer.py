"""Tests for the learned Layer 4 scoring layer and its fallback behaviour."""

import json
import math

import pytest

from netra_common.models.email import (
    AnalysisResults, AnalyzedEmail, AttachmentAnalysisResult, ContentAnalysisResult,
    DetectedTyposquat, EmailHeaders, HeaderAnalysisResult, ParsedEmail,
    RuleContribution, ThreatVerdict, UrlAnalysisResult,
)
from services.threat_engine.src.features import (
    FEATURE_LABELS, FEATURE_NAMES, extract_features, to_vector,
)
from services.threat_engine.src.ml_scorer import MLScorer, _sigmoid
from services.threat_engine.src.scorer import (
    apply_ml_contribution, evaluate_threat_score, finalize_score,
)


def build_analyzed(**overrides) -> AnalyzedEmail:
    headers = overrides.pop("headers", None) or EmailHeaders(
        **{"from": "a@b.com", "to": ["c@d.com"]}, subject="hello", received_chain=["hop1"]
    )
    parsed = ParsedEmail(
        email_id="e1", raw_s3_bucket="b", raw_s3_key="k",
        headers=headers, body_plain=overrides.pop("body", "hello"),
    )
    analysis = AnalysisResults(
        header_analysis=overrides.pop("header_analysis", HeaderAnalysisResult(
            spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass",
            has_authentication_results=True)),
        url_analysis=overrides.pop("url_analysis", UrlAnalysisResult()),
        content_analysis=overrides.pop("content_analysis", ContentAnalysisResult()),
        attachment_analysis=overrides.pop("attachment_analysis", AttachmentAnalysisResult()),
    )
    return AnalyzedEmail(email_id="e1", parsed_email=parsed, analysis=analysis)


# ------------------------------------------------------------------ features

def test_feature_names_and_extraction_agree():
    """Any feature the extractor emits must be in the canonical order, and vice versa."""
    produced = set(extract_features(build_analyzed()).keys())
    declared = set(FEATURE_NAMES)
    assert produced == declared, f"drift: {produced ^ declared}"


def test_every_feature_has_a_human_label():
    """Feature names become axis labels in the analyst-facing explanation."""
    missing = [n for n in FEATURE_NAMES if n not in FEATURE_LABELS]
    assert missing == []


def test_features_are_all_numeric_and_finite():
    values = extract_features(build_analyzed()).values()
    assert all(isinstance(v, float) and math.isfinite(v) for v in values)


def test_auth_verdicts_are_one_hot():
    analyzed = build_analyzed(header_analysis=HeaderAnalysisResult(
        spf_verdict="fail", dkim_verdict="pass", dmarc_verdict="missing",
        has_authentication_results=True))
    f = extract_features(analyzed)

    assert f["spf_fail"] == 1.0 and f["spf_pass"] == 0.0
    assert f["dkim_pass"] == 1.0 and f["dkim_fail"] == 0.0
    assert f["dmarc_none_or_missing"] == 1.0


def test_absent_typosquat_uses_the_far_sentinel():
    """No detection must not read as 'edit distance zero', which is maximal suspicion."""
    f = extract_features(build_analyzed())
    assert f["min_typosquat_distance"] == 20.0
    assert f["max_typosquat_similarity"] == 0.0


def test_typosquat_features_take_the_closest_brand():
    analyzed = build_analyzed(url_analysis=UrlAnalysisResult(
        typosquat_detections=[
            DetectedTyposquat(extracted_domain="micros0ft.com", target_brand="microsoft.com",
                              distance=1, similarity_ratio=0.95),
            DetectedTyposquat(extracted_domain="paypa1-x.com", target_brand="paypal.com",
                              distance=4, similarity_ratio=0.70),
        ]))
    f = extract_features(analyzed)
    assert f["typosquat_count"] == 2.0
    assert f["min_typosquat_distance"] == 1.0
    assert f["max_typosquat_similarity"] == 0.95


def test_reply_to_mismatch_detected():
    same = build_analyzed(headers=EmailHeaders(
        **{"from": "ceo@corp.com", "to": ["x@corp.com"]}, reply_to="ceo@corp.com"))
    diff = build_analyzed(headers=EmailHeaders(
        **{"from": "ceo@corp.com", "to": ["x@corp.com"]}, reply_to="attacker@evil.net"))

    assert extract_features(same)["reply_to_differs_from_sender"] == 0.0
    assert extract_features(diff)["reply_to_differs_from_sender"] == 1.0


def test_to_vector_defaults_unknown_features_to_zero():
    """A model trained before a feature existed must still score, not crash."""
    vec = to_vector({"spf_fail": 1.0}, ["spf_fail", "a_feature_added_later"])
    assert vec == [1.0, 0.0]


# ------------------------------------------------------------------ inference

def write_model(tmp_path, coefficients=None, intercept=0.0, threshold=0.5, max_points=25):
    order = FEATURE_NAMES
    artifact = {
        "version": "test-model",
        "feature_order": order,
        "coefficients": coefficients or [0.0] * len(order),
        "intercept": intercept,
        "means": [0.0] * len(order),
        "scales": [1.0] * len(order),
        "threshold": threshold,
        "max_points": max_points,
        "metrics": {"roc_auc": 0.99},
    }
    path = tmp_path / "model.json"
    path.write_text(json.dumps(artifact))
    return str(path)


def test_missing_artifact_degrades_to_rules_only():
    scorer = MLScorer("/nonexistent/model.json")
    assert scorer.available is False
    assert scorer.predict(build_analyzed()) is None


def test_malformed_artifact_degrades_to_rules_only(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"feature_order": ["a"], "coefficients": [1.0, 2.0], "intercept": 0}')
    scorer = MLScorer(str(bad))
    assert scorer.available is False
    assert scorer.predict(build_analyzed()) is None


def test_contributions_sum_to_the_logit(tmp_path):
    """The explainability guarantee: per-feature terms reconstruct the prediction exactly."""
    coefs = [0.1 * (i % 7) - 0.2 for i in range(len(FEATURE_NAMES))]
    scorer = MLScorer(write_model(tmp_path, coefficients=coefs, intercept=-0.4))

    prediction = scorer.predict(build_analyzed())
    total = sum(c.contribution for c in prediction.contributions) + scorer.intercept

    assert prediction.logit == pytest.approx(total, abs=1e-9)
    assert prediction.probability == pytest.approx(_sigmoid(prediction.logit), abs=1e-12)


def test_inference_is_deterministic(tmp_path):
    scorer = MLScorer(write_model(tmp_path, coefficients=[0.05] * len(FEATURE_NAMES)))
    analyzed = build_analyzed()
    first = scorer.predict(analyzed)
    second = scorer.predict(analyzed)
    assert first.probability == second.probability
    assert first.points == second.points


def test_points_are_capped_in_both_directions(tmp_path):
    scorer = MLScorer(write_model(tmp_path, intercept=50.0, max_points=25))
    assert scorer.predict(build_analyzed()).points == 25

    scorer = MLScorer(write_model(tmp_path, intercept=-50.0, max_points=25))
    assert scorer.predict(build_analyzed()).points == -25


def test_probability_at_threshold_contributes_nothing(tmp_path):
    """The model should only move the score when it actually disagrees with a coin flip."""
    scorer = MLScorer(write_model(tmp_path, intercept=0.0, threshold=0.5))
    assert scorer.predict(build_analyzed()).points == 0


# ------------------------------------------------------- integration with rules

def test_no_prediction_leaves_rule_contributions_untouched():
    _, _, _, contributions, _ = evaluate_threat_score(build_analyzed(
        content_analysis=ContentAnalysisResult(urgency_detected=True)).analysis)
    assert apply_ml_contribution(contributions, None) == contributions


def test_ml_contribution_is_appended_as_a_normal_rule(tmp_path):
    scorer = MLScorer(write_model(tmp_path, intercept=6.0))
    prediction = scorer.predict(build_analyzed())

    combined = apply_ml_contribution([], prediction)
    assert len(combined) == 1
    entry = combined[0]
    assert isinstance(entry, RuleContribution)
    assert entry.rule_id == "ML-PHISH"
    assert entry.category == "ml"
    assert "p(phishing)=" in entry.evidence


def test_finalize_score_still_sums_contributions_with_the_model():
    contributions = [
        RuleContribution(rule_id="A", category="content", label="a", points=30),
        RuleContribution(rule_id="ML-PHISH", category="ml", label="model", points=-10),
    ]
    score, verdict, rules, raw = finalize_score(contributions)

    assert raw == 20
    assert score == 20
    assert verdict == ThreatVerdict.BENIGN
    assert len(rules) == 2
    assert "-10 pts" in rules[1]


def test_model_cannot_overturn_hard_evidence(tmp_path):
    """An executable attachment must stay malicious however confident the model is."""
    from netra_common.models.email import FlaggedAttachment

    analyzed = build_analyzed(attachment_analysis=AttachmentAnalysisResult(
        has_executable_attachment=True,
        flagged_attachments=[FlaggedAttachment(
            filename="x.pdf.exe", sha256="a" * 64, extension=".exe",
            claimed_mime="application/pdf", reason="executable")]))

    _, _, _, contributions, _ = evaluate_threat_score(analyzed.analysis)
    # Maximally confident the message is benign.
    scorer = MLScorer(write_model(tmp_path, intercept=-50.0, max_points=25))
    combined = apply_ml_contribution(contributions, scorer.predict(analyzed))

    score, verdict, _, _ = finalize_score(combined)
    assert score == 25  # 50 from the rule, minus the model's full cap
    assert verdict == ThreatVerdict.SUSPICIOUS  # still flagged, not cleared
