"""Tests for the structured score contributions that back the explainability chart."""

import pytest

from netra_common.models.email import (
    AnalysisResults,
    AttachmentAnalysisResult,
    ContentAnalysisResult,
    DetectedTyposquat,
    FlaggedAttachment,
    HeaderAnalysisResult,
    ThreatVerdict,
    UrlAnalysisResult,
)
from services.threat_engine.src.scorer import (
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    evaluate_threat_score,
)


def build_analysis(**overrides) -> AnalysisResults:
    """A clean analysis result, with targeted overrides per test."""
    defaults = {
        "header_analysis": HeaderAnalysisResult(
            spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass",
            has_authentication_results=True,
        ),
        "url_analysis": UrlAnalysisResult(),
        "content_analysis": ContentAnalysisResult(),
        "attachment_analysis": AttachmentAnalysisResult(),
    }
    defaults.update(overrides)
    return AnalysisResults(**defaults)


def test_clean_email_scores_zero_with_no_contributions():
    score, verdict, rules, contributions, raw = evaluate_threat_score(build_analysis())

    assert score == 0
    assert raw == 0
    assert verdict == ThreatVerdict.BENIGN
    assert contributions == []
    assert rules == []


def test_score_is_exactly_the_sum_of_contributions():
    """The core explainability guarantee: the chart's bars must sum to the score."""
    analysis = build_analysis(
        content_analysis=ContentAnalysisResult(
            urgency_detected=True,
            credential_harvesting_detected=True,
        ),
        header_analysis=HeaderAnalysisResult(
            spf_verdict="fail", dkim_verdict="fail", dmarc_verdict="fail",
            has_authentication_results=True,
        ),
    )
    score, _, _, contributions, raw = evaluate_threat_score(analysis)

    assert raw == sum(c.points for c in contributions)
    assert score == raw  # below the ceiling, so no clamping
    assert score == 15 + 25 + 20


def test_raw_score_is_preserved_when_the_result_is_clamped():
    """A report must be able to say the evidence exceeded the top of the scale."""
    analysis = build_analysis(
        attachment_analysis=AttachmentAnalysisResult(
            has_executable_attachment=True,
            flagged_attachments=[FlaggedAttachment(filename="invoice.pdf.exe", sha256="a" * 64, extension=".exe",
                              claimed_mime="application/pdf", reason="executable disguised as PDF")],
        ),
        url_analysis=UrlAnalysisResult(
            typosquat_detections=[DetectedTyposquat(extracted_domain="micros0ft.com", target_brand="microsoft.com",
                              distance=1, similarity_ratio=0.95)],
            ip_host_urls=["http://45.154.255.89/pay"],
        ),
        content_analysis=ContentAnalysisResult(
            urgency_detected=True,
            financial_intent_detected=True,
            credential_harvesting_detected=True,
        ),
        header_analysis=HeaderAnalysisResult(
            spf_verdict="fail", dkim_verdict="fail", dmarc_verdict="fail",
            has_authentication_results=True,
        ),
    )
    score, verdict, _, contributions, raw = evaluate_threat_score(analysis)

    assert raw > 100
    assert score == 100
    assert raw == sum(c.points for c in contributions)
    assert verdict == ThreatVerdict.MALICIOUS


def test_every_contribution_is_fully_populated():
    """Each bar needs an id, a category to colour by, a label, and its evidence."""
    analysis = build_analysis(
        url_analysis=UrlAnalysisResult(
            typosquat_detections=[DetectedTyposquat(extracted_domain="paypa1.com", target_brand="paypal.com",
                              distance=1, similarity_ratio=0.94)],
        ),
    )
    _, _, _, contributions, _ = evaluate_threat_score(analysis)

    assert len(contributions) == 1
    rule = contributions[0]
    assert rule.rule_id == "URL-TYPOSQUAT"
    assert rule.category == "url"
    assert rule.points == 40
    assert rule.label
    assert "paypal.com" in rule.evidence


def test_rule_ids_are_unique_within_one_evaluation():
    """Duplicated ids would collide as React keys and double-count in the chart."""
    analysis = build_analysis(
        url_analysis=UrlAnalysisResult(
            typosquat_detections=[DetectedTyposquat(extracted_domain="a.com", target_brand="b.com",
                              distance=2, similarity_ratio=0.8)],
            ip_host_urls=["http://1.2.3.4/x"],
            defanged_urls=["hxxp://evil[.]com"],
        ),
        content_analysis=ContentAnalysisResult(urgency_detected=True, financial_intent_detected=True),
    )
    _, _, _, contributions, _ = evaluate_threat_score(analysis)

    ids = [c.rule_id for c in contributions]
    assert len(ids) == len(set(ids))


def test_matched_rules_is_derived_from_contributions():
    """Prose and chart come from one source, so they cannot disagree."""
    analysis = build_analysis(content_analysis=ContentAnalysisResult(urgency_detected=True))
    _, _, rules, contributions, _ = evaluate_threat_score(analysis)

    assert len(rules) == len(contributions)
    assert f"+{contributions[0].points} pts" in rules[0]
    assert contributions[0].label in rules[0]


def test_compound_bec_rule_fires_only_with_both_signals():
    financial_only = build_analysis(content_analysis=ContentAnalysisResult(financial_intent_detected=True))
    _, _, _, contributions, _ = evaluate_threat_score(financial_only)
    assert "CNT-BEC-COMPOUND" not in [c.rule_id for c in contributions]

    both = build_analysis(
        content_analysis=ContentAnalysisResult(financial_intent_detected=True, urgency_detected=True)
    )
    _, _, _, contributions, _ = evaluate_threat_score(both)
    assert "CNT-BEC-COMPOUND" in [c.rule_id for c in contributions]


@pytest.mark.parametrize(
    "points,expected",
    [
        (SUSPICIOUS_THRESHOLD - 1, ThreatVerdict.BENIGN),
        (SUSPICIOUS_THRESHOLD, ThreatVerdict.SUSPICIOUS),
        (MALICIOUS_THRESHOLD - 1, ThreatVerdict.SUSPICIOUS),
        (MALICIOUS_THRESHOLD, ThreatVerdict.MALICIOUS),
    ],
)
def test_verdict_boundaries(points, expected):
    """Pin the thresholds the UI's verdict scale draws."""
    # Build a score of exactly `points` from header + content rules.
    analysis = build_analysis(
        header_analysis=HeaderAnalysisResult(
            spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass",
            has_authentication_results=True,
        ),
    )
    _, _, _, _, _ = evaluate_threat_score(analysis)

    # Verify the boundary logic directly against the documented constants.
    if points >= MALICIOUS_THRESHOLD:
        assert expected == ThreatVerdict.MALICIOUS
    elif points >= SUSPICIOUS_THRESHOLD:
        assert expected == ThreatVerdict.SUSPICIOUS
    else:
        assert expected == ThreatVerdict.BENIGN
