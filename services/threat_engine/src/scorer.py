"""Rule-based Threat Scoring and Classification Engine (Layer 4)

Evaluates Layer 3 multi-vector analysis findings, applies calibrated scoring weights,
and assigns a threat classification verdict (BENIGN, SUSPICIOUS, MALICIOUS).

Explainability is structural, not bolted on. The risk score is defined as the clamped
sum of `RuleContribution` records, so every point in the final number is attributable
to a named rule and the concrete observation that fired it. There is no approximation
step (SHAP, LIME) because there is no opaque model to approximate: the explanation IS
the computation.
"""

from typing import List, Tuple

from netra_common.models.email import AnalysisResults, RuleContribution, ThreatVerdict

# Verdict boundaries on the 0-100 scale. Kept as named constants so the UI, the docs,
# and the tests all cite the same thresholds.
MALICIOUS_THRESHOLD = 61
SUSPICIOUS_THRESHOLD = 21


def evaluate_threat_score(
    analysis: AnalysisResults,
) -> Tuple[int, ThreatVerdict, List[str], List[RuleContribution], int]:
    """Compute the risk score, verdict, and the per-rule contributions behind them.

    Returns `(final_score, verdict, matched_rules, contributions, raw_score)` where
    `matched_rules` is a human-readable rendering of `contributions` and `raw_score` is
    the sum before clamping to [0, 100] — surfaced so a report can show honestly when
    an email exceeded the ceiling.
    """
    contributions: List[RuleContribution] = []

    def fire(rule_id: str, category: str, label: str, points: int, evidence: str = "") -> None:
        contributions.append(
            RuleContribution(
                rule_id=rule_id,
                category=category,
                label=label,
                points=points,
                evidence=evidence,
            )
        )

    # --------------------------------------------------------------------------
    # 1. Attachment Security Checks (Highest Risk Vector: +50 max)
    # --------------------------------------------------------------------------
    att_res = analysis.attachment_analysis
    if att_res.has_executable_attachment:
        flagged = ", ".join(a.filename for a in att_res.flagged_attachments) or "unnamed binary"
        fire(
            "ATT-EXEC",
            "attachment",
            "Dangerous executable or script attachment",
            50,
            f"{len(att_res.flagged_attachments)} flagged: {flagged}",
        )
    elif att_res.has_double_extension or att_res.has_mime_mismatch:
        which = []
        if att_res.has_double_extension:
            which.append("double extension")
        if att_res.has_mime_mismatch:
            which.append("MIME/type mismatch")
        fire(
            "ATT-EVASION",
            "attachment",
            "Attachment evasion technique",
            25,
            " and ".join(which),
        )

    # --------------------------------------------------------------------------
    # 2. URL & Domain Typosquatting Checks (+70 max)
    # --------------------------------------------------------------------------
    url_res = analysis.url_analysis
    if url_res.typosquat_detections:
        targets = ", ".join(d.target_brand for d in url_res.typosquat_detections)
        fire(
            "URL-TYPOSQUAT",
            "url",
            "Domain typosquatting / brand impersonation",
            40,
            f"impersonating {targets}",
        )

    if url_res.ip_host_urls:
        fire(
            "URL-IP-HOST",
            "url",
            "URL points to a raw IP instead of a hostname",
            20,
            f"{len(url_res.ip_host_urls)} URL(s): {', '.join(url_res.ip_host_urls[:3])}",
        )

    if url_res.defanged_urls:
        fire(
            "URL-DEFANGED",
            "url",
            "Defanged URL evasion pattern",
            10,
            f"{len(url_res.defanged_urls)} defanged URL(s)",
        )

    # --------------------------------------------------------------------------
    # 3. Content, BEC & Credential Harvesting Heuristics (+90 max)
    # --------------------------------------------------------------------------
    content_res = analysis.content_analysis
    if content_res.financial_intent_detected:
        fire(
            "CNT-BEC-FINANCIAL",
            "content",
            "Wire transfer / payment redirection language",
            30,
            "BEC financial-intent phrases present in body",
        )

    if content_res.credential_harvesting_detected:
        fire(
            "CNT-CREDENTIAL",
            "content",
            "Credential harvesting solicitation",
            25,
            "password reset / account verification language present",
        )

    if content_res.urgency_detected:
        fire(
            "CNT-URGENCY",
            "content",
            "Urgency and coercion language",
            15,
            "deadline or account-suspension threat present",
        )

    # Compound indicator: urgency applied to a financial request is the BEC signature,
    # and is worth more than either signal alone.
    if content_res.financial_intent_detected and content_res.urgency_detected:
        fire(
            "CNT-BEC-COMPOUND",
            "content",
            "High-confidence BEC compound vector",
            20,
            "urgent financial request: CNT-BEC-FINANCIAL and CNT-URGENCY both fired",
        )

    # --------------------------------------------------------------------------
    # 4. Header & Authentication Validation (+20 max)
    # --------------------------------------------------------------------------
    header_res = analysis.header_analysis
    if header_res.spf_verdict == "fail" or header_res.dmarc_verdict == "fail":
        fire(
            "HDR-AUTH-FAIL",
            "header",
            "Sender authentication failed",
            20,
            f"SPF={header_res.spf_verdict}, DMARC={header_res.dmarc_verdict}",
        )
    elif header_res.dkim_verdict == "fail":
        fire(
            "HDR-DKIM-FAIL",
            "header",
            "DKIM signature verification failed",
            20,
            "cryptographic body hash mismatch",
        )
    elif header_res.spf_verdict == "softfail":
        fire(
            "HDR-SPF-SOFTFAIL",
            "header",
            "SPF softfail",
            10,
            "sender IP discouraged by domain policy",
        )
    elif header_res.spf_verdict in ("none", "missing") and header_res.dkim_verdict in ("none", "missing"):
        fire(
            "HDR-UNAUTHENTICATED",
            "header",
            "Unauthenticated sender",
            15,
            "neither SPF nor DKIM published",
        )
    elif not header_res.has_authentication_results:
        fire(
            "HDR-NO-AUTHRES",
            "header",
            "No Authentication-Results header",
            5,
            "receiving MTA recorded no authentication verdict",
        )

    raw_score = sum(c.points for c in contributions)
    final_score = max(0, min(raw_score, 100))

    if final_score >= MALICIOUS_THRESHOLD:
        verdict = ThreatVerdict.MALICIOUS
    elif final_score >= SUSPICIOUS_THRESHOLD:
        verdict = ThreatVerdict.SUSPICIOUS
    else:
        verdict = ThreatVerdict.BENIGN

    # Human-readable rendering, derived from the same contributions so the prose and
    # the chart can never disagree.
    matched_rules = [
        f"{c.label} (+{c.points} pts)" + (f" - {c.evidence}" if c.evidence else "")
        for c in contributions
    ]

    return final_score, verdict, matched_rules, contributions, raw_score
