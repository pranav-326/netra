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

# Modern lure type (content_engine.LURE_PATTERNS) -> (rule id, label, points). Points
# reflect how often legitimate mail says the same thing: real file-sharing and delivery
# notices exist, a phone number to call about a "Geek Squad renewal" essentially doesn't.
LURE_RULES = {
    "callback_scam": ("CNT-LURE-CALLBACK", "Callback scam: brand, phone number and payment", 25),
    "mailbox_admin": ("CNT-LURE-MAILBOX", "Fake mailbox or account-admin notice", 20),
    "document_share": ("CNT-LURE-DOCUMENT", "Shared-document or e-signature lure", 15),
    "parcel_delivery": ("CNT-LURE-DELIVERY", "Parcel delivery lure", 10),
    "subscription_renewal": ("CNT-LURE-RENEWAL", "Subscription renewal bait", 10),
    "crypto": ("CNT-LURE-CRYPTO", "Cryptocurrency bait", 10),
}

# Rules founded on an objective property of the message rather than an interpretation
# of its language. An executable attachment either is or is not present; a URL either
# does or does not point at a bare IP. No probability should be able to argue these
# away, so when one of them fires the learned layer may only add points, never subtract.
#
# Without this floor the cap is one-directional: +25 cannot lift a 36 past the 61
# malicious threshold, but -25 pulls a 61 down to 36 and silently downgrades a
# MALICIOUS verdict to SUSPICIOUS. Content and header rules are deliberately excluded
# — those are exactly the judgements a model trained on real corpora should be able
# to moderate.
HARD_EVIDENCE_RULES = frozenset({
    "ATT-EXEC",       # a dangerous executable or script is attached
    "ATT-EVASION",    # double extension or MIME/type mismatch
    "URL-IP-HOST",    # a link points at a bare IP address
})


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

    if att_res.html_attachments:
        fire(
            "ATT-HTML",
            "attachment",
            "HTML file attached (fake login page vector)",
            25,
            ", ".join(att_res.html_attachments[:3]),
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

    # Deliberately small: legitimate marketing mail uses shorteners too. The real
    # weight lands on the destination, which the rules above have already analysed.
    if url_res.shortened_urls:
        hops = []
        for s in url_res.shortened_urls[:3]:
            if s.resolved:
                path = [s.original_url] + s.chain[1:-1] + [s.final_url]
            else:
                path = [s.original_url] + s.chain[1:] + [f"unresolved ({s.failure_reason})"]
            hops.append(" -> ".join(path))
        fire(
            "URL-SHORTENER",
            "url",
            "Link shortener hides the real destination",
            5,
            "; ".join(hops),
        )

    if url_res.abused_hosting_urls:
        fire(
            "URL-ABUSED-HOST",
            "url",
            "Link hosted on IPFS or throwaway app hosting",
            15,
            f"{len(url_res.abused_hosting_urls)} URL(s): {', '.join(url_res.abused_hosting_urls[:2])}",
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

    for lure, matched in sorted(content_res.lure_matches.items()):
        rule = LURE_RULES.get(lure)
        if rule:
            fire(rule[0], "content", rule[1], rule[2], f'matched "{matched}"')

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

    # Independent of authentication: modern phishing usually passes SPF from a domain
    # the attacker owns, so a passing check says nothing about who the sender claims to be.
    if header_res.impersonated_brand:
        fire(
            "HDR-BRAND-SPOOF",
            "header",
            "Sender name impersonates a brand",
            25,
            f"display name claims {header_res.impersonated_brand} but mail comes from {header_res.sender_domain}",
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


def _floor_against_hard_evidence(
    contributions: List[RuleContribution], points: int
) -> Tuple[int, List[str]]:
    """A learned model may never talk down hard evidence (see HARD_EVIDENCE_RULES)."""
    hard = sorted({c.rule_id for c in contributions} & HARD_EVIDENCE_RULES)
    return (0 if points < 0 and hard else points), hard


def apply_ml_contribution(
    contributions: List[RuleContribution],
    prediction,
) -> List[RuleContribution]:
    """Append the learned model's contribution to the rule contributions.

    The model enters the score the same way every rule does — as one more
    `RuleContribution` — so the waterfall, the SSE stage event, the API payload and
    the PDF report all render it with no changes. Its `evidence` names the features
    that actually drove the prediction, so the bar is as inspectable as a rule.

    A `None` prediction (no artifact shipped, or inference failed) simply adds
    nothing: the score stays exactly what the rules produced.

    The cap alone is not symmetric protection. +max_points cannot lift a sub-threshold
    score into MALICIOUS, but -max_points can drag a MALICIOUS score below the line.
    When a hard-evidence rule has fired the negative direction is therefore floored at
    zero, and the bar records that the model was overruled.
    """
    if prediction is None or prediction.points == 0:
        return contributions

    points, hard = _floor_against_hard_evidence(contributions, prediction.points)
    floored = points != prediction.points

    drivers = prediction.top_drivers(3, positive_only=prediction.points > 0)
    if drivers:
        driver_text = ", ".join(f"{d.label} ({d.contribution:+.2f})" for d in drivers)
    else:
        driver_text = "no single dominant feature"

    evidence = (
        f"p(phishing)={prediction.probability:.3f} vs threshold {prediction.threshold:.3f}; "
        f"top drivers: {driver_text}; model {prediction.model_version}"
    )

    if floored:
        evidence = (
            f"model suggested {prediction.points:+d} pts but was floored to 0: "
            f"hard evidence present ({', '.join(hard)}). " + evidence
        )

    # A floored prediction still gets a bar, at 0 points, so the report shows that the
    # model was consulted and overruled rather than silently omitting it.
    return contributions + [
        RuleContribution(
            rule_id="ML-PHISH",
            category="ml",
            label="Learned phishing classifier",
            points=points,
            evidence=evidence,
        )
    ]


def apply_text_contribution(
    contributions: List[RuleContribution],
    prediction,
) -> List[RuleContribution]:
    """Append the learned text model's contribution (ML-TEXT).

    Same contract as apply_ml_contribution: one capped, signed bar whose evidence names
    the words that moved it, floored at zero against hard evidence, and nothing at all
    when the model is unavailable.
    """
    if prediction is None or prediction.points == 0:
        return contributions

    points, hard = _floor_against_hard_evidence(contributions, prediction.points)

    terms = prediction.top_terms(4, positive=prediction.points > 0)
    term_text = ", ".join(f"'{t}' ({c:+.2f})" for t, c in terms) or "no single dominant term"
    evidence = (
        f"p(phishing)={prediction.probability:.3f} vs threshold {prediction.threshold:.3f}; "
        f"top terms: {term_text}; model {prediction.model_version}"
    )
    if points != prediction.points:
        evidence = (
            f"model suggested {prediction.points:+d} pts but was floored to 0: "
            f"hard evidence present ({', '.join(hard)}). " + evidence
        )

    return contributions + [
        RuleContribution(
            rule_id="ML-TEXT",
            category="ml",
            label="Learned text classifier",
            points=points,
            evidence=evidence,
        )
    ]


def finalize_score(contributions: List[RuleContribution]) -> Tuple[int, ThreatVerdict, List[str], int]:
    """Collapse contributions into the final score, verdict and prose.

    Shared by the rules-only and rules-plus-model paths so there is exactly one place
    where clamping and the verdict thresholds are applied.
    """
    raw_score = sum(c.points for c in contributions)
    final_score = max(0, min(raw_score, 100))

    if final_score >= MALICIOUS_THRESHOLD:
        verdict = ThreatVerdict.MALICIOUS
    elif final_score >= SUSPICIOUS_THRESHOLD:
        verdict = ThreatVerdict.SUSPICIOUS
    else:
        verdict = ThreatVerdict.BENIGN

    matched_rules = [
        f"{c.label} ({c.points:+d} pts)" + (f" - {c.evidence}" if c.evidence else "")
        for c in contributions
    ]

    return final_score, verdict, matched_rules, raw_score
