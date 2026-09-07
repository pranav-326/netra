"""Rule-based Threat Scoring and Classification Engine (Layer 4)
Evaluates Layer 3 multi-vector analysis findings, applies calibrated scoring weights,
and assigns a threat classification verdict (BENIGN, SUSPICIOUS, MALICIOUS).
"""

from typing import List, Tuple
from netra_common.models.email import AnalysisResults, ThreatVerdict


def evaluate_threat_score(analysis: AnalysisResults) -> Tuple[int, ThreatVerdict, List[str]]:
    """Compute 0-100 risk score, classification verdict, and itemized rule breakdown."""
    score = 0
    matched_rules: List[str] = []

    # --------------------------------------------------------------------------
    # 1. Attachment Security Checks (Highest Risk Vector: +50 max)
    # --------------------------------------------------------------------------
    att_res = analysis.attachment_analysis
    if att_res.has_executable_attachment:
        score += 50
        matched_rules.append(
            f"Dangerous executable/script attachment detected (+50 pts) - Count: {len(att_res.flagged_attachments)}"
        )
    elif att_res.has_double_extension or att_res.has_mime_mismatch:
        score += 25
        matched_rules.append(
            "Double-extension evasion or MIME-type mismatch detected (+25 pts)"
        )

    # --------------------------------------------------------------------------
    # 2. URL & Domain Typosquatting Checks (+40 max)
    # --------------------------------------------------------------------------
    url_res = analysis.url_analysis
    if url_res.typosquat_detections:
        score += 40
        targets = ", ".join([d.target_brand for d in url_res.typosquat_detections])
        matched_rules.append(
            f"Domain typosquatting / brand spoofing detected (+40 pts) - Impersonating: {targets}"
        )

    if url_res.ip_host_urls:
        score += 20
        matched_rules.append(
            f"URL points to raw IP address instead of domain hostname (+20 pts) - Count: {len(url_res.ip_host_urls)}"
        )

    if url_res.defanged_urls:
        score += 10
        matched_rules.append(
            f"Defanged URL evasion pattern identified (+10 pts) - Count: {len(url_res.defanged_urls)}"
        )

    # --------------------------------------------------------------------------
    # 3. Content, BEC & Credential Harvesting Heuristics (+40 max)
    # --------------------------------------------------------------------------
    content_res = analysis.content_analysis
    if content_res.financial_intent_detected:
        score += 30
        matched_rules.append("Business Email Compromise (BEC) / Wire Transfer trigger phrases detected (+30 pts)")

    if content_res.credential_harvesting_detected:
        score += 25
        matched_rules.append("Credential harvesting / Password reset solicitation detected (+25 pts)")

    if content_res.urgency_detected:
        score += 15
        matched_rules.append("Urgency / Coercive account suspension threat language detected (+15 pts)")

    # Compound BEC indicator: financial request combined with urgency
    if content_res.financial_intent_detected and content_res.urgency_detected:
        score += 20
        matched_rules.append("High-confidence BEC compound vector: urgent financial/wire redirection bait (+20 pts)")

    # --------------------------------------------------------------------------
    # 4. Header & Authentication Validation (+20 max)
    # --------------------------------------------------------------------------
    header_res = analysis.header_analysis
    if header_res.spf_verdict == "fail" or header_res.dmarc_verdict == "fail":
        score += 20
        matched_rules.append(
            f"Email authentication check failed (+20 pts) - SPF={header_res.spf_verdict}, DMARC={header_res.dmarc_verdict}"
        )
    elif header_res.dkim_verdict == "fail":
        score += 20
        matched_rules.append("DKIM cryptographic signature verification failed (+20 pts)")
    elif header_res.spf_verdict == "softfail":
        score += 10
        matched_rules.append("SPF check softfail: Sender IP discouraged by domain policy (+10 pts)")
    elif header_res.spf_verdict in ("none", "missing") and header_res.dkim_verdict in ("none", "missing"):
        score += 15
        matched_rules.append("Unauthenticated sender: Missing both SPF and DKIM records (+15 pts)")
    elif not header_res.has_authentication_results:
        score += 5
        matched_rules.append("No Authentication-Results headers present (+5 pts)")

    # Clamp risk score to [0, 100]
    final_score = max(0, min(score, 100))

    # Determine Verdict
    if final_score >= 61:
        verdict = ThreatVerdict.MALICIOUS
    elif final_score >= 21:
        verdict = ThreatVerdict.SUSPICIOUS
    else:
        verdict = ThreatVerdict.BENIGN

    return final_score, verdict, matched_rules
