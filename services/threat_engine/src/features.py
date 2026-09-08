"""Feature extraction for the learned scoring layer (Layer 4).

This module is the single source of truth for the model's input vector. Both the
offline trainer and the online scorer import `extract_features` from here, so a
feature can never be computed one way during training and another way in
production — train/serve skew of that kind is silent and poisons the model.

Every feature is derived from data the Layer 3 engines already produce. Nothing here
inspects the raw email again, so adding the model costs no additional parsing.

Feature names are stable, ordered, and human-readable because they become the axis
labels of the explanation shown to an analyst.
"""

from typing import TYPE_CHECKING, Dict, List

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for type checkers only
    from netra_common.models.email import AnalyzedEmail

# A large sentinel for "no typosquat was found", chosen so that a smaller edit
# distance always means more suspicious and the coefficient sign stays interpretable.
NO_TYPOSQUAT_DISTANCE = 20.0


def _auth_flags(verdict: str, prefix: str) -> Dict[str, float]:
    """One-hot the authentication verdicts.

    Kept as explicit indicators rather than an ordinal scale: 'softfail' is not
    numerically between 'pass' and 'fail' in any meaningful sense, and forcing an
    order would bake a false assumption into the model.
    """
    verdict = (verdict or "missing").lower()
    return {
        f"{prefix}_pass": 1.0 if verdict == "pass" else 0.0,
        f"{prefix}_fail": 1.0 if verdict == "fail" else 0.0,
        f"{prefix}_softfail": 1.0 if verdict == "softfail" else 0.0,
        f"{prefix}_none_or_missing": 1.0 if verdict in ("none", "missing") else 0.0,
    }


def extract_features(analyzed: "AnalyzedEmail") -> Dict[str, float]:
    """Build the model's feature dict from a Layer 3 AnalyzedEmail."""
    analysis = analyzed.analysis
    header = analysis.header_analysis
    url = analysis.url_analysis
    content = analysis.content_analysis
    attachment = analysis.attachment_analysis
    parsed = analyzed.parsed_email

    features: Dict[str, float] = {}

    # --- Sender authentication -------------------------------------------------
    features.update(_auth_flags(header.spf_verdict, "spf"))
    features.update(_auth_flags(header.dkim_verdict, "dkim"))
    features.update(_auth_flags(header.dmarc_verdict, "dmarc"))
    features["has_auth_results"] = 1.0 if header.has_authentication_results else 0.0
    features["auth_anomaly_count"] = float(len(header.auth_anomalies))

    # --- URLs and domains ------------------------------------------------------
    typosquats = url.typosquat_detections
    features["url_count"] = float(url.total_urls_inspected)
    features["root_domain_count"] = float(len(url.root_domains))
    features["typosquat_count"] = float(len(typosquats))
    # Closest brand collision: small distance = convincing impersonation.
    features["min_typosquat_distance"] = float(
        min((t.distance for t in typosquats), default=NO_TYPOSQUAT_DISTANCE)
    )
    features["max_typosquat_similarity"] = float(
        max((t.similarity_ratio for t in typosquats), default=0.0)
    )
    features["ip_host_url_count"] = float(len(url.ip_host_urls))
    features["defanged_url_count"] = float(len(url.defanged_urls))
    features["suspicious_url_flag_count"] = float(len(url.suspicious_url_flags))

    # --- Content heuristics ----------------------------------------------------
    features["urgency"] = 1.0 if content.urgency_detected else 0.0
    features["financial_intent"] = 1.0 if content.financial_intent_detected else 0.0
    features["credential_harvesting"] = 1.0 if content.credential_harvesting_detected else 0.0
    # The compound signal the rule engine also treats specially; given to the model
    # explicitly because a linear model cannot discover interactions on its own.
    features["financial_and_urgency"] = (
        1.0 if (content.financial_intent_detected and content.urgency_detected) else 0.0
    )
    features["content_heuristic_score"] = float(content.heuristic_content_score)
    features["matched_pattern_count"] = float(len(content.matched_patterns))

    # --- Attachments -----------------------------------------------------------
    features["attachment_count"] = float(attachment.total_attachments_inspected)
    features["has_executable_attachment"] = 1.0 if attachment.has_executable_attachment else 0.0
    features["has_double_extension"] = 1.0 if attachment.has_double_extension else 0.0
    features["has_mime_mismatch"] = 1.0 if attachment.has_mime_mismatch else 0.0
    features["flagged_attachment_count"] = float(len(attachment.flagged_attachments))

    # --- Message structure -----------------------------------------------------
    features["received_hop_count"] = float(len(parsed.headers.received_chain or []))
    features["has_reply_to"] = 1.0 if parsed.headers.reply_to else 0.0
    # Reply-To pointing somewhere other than From is a classic BEC redirect.
    features["reply_to_differs_from_sender"] = _reply_to_mismatch(parsed)
    features["recipient_count"] = float(len(parsed.headers.to_addresses or []))
    features["has_html_body"] = 1.0 if parsed.body_html else 0.0
    features["body_length_log"] = _log1p(len(parsed.body_plain or "") + len(parsed.body_html or ""))

    return features


def _reply_to_mismatch(parsed) -> float:
    """1.0 when Reply-To resolves to a different domain than From."""
    reply_to = (parsed.headers.reply_to or "").strip().lower()
    sender = (parsed.headers.from_address or "").strip().lower()
    if not reply_to or not sender:
        return 0.0
    return 1.0 if _domain_of(reply_to) != _domain_of(sender) else 0.0


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip(" <>") if "@" in address else address


def _log1p(value: float) -> float:
    """Compress heavy-tailed counts without pulling in numpy at inference time."""
    from math import log1p

    return float(log1p(max(value, 0.0)))


# Canonical feature order. The trained artifact records its own order, but this is
# the reference used to build a vector and to detect drift between the two.
FEATURE_NAMES: List[str] = [
    "spf_pass", "spf_fail", "spf_softfail", "spf_none_or_missing",
    "dkim_pass", "dkim_fail", "dkim_softfail", "dkim_none_or_missing",
    "dmarc_pass", "dmarc_fail", "dmarc_softfail", "dmarc_none_or_missing",
    "has_auth_results", "auth_anomaly_count",
    "url_count", "root_domain_count", "typosquat_count",
    "min_typosquat_distance", "max_typosquat_similarity",
    "ip_host_url_count", "defanged_url_count", "suspicious_url_flag_count",
    "urgency", "financial_intent", "credential_harvesting", "financial_and_urgency",
    "content_heuristic_score", "matched_pattern_count",
    "attachment_count", "has_executable_attachment", "has_double_extension",
    "has_mime_mismatch", "flagged_attachment_count",
    "received_hop_count", "has_reply_to", "reply_to_differs_from_sender",
    "recipient_count", "has_html_body", "body_length_log",
]

# Human-readable labels for the analyst-facing explanation.
FEATURE_LABELS: Dict[str, str] = {
    "spf_pass": "SPF passed",
    "spf_fail": "SPF failed",
    "spf_softfail": "SPF softfail",
    "spf_none_or_missing": "No SPF result",
    "dkim_pass": "DKIM passed",
    "dkim_fail": "DKIM failed",
    "dkim_softfail": "DKIM softfail",
    "dkim_none_or_missing": "No DKIM result",
    "dmarc_pass": "DMARC passed",
    "dmarc_fail": "DMARC failed",
    "dmarc_softfail": "DMARC softfail",
    "dmarc_none_or_missing": "No DMARC result",
    "has_auth_results": "Authentication-Results header present",
    "auth_anomaly_count": "Authentication anomalies",
    "url_count": "URLs in message",
    "root_domain_count": "Distinct root domains",
    "typosquat_count": "Typosquat detections",
    "min_typosquat_distance": "Closest brand edit distance",
    "max_typosquat_similarity": "Highest brand similarity",
    "ip_host_url_count": "URLs pointing at raw IPs",
    "defanged_url_count": "Defanged URLs",
    "suspicious_url_flag_count": "Suspicious URL structure flags",
    "urgency": "Urgency language",
    "financial_intent": "Financial / wire language",
    "credential_harvesting": "Credential harvesting language",
    "financial_and_urgency": "Urgent financial request (compound)",
    "content_heuristic_score": "Content heuristic score",
    "matched_pattern_count": "Content patterns matched",
    "attachment_count": "Attachments",
    "has_executable_attachment": "Executable attachment",
    "has_double_extension": "Double extension",
    "has_mime_mismatch": "MIME/extension mismatch",
    "flagged_attachment_count": "Flagged attachments",
    "received_hop_count": "Relay hops",
    "has_reply_to": "Reply-To present",
    "reply_to_differs_from_sender": "Reply-To domain differs from From",
    "recipient_count": "Recipients",
    "has_html_body": "HTML body present",
    "body_length_log": "Body length (log)",
}


def to_vector(features: Dict[str, float], order: List[str]) -> List[float]:
    """Project a feature dict onto an explicit ordering, defaulting absent keys to 0.

    Defaulting rather than raising means a model trained before a new feature existed
    still scores correctly instead of taking the whole pipeline down.
    """
    return [float(features.get(name, 0.0)) for name in order]
