"""Pydantic schemas for Email Ingestion, Parsing, and Metadata."""

from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class IngestionEvent(BaseModel):
    """Event emitted to Redis when an email is ingested."""
    email_id: str = Field(..., description="Unique UUID assigned to the ingested email")
    bucket: str = Field(..., description="MinIO bucket storing the raw payload")
    object_key: str = Field(..., description="Object key in the raw email bucket")
    ingested_at: datetime = Field(default_factory=datetime.utcnow, description="UTC ingestion timestamp")
    source_type: str = Field(..., description="Ingestion channel: 'file' or 'text'")
    file_size_bytes: int = Field(..., description="Size of the raw payload in bytes")
    original_filename: Optional[str] = Field(None, description="Original uploaded filename if file upload")


class AttachmentMetadata(BaseModel):
    """Metadata for an email attachment extracted by the parser."""
    filename: str = Field(..., description="Original filename of the attachment")
    content_type: str = Field(default="application/octet-stream", description="MIME content type")
    size_bytes: int = Field(..., description="Size of attachment in bytes")
    sha256: str = Field(..., description="SHA-256 cryptographic hash")
    md5: str = Field(..., description="MD5 hash")
    bucket: str = Field(default="attachments", description="MinIO bucket where attachment is saved")
    object_key: str = Field(..., description="Object storage path in the attachments bucket")


class EmailHeaders(BaseModel):
    """Extracted and normalized RFC 5322 headers."""
    from_address: Optional[str] = Field(None, alias="from", description="From header address")
    to_addresses: List[str] = Field(default_factory=list, alias="to", description="List of recipient addresses")
    cc_addresses: List[str] = Field(default_factory=list, alias="cc", description="CC recipient addresses")
    bcc_addresses: List[str] = Field(default_factory=list, alias="bcc", description="BCC recipient addresses")
    reply_to: Optional[str] = Field(None, description="Reply-To header address")
    subject: Optional[str] = Field(None, description="Email Subject line")
    date: Optional[str] = Field(None, description="Date header string")
    message_id: Optional[str] = Field(None, description="Message-ID header")
    received_chain: List[str] = Field(default_factory=list, description="Ordered hop-by-hop Received headers")
    raw_headers: Dict[str, Any] = Field(default_factory=dict, description="Full dictionary of all raw headers")

    class Config:
        populate_by_name = True


class ParsedEmail(BaseModel):
    """Canonical model for normalized email content extracted by Layer 2."""
    email_id: str = Field(..., description="Unique UUID of the email")
    raw_s3_bucket: str = Field(..., description="Bucket where raw email is stored")
    raw_s3_key: str = Field(..., description="Key of the raw email object")
    headers: EmailHeaders = Field(..., description="Parsed RFC 5322 headers")
    body_plain: Optional[str] = Field(None, description="Extracted plaintext body content")
    body_html: Optional[str] = Field(None, description="Extracted HTML body content")
    extracted_urls: List[str] = Field(default_factory=list, description="Unique URLs found in plaintext and HTML body")
    attachments: List[AttachmentMetadata] = Field(default_factory=list, description="List of extracted attachments")
    parsed_at: datetime = Field(default_factory=datetime.utcnow, description="UTC parsing timestamp")


# ------------------------------------------------------------------------------
# Layer 3: Analysis Results Schemas
# ------------------------------------------------------------------------------

class HeaderAnalysisResult(BaseModel):
    """Authentication and protocol analysis findings."""
    spf_verdict: str = Field(default="missing", description="SPF check result (pass, fail, softfail, neutral, none, missing)")
    dkim_verdict: str = Field(default="missing", description="DKIM check result (pass, fail, none, missing)")
    dmarc_verdict: str = Field(default="missing", description="DMARC check result (pass, fail, none, missing)")
    has_authentication_results: bool = Field(default=False, description="Whether Authentication-Results header was present")
    authres_header_count: int = Field(default=0, description="Number of Authentication-Results headers found on the message")
    has_conflicting_auth_results: bool = Field(default=False, description="Multiple Authentication-Results headers disagree, a hallmark of a prepended forgery")
    auth_anomalies: List[str] = Field(default_factory=list, description="Specific authentication irregularities or failures flagged")
    impersonated_brand: Optional[str] = Field(None, description="Brand the sender's display name claims while the sending domain is not that brand's")
    sender_domain: Optional[str] = Field(None, description="Registered root domain of the From address")


class DetectedTyposquat(BaseModel):
    """Details on a suspected domain typosquatting attempt."""
    extracted_domain: str
    target_brand: str
    distance: int
    similarity_ratio: float


class ShortenedUrl(BaseModel):
    """A link-shortener URL and where it was found to lead."""
    original_url: str = Field(..., description="The short link as it appeared in the email")
    chain: List[str] = Field(default_factory=list, description="Every hop in order, starting with the original short link")
    final_url: Optional[str] = Field(None, description="Resolved destination; None when resolution did not finish")
    resolved: bool = Field(default=False, description="True only when a non-shortener destination was reached")
    failure_reason: Optional[str] = Field(None, description="Why resolution stopped early; unresolved never means clean")


class UrlAnalysisResult(BaseModel):
    """URL and domain reputation/lexical analysis findings."""
    total_urls_inspected: int = Field(default=0)
    root_domains: List[str] = Field(default_factory=list, description="Unique registered root domains found")
    typosquat_detections: List[DetectedTyposquat] = Field(default_factory=list, description="Identified brand typosquatting targets")
    ip_host_urls: List[str] = Field(default_factory=list, description="URLs pointing directly to bare IP addresses")
    defanged_urls: List[str] = Field(default_factory=list, description="Defanged URLs (e.g. hxxp, [.] ) detected")
    suspicious_url_flags: List[str] = Field(default_factory=list, description="Heuristic flags (excessive subdomains, punycode, etc.)")
    shortened_urls: List[ShortenedUrl] = Field(default_factory=list, description="Link-shortener URLs and their resolved destinations")
    abused_hosting_urls: List[str] = Field(default_factory=list, description="Links on IPFS gateways or throwaway app hosting commonly used for phishing pages")


class ContentAnalysisResult(BaseModel):
    """Content, NLP, and BEC heuristic analysis findings."""
    urgency_detected: bool = Field(default=False, description="Urgency / coercion language detected")
    financial_intent_detected: bool = Field(default=False, description="Wire transfer, payroll, gift card, or payment triggers detected")
    credential_harvesting_detected: bool = Field(default=False, description="Password reset or credential verification triggers detected")
    matched_patterns: List[str] = Field(default_factory=list, description="List of specific heuristic phrase categories triggered")
    matched_keywords: List[str] = Field(default_factory=list, description="Snippets of matching suspicious terms")
    heuristic_content_score: float = Field(default=0.0, description="Heuristic threat indicator score from 0.0 to 1.0")
    lure_matches: Dict[str, str] = Field(default_factory=dict, description="Modern lure type -> the text that matched it")


class FlaggedAttachment(BaseModel):
    """Attachment flagged as potentially dangerous."""
    filename: str
    sha256: str
    extension: str
    claimed_mime: str
    reason: str


class AttachmentAnalysisResult(BaseModel):
    """Attachment security checks findings."""
    total_attachments_inspected: int = Field(default=0)
    has_executable_attachment: bool = Field(default=False, description="Whether an executable or script was detected")
    has_double_extension: bool = Field(default=False, description="Whether a double extension was detected (e.g., .pdf.exe)")
    has_mime_mismatch: bool = Field(default=False, description="Whether MIME type conflicts with file extension")
    flagged_attachments: List[FlaggedAttachment] = Field(default_factory=list, description="Detailed records of flagged attachments")
    html_attachments: List[str] = Field(default_factory=list, description="Attached HTML/SVG files, a common vector for fake login pages")


class LocationClue(BaseModel):
    """One piece of evidence about where an email, or the money it asks for, comes from."""
    kind: str = Field(..., description="iban, swift, phone, timezone, language, sender_domain")
    measures: str = Field(..., description="What the clue locates, e.g. 'payment destination', 'sender's clock'")
    value: str = Field(..., description="The observation, masked where it is financial data")
    countries: List[str] = Field(default_factory=list, description="Candidate ISO 3166 alpha-2 codes; empty = no location")
    region: Optional[str] = Field(None, description="Human-readable place, e.g. 'Florida' or 'India, Sri Lanka'")
    strength: str = Field(..., description="strong, medium or weak")
    note: Optional[str] = Field(None, description="Caveat, e.g. 'toll-free: carries no location'")


class OriginAssessment(BaseModel):
    """The clues combined into a probable sender country, with an honest confidence.

    Bank details are kept apart: they locate where the money goes, which is often a
    money-mule account in a different country from the sender.
    """
    country: Optional[str] = Field(None, description="ISO alpha-2 of the sender's most supported country")
    country_name: Optional[str] = None
    confidence: str = Field(default="undetermined", description="high, medium, low or undetermined")
    payment_countries: List[str] = Field(default_factory=list, description="Countries the requested payment goes to")
    summary: str = Field(default="No location clues found in this email.")
    supporting: List[str] = Field(default_factory=list)
    conflicting: List[str] = Field(default_factory=list)


class OriginAnalysisResult(BaseModel):
    """Location clues other than IP addresses (Layer 3). Contributes no risk points."""
    clues: List[LocationClue] = Field(default_factory=list)
    assessment: OriginAssessment = Field(default_factory=OriginAssessment)


class AnalysisResults(BaseModel):
    """Consolidated container aggregating all Layer 3 security engine outputs."""
    header_analysis: HeaderAnalysisResult = Field(default_factory=HeaderAnalysisResult)
    url_analysis: UrlAnalysisResult = Field(default_factory=UrlAnalysisResult)
    content_analysis: ContentAnalysisResult = Field(default_factory=ContentAnalysisResult)
    attachment_analysis: AttachmentAnalysisResult = Field(default_factory=AttachmentAnalysisResult)
    origin_analysis: OriginAnalysisResult = Field(default_factory=OriginAnalysisResult)


class AnalyzedEmail(BaseModel):
    """Canonical model combining parsed email data and comprehensive Layer 3 security analysis."""
    email_id: str = Field(..., description="Unique UUID of the email")
    parsed_email: ParsedEmail = Field(..., description="Original normalized email data")
    analysis: AnalysisResults = Field(default_factory=AnalysisResults, description="Multi-perspective security analysis results")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow, description="UTC analysis completion timestamp")


# ------------------------------------------------------------------------------
# Layer 4: Threat Engine & Classification Schemas
# ------------------------------------------------------------------------------

class ThreatVerdict(str, Enum):
    """Overall classification verdict for the analyzed email."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class IOCItem(BaseModel):
    """Extracted Indicator of Compromise (IOC) record."""
    type: str = Field(..., description="IOC Type: url, domain, ip, sha256, md5, sender_email")
    value: str = Field(..., description="The indicator value (e.g. 198.51.100.25, evil.com)")
    context: str = Field(default="", description="Contextual description of where/why this IOC was found")


class RuleContribution(BaseModel):
    """One scoring rule that fired, and exactly what it contributed to the risk score.

    This is Netra's explainability primitive. The score is a plain sum of these
    contributions, so a report can show precisely how it reached its number —
    deterministic and auditable, with no model attribution step to approximate.
    """
    rule_id: str = Field(..., description="Stable identifier for the rule, e.g. 'ATT-EXEC'")
    category: str = Field(..., description="Vector this rule belongs to: attachment, url, content, header")
    label: str = Field(..., description="Short human-readable name of what fired")
    points: int = Field(..., description="Points this rule added to the risk score")
    evidence: str = Field(default="", description="The concrete observation that triggered the rule")


class ThreatIntelligence(BaseModel):
    """Threat scoring, classification verdict, triggered rules, and consolidated IOCs."""
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score from 0 (harmless) to 100 (critical)")
    classification: ThreatVerdict = Field(..., description="Threat classification verdict")
    rule_contributions: List[RuleContribution] = Field(default_factory=list, description="Structured per-rule score contributions backing the risk score")
    score_before_clamp: int = Field(default=0, description="Raw sum of contributions before clamping to [0, 100]")
    matched_rules: List[str] = Field(default_factory=list, description="Human-readable rendering of rule_contributions, retained for compatibility")
    iocs: List[IOCItem] = Field(default_factory=list, description="Consolidated indicators of compromise for Layer 5 enrichment")
    classified_at: datetime = Field(default_factory=datetime.utcnow, description="UTC timestamp of threat classification")


class ClassifiedEmail(BaseModel):
    """Canonical envelope combining AnalyzedEmail with Layer 4 ThreatIntelligence."""
    email_id: str = Field(..., description="Unique UUID of the email")
    analyzed_email: AnalyzedEmail = Field(..., description="Layer 3 analyzed email data")
    threat_assessment: ThreatIntelligence = Field(..., description="Layer 4 threat evaluation, score, and IOCs")


# ------------------------------------------------------------------------------
# Layer 5: Threat Intelligence Enrichment Schemas
# ------------------------------------------------------------------------------

class EnrichedIOC(BaseModel):
    """Enriched IOC record containing external intelligence telemetry."""
    type: str = Field(..., description="IOC Type: url, domain, ip, sha256, md5, email_address")
    value: str = Field(..., description="The indicator value")
    context: str = Field(default="", description="Contextual origin")
    is_malicious: bool = Field(default=False, description="Flagged as malicious by external intelligence provider")
    threat_score: int = Field(default=0, ge=0, le=100, description="Reputation score (0-100)")
    provider: str = Field(default="Internal Feeds", description="Enrichment provider (VirusTotal, AbuseIPDB, URLhaus)")
    threat_names: List[str] = Field(default_factory=list, description="Malware families or campaign names associated with this IOC")
    details: Dict[str, Any] = Field(default_factory=dict, description="Raw provider telemetry details")


class EnrichmentData(BaseModel):
    """Aggregated external intelligence findings for the email."""
    total_iocs_checked: int = Field(default=0)
    malicious_iocs_found: int = Field(default=0)
    threat_actors: List[str] = Field(default_factory=list, description="Associated threat actor groups (e.g. APT29, FIN7, Storm-0558)")
    enriched_iocs: List[EnrichedIOC] = Field(default_factory=list, description="Detailed list of enriched indicators")
    enrichment_sources: List[str] = Field(default_factory=list, description="External intelligence feeds queried")
    enriched_at: datetime = Field(default_factory=datetime.utcnow)


class EnrichedEmail(BaseModel):
    """Canonical envelope combining ClassifiedEmail with Layer 5 external threat intelligence."""
    email_id: str = Field(..., description="Unique UUID of the email")
    classified_email: ClassifiedEmail = Field(..., description="Layer 4 classified email")
    enrichment: EnrichmentData = Field(default_factory=EnrichmentData, description="External threat intelligence enrichment")


# ------------------------------------------------------------------------------
# Layer 6: Graph Correlation & Campaign Detection Schemas
# ------------------------------------------------------------------------------

class CorrelationData(BaseModel):
    """Graph topology and attack campaign relationship insights from Neo4j."""
    campaign_id: Optional[str] = Field(None, description="Identified attack campaign identifier")
    campaign_name: Optional[str] = Field(None, description="Human-readable campaign cluster label")
    is_part_of_campaign: bool = Field(default=False, description="Whether this email links to other ingested threats")
    shared_ioc_count: int = Field(default=0, description="Count of overlapping IOCs with other emails")
    related_email_ids: List[str] = Field(default_factory=list, description="Other email UUIDs sharing infrastructure in Neo4j")
    graph_nodes_merged: int = Field(default=0, description="Total nodes created/merged in the Neo4j threat graph")
    correlated_at: datetime = Field(default_factory=datetime.utcnow)


class CorrelatedEmail(BaseModel):
    """Final canonical report combining email data, analysis, scoring, intel, and graph correlation."""
    email_id: str = Field(..., description="Unique UUID of the email")
    enriched_email: EnrichedEmail = Field(..., description="Layer 5 enriched email payload")
    correlation: CorrelationData = Field(default_factory=CorrelationData, description="Layer 6 graph correlation analysis")
    finalized_at: datetime = Field(default_factory=datetime.utcnow)


