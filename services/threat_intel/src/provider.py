"""Threat Intelligence Providers (Layer 5).

Two providers share one interface:

* `MockIntelProvider` — a curated local dataset simulating VirusTotal / AbuseIPDB /
  URLhaus / MISP. Every verdict it produces is labelled `(simulated)` so a live result
  can never be mistaken for a mocked one.
* `CompositeIntelProvider` — routes IP indicators to the live AbuseIPDB API and
  delegates everything else, plus any IP the live API could not answer, to the mock.

The composite is the default when an API key is configured; the mock is the fallback,
and the pipeline is unaffected either way.
"""

import logging
from typing import List, Dict, Any, Set

from netra_common.config import settings
from netra_common.models.email import IOCItem, EnrichedIOC, EnrichmentData
from .abuseipdb import AbuseIPDBClient

logger = logging.getLogger("netra.threat_intel.provider")

# Mock external intelligence database of known threats
MOCK_BAD_IPS: Dict[str, Dict[str, Any]] = {
    "198.51.100.42": {
        "score": 98,
        "provider": "AbuseIPDB",
        "threat_names": ["Bulletproof Phishing Host", "Credential Relay"],
        "threat_actor": "Storm-0558",
        "details": {
            "abuse_confidence_score": 98,
            "total_reports": 1420,
            "country": "RU",
            "usage_type": "Data Center / Web Hosting / Transit"
        }
    },
    "198.51.100.25": {
        "score": 92,
        "provider": "AbuseIPDB",
        "threat_names": ["BEC Infrastructure", "FastFlux C2"],
        "threat_actor": "FIN7",
        "details": {
            "abuse_confidence_score": 92,
            "total_reports": 854,
            "country": "SC",
            "usage_type": "Commercial Proxy"
        }
    },
    "203.0.113.195": {
        "score": 85,
        "provider": "AbuseIPDB",
        "threat_names": ["C2 Drop Point", "CobaltStrike Beacon"],
        "threat_actor": "APT29 / Nobelium",
        "details": {
            "abuse_confidence_score": 85,
            "total_reports": 312,
            "country": "NL",
            "usage_type": "VPN Gateway"
        }
    }
}

MOCK_BAD_DOMAINS: Dict[str, Dict[str, Any]] = {
    "micros0ft.com": {
        "score": 95,
        "provider": "VirusTotal",
        "threat_names": ["Phishing.O365.Impersonation", "CredentialHarvesting"],
        "threat_actor": "Storm-0558",
        "details": {"vt_positives": 52, "vt_total": 72, "registrar": "NameCheap Inc."}
    },
    "micros0ft-portal.com": {
        "score": 96,
        "provider": "VirusTotal",
        "threat_names": ["Phishing.Microsoft.Typosquat", "Malicious Landing Page"],
        "threat_actor": "Storm-0558",
        "details": {"vt_positives": 48, "vt_total": 72, "category": "phishing"}
    },
    "micros0ft-support.com": {
        "score": 94,
        "provider": "URLhaus",
        "threat_names": ["Phishing.SupportScam", "AccountTakeover"],
        "threat_actor": "Storm-0558",
        "details": {"urlhaus_status": "active", "threat": "phishing"}
    },
    "evil-portal.net": {
        "score": 90,
        "provider": "URLhaus",
        "threat_names": ["Malware Distribution", "AgentTesla C2"],
        "threat_actor": "FIN7",
        "details": {"urlhaus_status": "active", "threat": "malware_download"}
    },
    "external-mail.net": {
        "score": 75,
        "provider": "AbuseIPDB",
        "threat_names": ["Disposible Mail Relay", "BEC Phishing Campaign"],
        "threat_actor": "FIN7",
        "details": {"reports": 412, "reputation": "suspicious"}
    }
}


class MockIntelProvider:
    """Mock external threat intelligence provider simulating multi-feed enrichment."""

    def enrich_iocs(self, iocs: List[IOCItem]) -> EnrichmentData:
        """Enrich a list of IOC items using simulated threat feeds."""
        enriched_items: List[EnrichedIOC] = []
        threat_actors: Set[str] = set()
        malicious_count = 0
        # Populated as verdicts are produced. Reporting feeds that returned nothing
        # would overstate how much enrichment actually happened.
        sources_used: Set[str] = set()

        for ioc in iocs:
            val = ioc.value.lower().strip()
            ioc_type = ioc.type.lower()
            is_malicious = False
            threat_score = 0
            provider = "Internal Feeds (simulated)"
            threat_names = []
            details = {}

            # 1. IP Lookup
            if ioc_type == "ip":
                if val in MOCK_BAD_IPS:
                    intel = MOCK_BAD_IPS[val]
                    is_malicious = True
                    threat_score = intel["score"]
                    provider = f"{intel['provider']} (simulated)"
                    threat_names = intel["threat_names"]
                    details = intel["details"]
                    sources_used.add(intel["provider"])
                    if "threat_actor" in intel:
                        threat_actors.add(intel["threat_actor"])
                elif val.startswith("198.51.") or val.startswith("203.0."):
                    # Simulated dynamic feed hit for test subnets
                    is_malicious = True
                    threat_score = 80
                    provider = "AbuseIPDB (simulated)"
                    sources_used.add("AbuseIPDB")
                    threat_names = ["Suspicious Subnet Relay"]
                    details = {"abuse_confidence_score": 80, "reports": 115}

            # 2. Domain / URL Lookup
            elif ioc_type in ("domain", "url"):
                matched_domain = None
                for bad_d in MOCK_BAD_DOMAINS:
                    if bad_d in val:
                        matched_domain = bad_d
                        break

                if matched_domain:
                    intel = MOCK_BAD_DOMAINS[matched_domain]
                    is_malicious = True
                    threat_score = intel["score"]
                    provider = f"{intel['provider']} (simulated)"
                    threat_names = intel["threat_names"]
                    details = intel["details"]
                    sources_used.add(intel["provider"])
                    if "threat_actor" in intel:
                        threat_actors.add(intel["threat_actor"])
                elif "micros0ft" in val or "paypal" in val or "phish" in val:
                    is_malicious = True
                    threat_score = 85
                    provider = "VirusTotal (simulated)"
                    sources_used.add("VirusTotal")
                    threat_names = ["Heuristic.Typosquat.Phish"]
                    details = {"vt_positives": 35, "vt_total": 72}

            # 3. File Hash Lookup
            elif ioc_type in ("sha256", "md5"):
                # Simulate VirusTotal hit on test sample hashes or executables
                if "patch" in ioc.context.lower() or "exe" in ioc.context.lower() or len(val) == 64:
                    is_malicious = True
                    threat_score = 99
                    provider = "VirusTotal (simulated)"
                    sources_used.add("VirusTotal")
                    threat_names = ["Trojan.Win32.AgentTesla", "CobaltStrike.Stager"]
                    threat_actors.add("FIN7")
                    details = {
                        "vt_positives": 58,
                        "vt_total": 72,
                        "first_seen": "2026-08-15T09:00:00Z",
                        "malware_family": "AgentTesla",
                    }

            if is_malicious:
                malicious_count += 1

            enriched_items.append(
                EnrichedIOC(
                    type=ioc.type,
                    value=ioc.value,
                    context=ioc.context,
                    is_malicious=is_malicious,
                    threat_score=threat_score,
                    provider=provider,
                    threat_names=threat_names,
                    details=details,
                )
            )

        return EnrichmentData(
            total_iocs_checked=len(iocs),
            malicious_iocs_found=malicious_count,
            threat_actors=sorted(list(threat_actors)),
            enriched_iocs=enriched_items,
            enrichment_sources=sorted(list(sources_used)),
        )


class CompositeIntelProvider:
    """Live-first provider: AbuseIPDB for IPs, the mock dataset for everything else.

    Falls back per-indicator rather than per-request. If AbuseIPDB answers for two of
    three IPs, those two carry live verdicts and the third carries a mock verdict — the
    `provider` label on each `EnrichedIOC` says which, so a reader can always tell real
    intelligence from simulated.
    """

    def __init__(self, client: "AbuseIPDBClient", fallback: "MockIntelProvider" = None):
        self.client = client
        self.fallback = fallback or MockIntelProvider()

    def enrich_iocs(self, iocs: List[IOCItem]) -> EnrichmentData:
        # Start from the mock enrichment so non-IP indicators and unanswered IPs keep
        # their existing behaviour, then overwrite IPs the live API could answer.
        enrichment = self.fallback.enrich_iocs(iocs)

        if not self.client.available:
            return enrichment

        live_hits = 0
        cache_hits = 0
        upgraded: List[EnrichedIOC] = []

        for item in enrichment.enriched_iocs:
            if item.type.lower() != "ip":
                upgraded.append(item)
                continue

            verdict = self.client.check_ip(item.value)
            if verdict is None:
                # No live answer: keep the mock verdict, already labelled (simulated).
                upgraded.append(item)
                continue

            live_hits += 1
            if verdict.get("cached"):
                cache_hits += 1

            details = dict(verdict["details"])
            details["cached"] = bool(verdict.get("cached"))

            upgraded.append(
                EnrichedIOC(
                    type=item.type,
                    value=item.value,
                    context=item.context,
                    is_malicious=verdict["is_malicious"],
                    threat_score=verdict["threat_score"],
                    provider="AbuseIPDB (live)",
                    threat_names=verdict["threat_names"],
                    details=details,
                )
            )

        if live_hits == 0:
            return enrichment

        # Recount from the upgraded list — a live verdict can clear an IP the mock
        # flagged, or flag one the mock considered clean.
        malicious_count = sum(1 for i in upgraded if i.is_malicious)

        sources = set(enrichment.enrichment_sources)
        # The simulated AbuseIPDB label is no longer accurate once live data is present.
        sources.discard("AbuseIPDB")
        sources.add("AbuseIPDB (live)")

        logger.info(
            f"AbuseIPDB enriched {live_hits} IP indicator(s) "
            f"({cache_hits} from cache, {live_hits - cache_hits} live API calls). "
            f"Quota remaining: {self.client.quota_remaining if self.client.quota_remaining is not None else 'unknown'}"
        )

        return EnrichmentData(
            total_iocs_checked=enrichment.total_iocs_checked,
            malicious_iocs_found=malicious_count,
            threat_actors=enrichment.threat_actors,
            enriched_iocs=upgraded,
            enrichment_sources=sorted(sources),
        )


def build_intel_provider(redis_client: Any = None):
    """Select the provider for this deployment.

    Returns the composite provider when an AbuseIPDB key is configured, otherwise the
    mock. Callers do not branch on this — both satisfy the same `enrich_iocs` contract.
    """
    if settings.abuseipdb_active:
        return CompositeIntelProvider(AbuseIPDBClient(redis_client=redis_client))

    logger.info("No AbuseIPDB key configured; Layer 5 running on the simulated dataset only.")
    return MockIntelProvider()
