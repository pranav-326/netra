"""Mock Threat Intelligence Provider (Layer 5)
Simulates external threat feeds (VirusTotal, AbuseIPDB, URLhaus, MISP) against
Layer 4 IOCs to enrich data with reputation scores, malware tags, and threat actor attribution.
"""

from typing import List, Dict, Any, Set
from netra_common.models.email import IOCItem, EnrichedIOC, EnrichmentData

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
        sources_used = {"AbuseIPDB", "VirusTotal", "URLhaus", "MISP"}

        for ioc in iocs:
            val = ioc.value.lower().strip()
            ioc_type = ioc.type.lower()
            is_malicious = False
            threat_score = 0
            provider = "Internal Feeds"
            threat_names = []
            details = {}

            # 1. IP Lookup
            if ioc_type == "ip":
                if val in MOCK_BAD_IPS:
                    intel = MOCK_BAD_IPS[val]
                    is_malicious = True
                    threat_score = intel["score"]
                    provider = intel["provider"]
                    threat_names = intel["threat_names"]
                    details = intel["details"]
                    if "threat_actor" in intel:
                        threat_actors.add(intel["threat_actor"])
                elif val.startswith("198.51.") or val.startswith("203.0."):
                    # Simulated dynamic feed hit for test subnets
                    is_malicious = True
                    threat_score = 80
                    provider = "AbuseIPDB"
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
                    provider = intel["provider"]
                    threat_names = intel["threat_names"]
                    details = intel["details"]
                    if "threat_actor" in intel:
                        threat_actors.add(intel["threat_actor"])
                elif "micros0ft" in val or "paypal" in val or "phish" in val:
                    is_malicious = True
                    threat_score = 85
                    provider = "VirusTotal"
                    threat_names = ["Heuristic.Typosquat.Phish"]
                    details = {"vt_positives": 35, "vt_total": 72}

            # 3. File Hash Lookup
            elif ioc_type in ("sha256", "md5"):
                # Simulate VirusTotal hit on test sample hashes or executables
                if "patch" in ioc.context.lower() or "exe" in ioc.context.lower() or len(val) == 64:
                    is_malicious = True
                    threat_score = 99
                    provider = "VirusTotal"
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
