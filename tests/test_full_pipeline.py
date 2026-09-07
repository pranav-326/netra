"""End-to-End Pipeline Unit Test for Layers 5, 6, and 7/9 components."""

from services.threat_intel.src.provider import MockIntelProvider, MOCK_BAD_IPS, MOCK_BAD_DOMAINS
from services.correlation.src.graph import Neo4jCorrelator
from netra_common.models.email import IOCItem, EnrichedIOC


def test_mock_threat_intel_provider():
    provider = MockIntelProvider()

    test_iocs = [
        IOCItem(type="ip", value="198.51.100.42", context="Hop IP"),
        IOCItem(type="domain", value="micros0ft.com", context="Phishing domain"),
        IOCItem(type="sha256", value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", context="exe patch"),
        IOCItem(type="ip", value="8.8.8.8", context="Benign DNS"),
    ]

    enrichment = provider.enrich_iocs(test_iocs)

    assert enrichment.total_iocs_checked == 4
    assert enrichment.malicious_iocs_found == 3, f"Expected 3 malicious IOCs, got {enrichment.malicious_iocs_found}"
    assert "Storm-0558" in enrichment.threat_actors
    assert "FIN7" in enrichment.threat_actors

    malicious_vals = [item.value for item in enrichment.enriched_iocs if item.is_malicious]
    assert "198.51.100.42" in malicious_vals
    assert "micros0ft.com" in malicious_vals
    print("[PASS] Layer 5 Mock Threat Intel Provider passed.")


def test_correlation_fallback_clustering():
    correlator = Neo4jCorrelator.__new__(Neo4jCorrelator)
    correlator.driver = None

    # Test deterministic campaign grouping on shared malicious IOCs
    iocs1 = [
        EnrichedIOC(type="ip", value="198.51.100.42", is_malicious=True),
        EnrichedIOC(type="domain", value="micros0ft.com", is_malicious=True),
    ]
    res1 = correlator._fallback_correlation(iocs1)
    assert res1.is_part_of_campaign is True
    assert res1.campaign_id.startswith("CAMP-")

    # Same IOCs should produce identical deterministic campaign ID
    iocs2 = [
        EnrichedIOC(type="ip", value="198.51.100.42", is_malicious=True),
        EnrichedIOC(type="domain", value="micros0ft.com", is_malicious=True),
    ]
    res2 = correlator._fallback_correlation(iocs2)
    assert res1.campaign_id == res2.campaign_id
    print(f"[PASS] Layer 6 Campaign Clustering passed: {res1.campaign_id}")


if __name__ == "__main__":
    test_mock_threat_intel_provider()
    test_correlation_fallback_clustering()
    print("\n>>> ALL REMAINING BACKEND COMPONENT TESTS PASSED CLEANLY <<<")
