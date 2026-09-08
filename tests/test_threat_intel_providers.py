"""Tests for live AbuseIPDB enrichment and its fallback to the simulated dataset."""

import pytest

from netra_common.models.email import IOCItem
from services.threat_intel.src.abuseipdb import AbuseIPDBClient, is_publicly_routable
from services.threat_intel.src.provider import CompositeIntelProvider, MockIntelProvider


# ----------------------------------------------------------------- test doubles

class StubClient:
    """Stands in for AbuseIPDBClient with scripted answers."""

    def __init__(self, answers=None, available=True):
        self.answers = answers or {}
        self.available = available
        self.quota_remaining = 900
        self.calls = []

    def check_ip(self, ip):
        if not self.available:
            raise AssertionError("check_ip must not be called while unavailable")
        self.calls.append(ip)
        return self.answers.get(ip)


def live_verdict(is_malicious, score, cached=False):
    return {
        "is_malicious": is_malicious,
        "threat_score": score,
        "threat_names": [f"AbuseIPDB confidence {score}%"],
        "details": {"source": "AbuseIPDB live API", "abuse_confidence_score": score},
        "cached": cached,
    }


# --------------------------------------------------------------- routing gate

@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "172.16.4.4", "127.0.0.1",
                                "169.254.10.1", "0.0.0.0", "224.0.0.1", "not-an-ip", ""])
def test_non_routable_addresses_never_reach_the_api(ip):
    """Quota is finite; addresses that cannot have public reports must be filtered out."""
    assert is_publicly_routable(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "45.154.255.89", "185.220.101.5"])
def test_public_addresses_are_routable(ip):
    assert is_publicly_routable(ip) is True


def test_client_skips_lookup_for_private_addresses():
    client = AbuseIPDBClient(redis_client=None)
    client.enabled = True
    client.suspended_reason = None
    assert client.check_ip("192.168.1.10") is None


def test_client_returns_none_when_disabled():
    client = AbuseIPDBClient(redis_client=None)
    client.enabled = False
    assert client.check_ip("8.8.8.8") is None


def test_normalise_maps_abuseipdb_response_onto_netra_shape():
    verdict = AbuseIPDBClient._normalise("185.220.101.5", {
        "abuseConfidenceScore": 100,
        "totalReports": 264,
        "countryCode": "DE",
        "isp": "Example Hosting",
        "usageType": "Data Center/Web Hosting/Transit",
        "isTor": True,
    })

    assert verdict["is_malicious"] is True
    assert verdict["threat_score"] == 100
    assert verdict["details"]["total_reports"] == 264
    assert verdict["details"]["country"] == "DE"
    assert "Tor exit node" in verdict["threat_names"]


def test_normalise_clamps_score_into_range():
    verdict = AbuseIPDBClient._normalise("1.2.3.4", {"abuseConfidenceScore": 5000})
    assert 0 <= verdict["threat_score"] <= 100


# --------------------------------------------------------- composite provider

def test_live_verdict_replaces_the_simulated_one_for_ips():
    client = StubClient({"198.51.100.42": live_verdict(True, 97)})
    provider = CompositeIntelProvider(client, MockIntelProvider())

    result = provider.enrich_iocs([IOCItem(type="ip", value="198.51.100.42", context="Hop IP")])
    ip_item = result.enriched_iocs[0]

    assert ip_item.provider == "AbuseIPDB (live)"
    assert ip_item.threat_score == 97
    assert "AbuseIPDB (live)" in result.enrichment_sources
    assert "AbuseIPDB" not in result.enrichment_sources


def test_live_data_may_clear_an_ip_the_mock_flagged():
    """A live feed that disagrees with the local dataset must win, and be recounted."""
    client = StubClient({"198.51.100.42": live_verdict(False, 0)})
    provider = CompositeIntelProvider(client, MockIntelProvider())

    result = provider.enrich_iocs([IOCItem(type="ip", value="198.51.100.42", context="Hop IP")])

    assert result.enriched_iocs[0].is_malicious is False
    assert result.malicious_iocs_found == 0


def test_unanswered_ip_falls_back_to_the_simulated_verdict():
    """None means 'no live data', never 'clean' — the mock verdict must survive."""
    client = StubClient({})  # every lookup returns None
    provider = CompositeIntelProvider(client, MockIntelProvider())

    result = provider.enrich_iocs([IOCItem(type="ip", value="198.51.100.42", context="Hop IP")])
    item = result.enriched_iocs[0]

    assert item.is_malicious is True
    assert item.provider.endswith("(simulated)")


def test_suspended_client_is_never_called():
    client = StubClient({}, available=False)
    provider = CompositeIntelProvider(client, MockIntelProvider())

    result = provider.enrich_iocs([IOCItem(type="ip", value="198.51.100.42", context="Hop IP")])

    assert client.calls == []
    assert result.enriched_iocs[0].provider.endswith("(simulated)")


def test_non_ip_indicators_are_not_sent_to_abuseipdb():
    """AbuseIPDB only covers IPs; domains and hashes must not consume quota."""
    client = StubClient({})
    provider = CompositeIntelProvider(client, MockIntelProvider())

    provider.enrich_iocs([
        IOCItem(type="domain", value="micros0ft.com", context="Phishing domain"),
        IOCItem(type="sha256", value="a" * 64, context="attachment"),
    ])

    assert client.calls == []


def test_mixed_indicators_are_labelled_by_their_actual_source():
    client = StubClient({"198.51.100.42": live_verdict(True, 88)})
    provider = CompositeIntelProvider(client, MockIntelProvider())

    result = provider.enrich_iocs([
        IOCItem(type="ip", value="198.51.100.42", context="Hop IP"),
        IOCItem(type="domain", value="micros0ft.com", context="Phishing domain"),
    ])

    by_type = {i.type: i for i in result.enriched_iocs}
    assert by_type["ip"].provider == "AbuseIPDB (live)"
    assert by_type["domain"].provider.endswith("(simulated)")


def test_mock_provider_labels_every_verdict_as_simulated():
    """A reader must never mistake the local dataset for real threat intelligence."""
    result = MockIntelProvider().enrich_iocs([
        IOCItem(type="ip", value="198.51.100.42", context="Hop IP"),
        IOCItem(type="domain", value="micros0ft.com", context="Phishing domain"),
        IOCItem(type="sha256", value="b" * 64, context="exe payload"),
    ])

    for item in result.enriched_iocs:
        assert item.provider.endswith("(simulated)"), f"{item.value} not labelled: {item.provider}"


def test_enrichment_sources_lists_only_feeds_that_answered():
    """Listing every feed regardless of result would overstate the enrichment."""
    result = MockIntelProvider().enrich_iocs([
        IOCItem(type="ip", value="8.8.8.8", context="Benign DNS"),
    ])
    assert result.enrichment_sources == []
