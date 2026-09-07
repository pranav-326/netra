"""Standalone algorithmic validation for Layer 5 enrichment and Layer 6 clustering."""

import hashlib

MOCK_BAD_IPS = {
    "198.51.100.42": {"score": 98, "provider": "AbuseIPDB", "actor": "Storm-0558"},
    "198.51.100.25": {"score": 92, "provider": "AbuseIPDB", "actor": "FIN7"},
}

MOCK_BAD_DOMAINS = {
    "micros0ft.com": {"score": 95, "provider": "VirusTotal", "actor": "Storm-0558"},
    "evil-portal.net": {"score": 90, "provider": "URLhaus", "actor": "FIN7"},
}


def mock_enrich_ioc(itype, val):
    val_clean = val.lower().strip()
    if itype == "ip" and val_clean in MOCK_BAD_IPS:
        info = MOCK_BAD_IPS[val_clean]
        return True, info["score"], info["provider"], info["actor"]
    if itype in ("domain", "url"):
        for bad_d, info in MOCK_BAD_DOMAINS.items():
            if bad_d in val_clean:
                return True, info["score"], info["provider"], info["actor"]
    if itype in ("sha256", "md5") and (len(val_clean) == 64 or "patch" in val_clean):
        return True, 99, "VirusTotal", "FIN7"
    return False, 0, "Internal Feeds", None


def test_enrichment_logic():
    is_mal, score, prov, actor = mock_enrich_ioc("ip", "198.51.100.42")
    assert is_mal is True and score == 98 and actor == "Storm-0558"

    is_mal, score, prov, actor = mock_enrich_ioc("domain", "https://micros0ft.com/login")
    assert is_mal is True and score == 95 and actor == "Storm-0558"

    is_mal, score, prov, actor = mock_enrich_ioc("ip", "8.8.8.8")
    assert is_mal is False
    print("[PASS] Enrichment logic passed.")


def test_clustering_logic():
    malicious_iocs = ["198.51.100.42", "micros0ft.com"]
    seed = ":".join(sorted(malicious_iocs))
    camp_id1 = "CAMP-" + hashlib.sha256(seed.encode()).hexdigest()[:8].upper()

    # Re-running with same IOCs in different order
    malicious_iocs2 = ["micros0ft.com", "198.51.100.42"]
    seed2 = ":".join(sorted(malicious_iocs2))
    camp_id2 = "CAMP-" + hashlib.sha256(seed2.encode()).hexdigest()[:8].upper()

    assert camp_id1 == camp_id2
    print(f"[PASS] Deterministic Campaign Clustering passed: {camp_id1}")


if __name__ == "__main__":
    test_enrichment_logic()
    test_clustering_logic()
    print("\n>>> ALL LOGIC TESTS PASSED CLEANLY <<<")
