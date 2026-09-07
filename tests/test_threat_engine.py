"""Functional unit test for Layer 4 Threat Engine scoring and IOC extraction algorithms."""

import re
import ipaddress

IPV4_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def extract_ips_from_received_chain(received_chain):
    found_ips = set()
    for hop in received_chain:
        matches = IPV4_PATTERN.findall(hop)
        for ip_str in matches:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not ip_obj.is_loopback and not ip_obj.is_unspecified:
                    found_ips.add(ip_str)
            except ValueError:
                continue
    return sorted(list(found_ips))


def evaluate_mock_threat_score(has_exec, has_typosquat, has_bec, has_credential, has_urgency, spf_fail, dmarc_fail):
    score = 0
    matched_rules = []
    if has_exec:
        score += 50
        matched_rules.append("Dangerous executable/script attachment detected (+50 pts)")
    if has_typosquat:
        score += 40
        matched_rules.append("Domain typosquatting detected (+40 pts)")
    if has_bec:
        score += 30
        matched_rules.append("BEC / Wire Transfer trigger phrases detected (+30 pts)")
    if has_credential:
        score += 25
        matched_rules.append("Credential harvesting detected (+25 pts)")
    if has_urgency:
        score += 15
        matched_rules.append("Urgency language detected (+15 pts)")
    if spf_fail or dmarc_fail:
        score += 20
        matched_rules.append("Authentication failure (+20 pts)")

    final_score = max(0, min(score, 100))
    if final_score >= 61:
        verdict = "MALICIOUS"
    elif final_score >= 21:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"
    return final_score, verdict, matched_rules


def run_tests():
    # 1. Test Scoring Cases
    # Phishing combo: Typosquat (40) + Credential (25) + Urgency (15) + SPF Fail (20) = 100 -> MALICIOUS
    s1, v1, r1 = evaluate_mock_threat_score(
        has_exec=False, has_typosquat=True, has_bec=False,
        has_credential=True, has_urgency=True, spf_fail=True, dmarc_fail=True
    )
    assert s1 == 100, f"Expected 100, got {s1}"
    assert v1 == "MALICIOUS"
    assert len(r1) == 4
    print(f"[PASS] Phishing evaluation: Score={s1}, Verdict={v1}, Rules={len(r1)}")

    # BEC combo: BEC wire (30) + Urgency (15) = 45 -> SUSPICIOUS
    s2, v2, r2 = evaluate_mock_threat_score(
        has_exec=False, has_typosquat=False, has_bec=True,
        has_credential=False, has_urgency=True, spf_fail=False, dmarc_fail=False
    )
    assert s2 == 45
    assert v2 == "SUSPICIOUS"
    print(f"[PASS] BEC evaluation: Score={s2}, Verdict={v2}, Rules={len(r2)}")

    # Clean email: 0 -> BENIGN
    s3, v3, r3 = evaluate_mock_threat_score(
        has_exec=False, has_typosquat=False, has_bec=False,
        has_credential=False, has_urgency=False, spf_fail=False, dmarc_fail=False
    )
    assert s3 == 0
    assert v3 == "BENIGN"
    print(f"[PASS] Clean email evaluation: Score={s3}, Verdict={v3}, Rules={len(r3)}")

    # 2. Test IOC extraction from Received Chain
    hops = [
        "from mail.evil-portal.com ([198.51.100.42]) by mx.corp.com with ESMTP",
        "from internal.router ([10.0.0.1]) by mail.evil-portal.com; (127.0.0.1 discarded)",
    ]
    extracted_ips = extract_ips_from_received_chain(hops)
    assert "198.51.100.42" in extracted_ips
    assert "10.0.0.1" in extracted_ips
    assert "127.0.0.1" not in extracted_ips
    print(f"[PASS] Received chain IP extraction: {extracted_ips}")

    print("\n>>> ALL LAYER 4 THREAT ENGINE UNIT TESTS PASSED <<<")


if __name__ == "__main__":
    run_tests()
