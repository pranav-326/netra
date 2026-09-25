"""Tests for link-shortener resolution and its URL-SHORTENER scoring rule.

Every test injects a fake fetcher, so nothing here touches the network.
"""

import pytest

from netra_common.models.email import AnalysisResults, HeaderAnalysisResult
from services.analyzer.src.engines.shortener import (
    MAX_HOPS,
    ShortenerResolver,
    fetch_redirect_target,
    is_shortener,
)
from services.analyzer.src.engines.url_engine import analyze_urls
from services.threat_engine.src.scorer import evaluate_threat_score


class FakeShortener:
    """Maps short URLs to redirect targets and records every lookup."""

    def __init__(self, redirects=None, fail_on=()):
        self.redirects = redirects or {}
        self.fail_on = set(fail_on)
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        if url in self.fail_on:
            raise TimeoutError("simulated timeout")
        return self.redirects.get(url)


def resolver_for(redirects=None, fail_on=()):
    fake = FakeShortener(redirects, fail_on)
    return ShortenerResolver(fetch=fake), fake


def score(url_analysis):
    analysis = AnalysisResults(
        header_analysis=HeaderAnalysisResult(
            spf_verdict="pass", dkim_verdict="pass", dmarc_verdict="pass",
            has_authentication_results=True,
        ),
        url_analysis=url_analysis,
    )
    return evaluate_threat_score(analysis)


def test_tinyurl_destination_is_analysed_like_a_direct_link():
    resolver, _ = resolver_for({
        "https://tinyurl.com/abc123": "https://micros0ft.com/account-verification/login.php",
    })

    result = analyze_urls(["https://tinyurl.com/abc123"], resolver=resolver)

    assert len(result.shortened_urls) == 1
    link = result.shortened_urls[0]
    assert link.resolved
    assert link.final_url == "https://micros0ft.com/account-verification/login.php"
    assert [t.target_brand for t in result.typosquat_detections] == ["microsoft.com"]
    assert {"tinyurl.com", "micros0ft.com"} <= set(result.root_domains)


def test_shortened_typosquat_scores_shortener_plus_typosquat():
    resolver, _ = resolver_for({"https://tinyurl.com/abc123": "https://micros0ft.com/login"})

    final, _, _, contributions, raw = score(
        analyze_urls(["https://tinyurl.com/abc123"], resolver=resolver)
    )

    points = {c.rule_id: c.points for c in contributions}
    assert points == {"URL-SHORTENER": 5, "URL-TYPOSQUAT": 40}
    assert final == raw == 45
    shortener = next(c for c in contributions if c.rule_id == "URL-SHORTENER")
    assert shortener.evidence == "https://tinyurl.com/abc123 -> https://micros0ft.com/login"


def test_shortener_to_benign_site_scores_only_five():
    resolver, _ = resolver_for({"https://bit.ly/docs": "https://docs.google.com/document/d/1"})

    final, _, _, contributions, _ = score(analyze_urls(["https://bit.ly/docs"], resolver=resolver))

    assert [(c.rule_id, c.points) for c in contributions] == [("URL-SHORTENER", 5)]
    assert final == 5


def test_nested_shorteners_are_followed_to_the_end():
    resolver, _ = resolver_for({
        "https://bit.ly/a": "https://tinyurl.com/b",
        "https://tinyurl.com/b": "https://is.gd/c",
        "https://is.gd/c": "https://paypa1.com/signin",
    })

    link = analyze_urls(["https://bit.ly/a"], resolver=resolver).shortened_urls[0]

    assert link.resolved
    assert link.chain == [
        "https://bit.ly/a", "https://tinyurl.com/b", "https://is.gd/c", "https://paypa1.com/signin",
    ]


def test_resolution_stops_after_max_hops():
    looping = {"https://tinyurl.com/loop": "https://tinyurl.com/loop"}
    resolver, fake = resolver_for(looping)

    link = analyze_urls(["https://tinyurl.com/loop"], resolver=resolver).shortened_urls[0]

    assert not link.resolved
    assert link.final_url is None
    assert "nested" in link.failure_reason
    assert len(fake.calls) == MAX_HOPS


def test_network_failure_is_unresolved_not_clean_and_is_retried():
    resolver, fake = resolver_for(fail_on={"https://tinyurl.com/down"})

    result = analyze_urls(["https://tinyurl.com/down"], resolver=resolver)
    link = result.shortened_urls[0]
    assert not link.resolved
    assert "lookup failed" in link.failure_reason

    final, _, _, contributions, _ = score(result)
    assert [c.rule_id for c in contributions] == ["URL-SHORTENER"]
    assert "unresolved" in contributions[0].evidence

    analyze_urls(["https://tinyurl.com/down"], resolver=resolver)
    assert len(fake.calls) == 2


def test_expired_link_is_unresolved():
    resolver, _ = resolver_for({})

    link = analyze_urls(["https://tinyurl.com/gone"], resolver=resolver).shortened_urls[0]

    assert not link.resolved
    assert "expired" in link.failure_reason


def test_successful_resolutions_are_cached():
    resolver, fake = resolver_for({"https://tinyurl.com/abc": "https://example.org/"})

    analyze_urls(["https://tinyurl.com/abc"], resolver=resolver)
    analyze_urls(["https://tinyurl.com/abc"], resolver=resolver)

    assert fake.calls == ["https://tinyurl.com/abc"]


def test_shortener_hiding_a_raw_ip_trips_the_ip_rule():
    resolver, _ = resolver_for({"https://tinyurl.com/ip": "http://198.51.100.42/login"})

    result = analyze_urls(["https://tinyurl.com/ip"], resolver=resolver)

    assert result.ip_host_urls == ["http://198.51.100.42/login"]


def test_defanged_short_link_is_still_resolved():
    resolver, fake = resolver_for({"https://tinyurl.com/x": "https://example.org/"})

    result = analyze_urls(["hxxps://tinyurl[.]com/x"], resolver=resolver)

    assert fake.calls == ["https://tinyurl.com/x"]
    assert result.shortened_urls[0].original_url == "hxxps://tinyurl[.]com/x"
    assert result.defanged_urls == ["hxxps://tinyurl[.]com/x"]


def test_ordinary_links_never_trigger_a_lookup():
    resolver, fake = resolver_for({})

    result = analyze_urls(["https://example.org/page", "https://github.com/"], resolver=resolver)

    assert fake.calls == []
    assert result.shortened_urls == []


def test_resolver_none_skips_resolution():
    result = analyze_urls(["https://tinyurl.com/abc"], resolver=None)

    assert result.shortened_urls == []


@pytest.mark.parametrize("host,expected", [
    ("tinyurl.com", True),
    ("www.TinyURL.com", True),
    ("bit.ly", True),
    ("tinyurl.com.evil.net", False),
    ("nottinyurl.com", False),
    (None, False),
])
def test_is_shortener(host, expected):
    assert is_shortener(host) is expected


def test_fetcher_refuses_to_contact_non_shortener_hosts():
    with pytest.raises(ValueError):
        fetch_redirect_target("https://attacker.example/phish")
