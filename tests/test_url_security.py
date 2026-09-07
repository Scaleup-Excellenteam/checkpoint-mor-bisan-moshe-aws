"""Focused tests for url_security (Person 3).

Every provider call is served by an in-process ``httpx.MockTransport``; an
autouse guard makes any real network attempt fail the test. No test needs
internet access or consumes VirusTotal quota.
"""
import threading
import time

import httpx
import pytest

from chat_system import url_security as us
from chat_system.security_contracts import SecurityDecision


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def forbidden(self, request):
        raise AssertionError(f"real network request attempted: {request.url.host}")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)


def _stats(malicious=0, suspicious=0, harmless=0, undetected=0, age_seconds=0):
    return httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                "harmless": harmless, "undetected": undetected},
        "last_analysis_date": time.time() - age_seconds,
    }}})


def _checker(handler, api_key="test-key"):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return us.VirusTotalURLReputationChecker(api_key=api_key, http_client=client)


def _counting(response_factory):
    calls = []

    def handler(request):
        calls.append(request.url.path.rsplit("/", 1)[-1])
        return response_factory(request)
    return handler, calls


# ---------------------------------------------------------------------------
# URL extraction and normalization (URLExtractor contract)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("plain chat, nothing here", []),
    ("numbers 3.14 and e.g. etc.", []),
    ("see https://Example.com/Path?x=1 now", ["https://example.com/Path?x=1"]),
    ("plain http://example.com", ["http://example.com/"]),
    ("www.Example.COM/page today", ["http://www.example.com/page"]),
    # trailing punctuation
    ("visit https://example.com, then (http://example.net). ok?", ["https://example.com/", "http://example.net/"]),
    ("quoted 'https://example.org/a' and \"https://example.org/b\".", ["https://example.org/a", "https://example.org/b"]),
    # duplicates collapse after normalization
    ("https://dup.com/x and HTTPS://DUP.com/x and https://dup.com:443/x", ["https://dup.com/x"]),
    # unsupported or invalid schemes are not extracted
    ("ftp://files.example.com/x mailto:a@example.com javascript:alert(1) file:///etc/passwd", []),
    ("http:///nohost and http:// and https://", []),
    # normalization: default port dropped, fragment dropped, case folded, empty path -> /
    ("HTTP://Example.COM:80#frag", ["http://example.com/"]),
    ("https://example.com:8443/p", ["https://example.com:8443/p"]),
    ("http://[::1]:8080/x", ["http://[::1]:8080/x"]),
    # IDNA
    ("http://пример.рф/test", ["http://xn--e1afmkfd.xn--p1ai/test"]),
])
def test_extract_urls(text, expected):
    assert us.extract_urls(text) == expected
    assert us.RegexURLExtractor().extract(text) == expected


def test_deceptive_hostname_is_checked_as_itself_not_as_trusted_substring():
    urls = us.extract_urls("login at http://paypal.com.evil.tld/login")
    assert urls == ["http://paypal.com.evil.tld/login"]
    assert us.hostname_of(urls[0]) == "paypal.com.evil.tld"


def test_hostname_in_path_is_not_the_host():
    assert us.hostname_of(us.extract_urls("https://evil.tld/paypal.com/index")[0]) == "evil.tld"


@pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://[::1]/y", "http://8.8.8.8:9000/z",
                                 "http://localhost:8000/", "http://box.local/x", "http://svc.internal/"])
def test_ip_and_internal_hosts_are_not_sent_to_provider(url):
    assert us.hostname_of(us.normalize_url(url)) is None


# Preserved pre-contract helper: bare domains for common TLDs only.
@pytest.mark.parametrize("text,expected", [
    ("bare domain example.org mentioned", ["example.org"]),
    ("file mentions config.yml or node.js", []),
    ("dup https://a.com and www.a.com and bare a.com", ["a.com", "www.a.com"]),
    ("http://127.0.0.1/x and http://myhost.local/y", []),
])
def test_extract_domains_preserved_behavior(text, expected):
    assert us.extract_domains(text) == expected


def test_extract_domains_limit_and_bare_opt_out():
    text = " ".join(f"a{i}.com" for i in range(7))
    assert us.extract_domains(text, limit=3) == ["a0.com", "a1.com", "a2.com"]
    assert us.extract_domains(text, include_bare=False) == []


# ---------------------------------------------------------------------------
# SecurityDecision contract and reason mappings
# ---------------------------------------------------------------------------

def test_check_returns_contract_decision_without_full_url():
    checker = _checker(lambda request: _stats(harmless=10))
    decision = checker.check("https://example.com/reset?token=SECRET123")
    assert isinstance(decision, SecurityDecision)
    assert decision.source == "url_reputation"
    assert 0 <= decision.risk_score <= 100
    assert decision.details["domain"] == "example.com"
    assert "SECRET123" not in repr(decision)  # only the hostname is recorded


@pytest.mark.parametrize("stats,action,reason", [
    (dict(harmless=10), "allow", us.REASON_SAFE),
    (dict(malicious=1, harmless=10), "review", us.REASON_MALICIOUS_REVIEW),
    (dict(malicious=2, harmless=10), "block", us.REASON_MALICIOUS),
    (dict(suspicious=1, harmless=10), "review", us.REASON_SUSPICIOUS),
    (dict(undetected=20), "review", us.REASON_UNKNOWN),
    (dict(harmless=10, age_seconds=999_999_999), "review", us.REASON_UNKNOWN),
])
def test_reputation_mappings(stats, action, reason):
    decision = _checker(lambda request: _stats(**stats)).check("https://domain.com/")
    assert (decision.action, decision.reason_code) == (action, reason)
    if action == "block":
        assert decision.risk_score == 100
    if action == "allow":
        assert decision.risk_score == 0


def test_no_report_404_is_unknown_review():
    decision = _checker(lambda request: httpx.Response(404)).check("https://new.com/")
    assert (decision.action, decision.reason_code) == ("review", us.REASON_UNKNOWN)
    assert decision.details["detail"] == "no_report"


def test_missing_api_key_fails_closed_with_reputation_unavailable():
    handler, calls = _counting(lambda request: _stats(harmless=10))
    decision = _checker(handler, api_key="").check("https://domain.com/")
    assert (decision.action, decision.reason_code) == ("block", "reputation_unavailable")
    assert decision.details["detail"] == "missing_api_key"
    assert calls == []  # never contacted the provider


def test_timeout_and_connection_errors_are_unavailable():
    def timeout(request):
        raise httpx.TimeoutException("timed out", request=request)

    def connect_error(request):
        raise httpx.ConnectError("refused", request=request)

    for handler, detail in ((timeout, "timeout"), (connect_error, "request_error")):
        decision = _checker(handler).check("https://domain.com/")
        assert (decision.action, decision.reason_code) == ("block", "reputation_unavailable")
        assert decision.details["detail"] == detail


@pytest.mark.parametrize("status,detail", [(401, "auth_error_401"), (403, "auth_error_403"),
                                           (500, "http_500"), (503, "http_503")])
def test_http_errors_are_unavailable(status, detail):
    decision = _checker(lambda request: httpx.Response(status)).check("https://domain.com/")
    assert (decision.action, decision.reason_code) == ("block", "reputation_unavailable")
    assert decision.details["detail"] == detail


def test_malformed_provider_json_is_unavailable():
    decision = _checker(lambda request: httpx.Response(200, json={"data": {}})).check("https://d.com/")
    assert decision.reason_code == "reputation_unavailable" and decision.details["detail"] == "invalid_response"


def test_http_429_enters_cooldown_blocking_later_lookups():
    responses = iter([httpx.Response(429), _stats(harmless=10)])
    handler, calls = _counting(lambda request: next(responses))
    checker = _checker(handler)
    first = checker.check("https://a.com/")
    assert first.reason_code == "reputation_unavailable" and first.details["detail"] == "rate_limited_429"
    second = checker.check("https://b.com/")
    assert second.reason_code == "reputation_unavailable" and second.details["detail"] == "rate_limited"
    assert calls == ["a.com"]  # b.com never reached the provider during cooldown


def test_local_rate_budget_blocks_without_calling_provider(monkeypatch):
    monkeypatch.setattr(us, "RATE_LIMIT_PER_MINUTE", 2)
    handler, calls = _counting(lambda request: _stats(harmless=10))
    checker = _checker(handler)
    results = [checker.check(f"https://{d}/") for d in ("a.com", "b.com", "c.com")]
    assert calls == ["a.com", "b.com"]
    assert results[2].reason_code == "reputation_unavailable"


@pytest.mark.parametrize("url", ["http://127.0.0.1/x", "http://[::1]:8080/x", "http://localhost/",
                                 "http://box.local/", "not a url", "ftp://example.com/", "", "http://"])
def test_unsupported_hosts_are_review_and_never_sent(url):
    handler, calls = _counting(lambda request: _stats(harmless=10))
    decision = _checker(handler).check(url)
    assert (decision.action, decision.reason_code) == ("review", us.REASON_HOST_UNSUPPORTED)
    assert calls == []


def test_unexpected_exception_fails_closed():
    def boom(request):
        raise RuntimeError("unexpected")
    decision = _checker(boom).check("https://domain.com/")
    assert decision.reason_code == "reputation_unavailable" and decision.details["detail"] == "internal_error"


def test_network_guard_blocks_real_transport():
    # Default client uses the real HTTPTransport; the autouse guard must stop it,
    # and the checker must fail closed rather than raise.
    checker = us.VirusTotalURLReputationChecker(api_key="k")
    try:
        decision = checker.check("https://example.com/")
    finally:
        checker.close()
    assert decision.reason_code == "reputation_unavailable"


# ---------------------------------------------------------------------------
# Cache and coalescing
# ---------------------------------------------------------------------------

def test_cache_default_is_24_hours():
    assert us.CACHE_TTL_SECONDS == 24 * 3600


def test_cache_hit_miss_and_expiry(monkeypatch):
    monkeypatch.setattr(us, "CACHE_TTL_SECONDS", 0.05)
    handler, calls = _counting(lambda request: _stats(harmless=10))
    checker = _checker(handler)
    first = checker.check("https://cached.com/a")
    second = checker.check("https://cached.com/b")  # same host, different path -> same cache entry
    assert first.details["cache_status"] == "miss" and second.details["cache_status"] == "hit"
    assert len(calls) == 1
    time.sleep(0.1)
    third = checker.check("https://cached.com/a")
    assert third.details["cache_status"] == "miss" and len(calls) == 2


@pytest.mark.parametrize("stats", [dict(harmless=10), dict(malicious=3), dict(undetected=5)])
def test_safe_malicious_and_unknown_verdicts_are_cached(stats):
    handler, calls = _counting(lambda request: _stats(**stats))
    checker = _checker(handler)
    checker.check("https://x.com/")
    checker.check("https://x.com/")
    assert len(calls) == 1


def test_unavailable_is_not_cached_so_next_attempt_retries():
    responses = iter([httpx.Response(500), _stats(harmless=10)])
    handler, calls = _counting(lambda request: next(responses))
    checker = _checker(handler)
    assert checker.check("https://x.com/").reason_code == "reputation_unavailable"
    assert checker.check("https://x.com/").action == "allow"
    assert len(calls) == 2


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(us, "CACHE_MAX_SIZE", 2)
    checker = _checker(lambda request: _stats(harmless=10))
    for d in ("a.com", "b.com", "c.com"):
        checker.check(f"https://{d}/")
    assert list(checker._cache) == ["b.com", "c.com"]


def test_concurrent_lookups_for_same_host_are_coalesced():
    def slow(request):
        time.sleep(0.15)
        return _stats(harmless=10)
    handler, calls = _counting(slow)
    checker = _checker(handler)
    results = []
    threads = [threading.Thread(target=lambda: results.append(checker.check("https://shared.com/")))
               for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert all(r.action == "allow" for r in results)
    assert {r.details["cache_status"] for r in results} >= {"miss", "coalesced"}


# ---------------------------------------------------------------------------
# Message-level aggregation helper
# ---------------------------------------------------------------------------

def test_evaluate_message_without_urls_allows_and_skips_provider():
    handler, calls = _counting(lambda request: _stats(harmless=10))
    decision = _checker(handler).evaluate_message("just chatting, no links")
    assert (decision.action, decision.reason_code) == ("allow", us.REASON_NO_URLS)
    assert calls == []


def test_evaluate_message_multiple_urls_worst_wins():
    def handler(request):
        domain = request.url.path.rsplit("/", 1)[-1]
        return _stats(malicious=3) if domain == "evil.com" else _stats(harmless=10)
    decision = _checker(handler).evaluate_message("see https://good.com and https://evil.com/x")
    assert (decision.action, decision.reason_code) == ("block", us.REASON_MALICIOUS)
    assert decision.details["domain"] == "evil.com"
    assert decision.details["domains"] == ["good.com", "evil.com"]


def test_evaluate_message_too_many_urls_escalates_to_review(monkeypatch):
    monkeypatch.setattr(us, "MAX_URLS_PER_MESSAGE", 2)
    handler, calls = _counting(lambda request: _stats(harmless=10))
    decision = _checker(handler).evaluate_message("https://a.com https://b.com https://c.com")
    assert decision.action == "review" and decision.details["truncated"] is True
    assert calls == ["a.com", "b.com"]


def test_evaluate_message_bare_domains_only_when_opted_in():
    handler, calls = _counting(lambda request: _stats(harmless=10))
    checker = _checker(handler)
    assert checker.evaluate_message("bare example.com here").reason_code == us.REASON_NO_URLS
    assert checker.evaluate_message("bare example.com here", include_bare_domains=True).action == "allow"
    assert calls == ["example.com"]
