"""URL reputation for chat messages (Person 3), backed by VirusTotal domain reports.

Implements the frozen ``URLExtractor`` and ``URLReputationChecker`` protocols from
``security_contracts.py`` and returns ``SecurityDecision`` values with
``source="url_reputation"``. Three layers, each testable on its own:

  - URL extraction and normalization (regex + urllib parsing, no network),
  - VirusTotal HTTP communication (one shared ``httpx.Client``),
  - policy mapping from VirusTotal analysis stats to a ``SecurityDecision``.

Decision mapping (see COMMON_SECURITY_DECISIONS.md):
  - 2+ malicious engine detections      -> block,  ``url_malicious``            (score 100)
  - exactly 1 malicious detection       -> review, ``url_malicious_review``     (score 70)
  - any suspicious detection            -> review, ``url_suspicious``           (score 50)
  - no usable evidence (no report, no timestamp, stale, undetected-only)
                                        -> review, ``url_reputation_unknown``   (score 40)
  - IP-literal / internal / unparsable host, never sent to the provider
                                        -> review, ``url_host_unsupported``     (score 40)
  - recent report with harmless votes and nothing above
                                        -> allow,  ``url_safe``                 (score 0)
  - provider check could not complete (missing key, timeout, HTTP error, 429,
    local rate budget, malformed response)
                                        -> block,  ``reputation_unavailable``   (score 100)

Safe, malicious and unknown verdicts are cached for 24 hours and the cache is
consulted before the provider. ``reputation_unavailable`` is never cached so the
next attempt retries. This cache is independent from any DLP blacklist. A verdict
describes VirusTotal's crowd-sourced scan history for a hostname; it is not a
guarantee that a site is genuine or safe, and "allow" means "nothing on record".

Parsing limitations:
  - Only ``http://``, ``https://`` and ``www.`` links are extracted, per the
    shared decision. ``extract_domains`` additionally recognizes bare
    ``example.com`` mentions for a curated list of common TLDs; it is an opt-in
    helper kept from the pre-contract implementation, not part of the contract.
  - The exact parsed hostname is what gets checked: ``paypal.com.evil.tld`` is
    looked up as itself and is never trusted because it contains ``paypal.com``.
    A subdomain may have no report of its own and is then "unknown".
  - IDNA uses Python's built-in codec, not full IDNA2008/UTS-46; exotic hostnames
    may be dropped as malformed rather than normalized.
  - The rate counter is process-local and cannot see other applications sharing
    the same API key; VirusTotal-side throttling is handled by the 429 cooldown.
  - The submitted URL is never fetched; only the hostname is sent to VirusTotal,
    and only the hostname (never the full URL) appears in decision details/logs.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import logging
import os
import re
import threading
import time
from collections import OrderedDict, deque
from typing import Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from chat_system.security_contracts import SecurityDecision

log = logging.getLogger("chat.url_security")

SOURCE = "url_reputation"

REASON_SAFE = "url_safe"
REASON_UNKNOWN = "url_reputation_unknown"
REASON_SUSPICIOUS = "url_suspicious"
REASON_MALICIOUS_REVIEW = "url_malicious_review"
REASON_MALICIOUS = "url_malicious"
REASON_HOST_UNSUPPORTED = "url_host_unsupported"
REASON_UNAVAILABLE = "reputation_unavailable"
REASON_NO_URLS = "no_urls"

VIRUSTOTAL_API_BASE_URL = os.environ.get(
    "VIRUSTOTAL_API_BASE_URL", "https://www.virustotal.com/api/v3/domains"
)
CACHE_TTL_SECONDS = float(os.environ.get("URL_REPUTATION_CACHE_TTL_SECONDS", 24 * 3600))
CACHE_MAX_SIZE = int(os.environ.get("URL_REPUTATION_CACHE_MAX_SIZE", 512))
MAX_URLS_PER_MESSAGE = int(os.environ.get("URL_REPUTATION_MAX_URLS_PER_MESSAGE", 5))
MAX_REPORT_AGE_SECONDS = float(os.environ.get("URL_REPUTATION_MAX_REPORT_AGE_SECONDS", 7 * 24 * 3600))
REQUEST_TIMEOUT_SECONDS = float(os.environ.get("URL_REPUTATION_REQUEST_TIMEOUT_SECONDS", 10))
# VirusTotal's free public API allows 4 requests/minute per key. Process-local only.
RATE_LIMIT_PER_MINUTE = int(os.environ.get("URL_REPUTATION_RATE_LIMIT_PER_MINUTE", 4))
COOLDOWN_SECONDS = float(os.environ.get("URL_REPUTATION_COOLDOWN_SECONDS", 60))
REVIEW_MALICIOUS_MIN = int(os.environ.get("URL_REPUTATION_REVIEW_MALICIOUS_MIN", 1))
BLOCK_MALICIOUS_MIN = int(os.environ.get("URL_REPUTATION_BLOCK_MALICIOUS_MIN", 2))
SUSPICIOUS_REVIEW_MIN = int(os.environ.get("URL_REPUTATION_SUSPICIOUS_REVIEW_MIN", 1))

_INTERNAL_SUFFIXES = {
    "localhost", "local", "internal", "lan", "home", "corp", "test", "invalid",
    "example", "localdomain",
}
_COMMON_BARE_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "io", "co", "ai", "app", "dev", "xyz", "info", "biz", "name", "pro",
    "us", "uk", "ca", "de", "fr", "es", "it", "nl", "ru", "cn", "jp", "kr",
    "in", "au", "br", "mx", "ch", "se", "no", "fi", "dk", "pl", "tv", "me",
    "cc", "online", "site", "tech", "store", "cloud",
}
# Brackets are excluded from the body (markdown/link syntax) except for a bracketed
# IPv6 literal directly after the scheme, so such links still reach the checker.
_URL_PATTERN = re.compile(
    r'(?:https?://|www\.)(?:\[[0-9a-fA-F:.]{2,45}\][^\s<>{}\[\]"\'\\]{0,2048}|[^\s<>{}\[\]"\'\\]{1,2048})',
    re.IGNORECASE,
)
_BARE_DOMAIN_PATTERN = re.compile(
    r'(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?P<tld>[a-zA-Z]{2,24})(?![\w-])'
)
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""
_DEFAULT_PORTS = {"http": 80, "https": 443}


# ---------------------------------------------------------------------------
# Extraction and normalization (no network)
# ---------------------------------------------------------------------------

def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_internal_hostname(host: str) -> bool:
    return host == "localhost" or host.split(".")[-1] in _INTERNAL_SUFFIXES


def _idna_host(raw: str) -> str | None:
    """Lowercase + IDNA-encode a hostname; None if structurally invalid."""
    host = raw.strip().rstrip(_TRAILING_PUNCTUATION).rstrip(".").lower()
    if not host:
        return None
    if _is_ip_address(host):
        return host
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not ascii_host or len(ascii_host) > 253:
        return None
    if any(not label or len(label) > 63 for label in ascii_host.split(".")):
        return None
    return ascii_host


def normalize_hostname(raw: str) -> str | None:
    """Return a checkable public hostname, or None for IP literals, internal or malformed hosts."""
    host = _idna_host(raw)
    if host is None or _is_ip_address(host) or "." not in host or _is_internal_hostname(host):
        return None
    return host


def normalize_url(candidate: str) -> str | None:
    """Normalize one http(s)/www link; None if it has no usable hostname or scheme."""
    candidate = candidate.strip().rstrip(_TRAILING_PUNCTUATION)
    if not candidate:
        return None
    lowered = candidate.lower()
    if not lowered.startswith(("http://", "https://")):
        if not lowered.startswith("www."):
            return None
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not hostname:
        return None
    host = _idna_host(hostname)
    if host is None:
        return None
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    scheme = parts.scheme.lower()
    netloc = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def hostname_of(url: str) -> str | None:
    """Hostname of a normalized URL, or None when it must not be sent to the provider."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return None
    return normalize_hostname(hostname) if hostname else None


def extract_urls(text: str) -> list[str]:
    """Return normalized, unique http(s)/www URLs from original text (URLExtractor contract)."""
    urls: list[str] = []
    seen: set[str] = set()
    for match in _URL_PATTERN.finditer(text):
        url = normalize_url(match.group(0))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def extract_domains(text: str, limit: int | None = None, include_bare: bool = True) -> list[str]:
    """Unique checkable hostnames in text; optionally also bare ``example.com`` mentions.

    Kept from the pre-contract implementation as an opt-in helper; the contract
    extractor is ``extract_urls``. Bare mentions are only recognized for common
    TLDs so that ``config.yml`` or ``node.js`` are not misread as domains.
    """
    domains: list[str] = []
    seen: set[str] = set()

    def add(domain):
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)

    pieces, last_end = [], 0
    for match in _URL_PATTERN.finditer(text):
        pieces.append(text[last_end:match.start()])
        last_end = match.end()
        url = normalize_url(match.group(0))
        add(hostname_of(url) if url else None)
    pieces.append(text[last_end:])
    if include_bare:
        for match in _BARE_DOMAIN_PATTERN.finditer("".join(pieces)):
            if match.group("tld").lower() in _COMMON_BARE_TLDS:
                add(normalize_hostname(match.group(0)))
    if limit is not None and len(domains) > limit:
        domains = domains[:limit]
    return domains


class RegexURLExtractor:
    """``URLExtractor`` implementation."""

    def extract(self, text: str) -> list[str]:
        return extract_urls(text)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def _decision(action, reason, score, **details) -> SecurityDecision:
    return SecurityDecision(action=action, reason_code=reason, risk_score=score,
                            source=SOURCE, details=details)


def decide_from_stats(domain, malicious, suspicious, harmless, undetected,
                      analysis_timestamp, now) -> SecurityDecision:
    """Map VirusTotal ``last_analysis_stats`` to a SecurityDecision (see module docstring)."""
    evidence = dict(domain=domain, malicious=malicious, suspicious=suspicious, harmless=harmless,
                    undetected=undetected, analysis_timestamp=analysis_timestamp, cache_status="miss")
    if malicious >= BLOCK_MALICIOUS_MIN:
        return _decision("block", REASON_MALICIOUS, 100, detail="malicious_detections", **evidence)
    if malicious >= REVIEW_MALICIOUS_MIN:
        return _decision("review", REASON_MALICIOUS_REVIEW, 70, detail="single_malicious_detection", **evidence)
    if suspicious >= SUSPICIOUS_REVIEW_MIN:
        return _decision("review", REASON_SUSPICIOUS, 50, detail="suspicious_detections", **evidence)
    if analysis_timestamp is None:
        return _decision("review", REASON_UNKNOWN, 40, detail="no_analysis_timestamp", **evidence)
    if now - analysis_timestamp > MAX_REPORT_AGE_SECONDS:
        return _decision("review", REASON_UNKNOWN, 40, detail="stale_report", **evidence)
    if harmless > 0:
        return _decision("allow", REASON_SAFE, 0, detail="harmless_evidence", **evidence)
    return _decision("review", REASON_UNKNOWN, 40, detail="undetected_only", **evidence)


def _unavailable(domain, detail) -> SecurityDecision:
    return _decision("block", REASON_UNAVAILABLE, 100, domain=domain, detail=detail, cache_status="miss")


def _with_cache_status(decision: SecurityDecision, status: str) -> SecurityDecision:
    return dataclasses.replace(decision, details={**decision.details, "cache_status": status})


_ACTION_RANK = {"allow": 0, "review": 1, "block": 2}


def worst_of(decisions: Sequence[SecurityDecision]) -> SecurityDecision:
    return max(decisions, key=lambda d: (_ACTION_RANK[d.action], d.risk_score))


# ---------------------------------------------------------------------------
# Provider client with cache, coalescing and rate limiting
# ---------------------------------------------------------------------------

class VirusTotalURLReputationChecker:
    """``URLReputationChecker`` implementation (synchronous, thread-safe).

    The frozen protocol is synchronous, so this uses ``httpx.Client``; callers on
    an event loop should run ``check`` via ``asyncio.to_thread`` like the other
    blocking work in this project. No failure path is ever treated as safe.
    """

    def __init__(self, api_key: str | None = None, http_client: httpx.Client | None = None):
        self._api_key = api_key if api_key is not None else os.environ.get("VIRUSTOTAL_API_KEY")
        self._client = http_client or httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS)
        self._cache: "OrderedDict[str, tuple[float, SecurityDecision]]" = OrderedDict()
        self._lock = threading.Lock()
        self._inflight: dict[str, threading.Lock] = {}
        self._request_times: deque[float] = deque()
        self._cooldown_until = 0.0

    # -- public API --------------------------------------------------------

    def check(self, url: str) -> SecurityDecision:
        """Decision for one URL; the cache is consulted before the provider."""
        normalized = normalize_url(url) if isinstance(url, str) else None
        domain = hostname_of(normalized) if normalized else None
        if domain is None:
            return _decision("review", REASON_HOST_UNSUPPORTED, 40,
                             detail="ip_internal_or_unparsable_host", cache_status="miss")
        return self._check_domain(domain)

    def evaluate_message(self, text: str, include_bare_domains: bool = False) -> SecurityDecision:
        """Aggregate decision for every URL in a message (worst wins). No URLs -> allow."""
        domains = extract_domains(text, include_bare=include_bare_domains)
        if not domains:
            return _decision("allow", REASON_NO_URLS, 0, domains=[])
        truncated = len(domains) > MAX_URLS_PER_MESSAGE
        checked = domains[:MAX_URLS_PER_MESSAGE]
        decisions = [self._check_domain(domain) for domain in checked]
        if truncated:
            decisions.append(_decision("review", REASON_UNKNOWN, 40, detail="too_many_urls",
                                       domain=None, cache_status="miss"))
        worst = worst_of(decisions)
        return dataclasses.replace(worst, details={**worst.details, "domains": checked,
                                                   "truncated": truncated})

    def close(self) -> None:
        self._client.close()

    # -- cache -------------------------------------------------------------

    def _cache_get(self, domain, now):
        entry = self._cache.get(domain)
        if entry is None:
            return None
        expires_at, decision = entry
        if expires_at < now:
            del self._cache[domain]
            return None
        self._cache.move_to_end(domain)
        return decision

    def _cache_put(self, domain, decision, now):
        self._cache[domain] = (now + CACHE_TTL_SECONDS, decision)
        self._cache.move_to_end(domain)
        while len(self._cache) > CACHE_MAX_SIZE:
            self._cache.popitem(last=False)

    def _check_domain(self, domain: str) -> SecurityDecision:
        with self._lock:
            cached = self._cache_get(domain, time.time())
            if cached is not None:
                return _with_cache_status(cached, "hit")
            key_lock = self._inflight.setdefault(domain, threading.Lock())
        with key_lock:  # concurrent callers for the same domain wait here
            with self._lock:
                cached = self._cache_get(domain, time.time())
                if cached is not None:
                    return _with_cache_status(cached, "coalesced")
            decision = self._fetch_and_decide(domain)
            with self._lock:
                if decision.reason_code != REASON_UNAVAILABLE:
                    self._cache_put(domain, decision, time.time())
                self._inflight.pop(domain, None)
            return decision

    # -- provider ----------------------------------------------------------

    def _rate_limit_ok(self, now):
        if now < self._cooldown_until:
            return False
        while self._request_times and now - self._request_times[0] > 60:
            self._request_times.popleft()
        return len(self._request_times) < RATE_LIMIT_PER_MINUTE

    def _fetch_and_decide(self, domain: str) -> SecurityDecision:
        try:
            return self._fetch_and_decide_unsafe(domain)
        except Exception:
            log.error("url_reputation_lookup_failed")
            return _unavailable(domain, "internal_error")

    def _fetch_and_decide_unsafe(self, domain: str) -> SecurityDecision:
        if not self._api_key:
            return _unavailable(domain, "missing_api_key")
        now = time.time()
        with self._lock:
            allowed = self._rate_limit_ok(now)
            if allowed:
                self._request_times.append(now)
        if not allowed:
            return _unavailable(domain, "rate_limited")

        try:
            response = self._client.get(f"{VIRUSTOTAL_API_BASE_URL}/{domain}",
                                        headers={"x-apikey": self._api_key},
                                        timeout=REQUEST_TIMEOUT_SECONDS)
        except httpx.TimeoutException:
            return _unavailable(domain, "timeout")
        except httpx.HTTPError:
            return _unavailable(domain, "request_error")

        if response.status_code == 429:
            with self._lock:
                self._cooldown_until = time.time() + COOLDOWN_SECONDS
            return _unavailable(domain, "rate_limited_429")
        if response.status_code in (401, 403):
            return _unavailable(domain, f"auth_error_{response.status_code}")
        if response.status_code == 404:
            return _decision("review", REASON_UNKNOWN, 40, domain=domain, detail="no_report",
                             malicious=None, suspicious=None, harmless=None, undetected=None,
                             analysis_timestamp=None, cache_status="miss")
        if response.status_code != 200:
            return _unavailable(domain, f"http_{response.status_code}")

        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            analysis_timestamp = attributes.get("last_analysis_date")
        except (KeyError, TypeError, ValueError):
            return _unavailable(domain, "invalid_response")
        return decide_from_stats(domain, malicious, suspicious, harmless, undetected,
                                 analysis_timestamp, time.time())
