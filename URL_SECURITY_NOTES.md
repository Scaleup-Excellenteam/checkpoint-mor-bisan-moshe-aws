# URL Reputation (Person 3) — setup, configuration and integration notes

Module: `url_security.py`. Tests: `tests/test_url_security.py`. Implements the
frozen `URLExtractor` and `URLReputationChecker` protocols from
`security_contracts.py`; decisions follow `COMMON_SECURITY_DECISIONS.md`.

## Configuration (environment, read at process start)

Set the key in the **same PowerShell session** that starts the server; it is never
written to disk, logged, or returned to clients:

```powershell
$env:VIRUSTOTAL_API_KEY = "paste-your-virustotal-api-key-here"
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | unset | Required. Without it every URL check is `reputation_unavailable` (block). |
| `URL_REPUTATION_CACHE_TTL_SECONDS` | `86400` (24 h) | Verdict cache lifetime (agreed policy). |
| `URL_REPUTATION_CACHE_MAX_SIZE` | `512` | Bounded LRU size. |
| `URL_REPUTATION_MAX_URLS_PER_MESSAGE` | `5` | Extra hosts escalate the message to `review`. |
| `URL_REPUTATION_MAX_REPORT_AGE_SECONDS` | `604800` (7 d) | Older VirusTotal reports count as unknown. |
| `URL_REPUTATION_REQUEST_TIMEOUT_SECONDS` | `10` | Per-lookup timeout; no retries. |
| `URL_REPUTATION_RATE_LIMIT_PER_MINUTE` | `4` | Local budget matching the free public API. |
| `URL_REPUTATION_COOLDOWN_SECONDS` | `60` | Pause after an HTTP 429. |
| `URL_REPUTATION_REVIEW_MALICIOUS_MIN` / `_BLOCK_MALICIOUS_MIN` | `1` / `2` | 1 detection → review, 2+ → block. |
| `URL_REPUTATION_SUSPICIOUS_REVIEW_MIN` | `1` | Suspicious detections → review. |
| `VIRUSTOTAL_API_BASE_URL` | official endpoint | Tests only (mock server). |

Provider call: `GET https://www.virustotal.com/api/v3/domains/{hostname}` with the
key in the `x-apikey` header. Existing reports only — nothing is submitted for
scanning and the user's URL is never fetched. Only the hostname is sent and only the
hostname appears in `SecurityDecision.details` (never the full URL or message).

## Decision mapping

| Evidence | action | reason_code | score | cached |
| --- | --- | --- | --- | --- |
| ≥2 malicious engines | block | `url_malicious` | 100 | yes |
| 1 malicious engine | review | `url_malicious_review` | 70 | yes |
| ≥1 suspicious | review | `url_suspicious` | 50 | yes |
| no report / no timestamp / stale / undetected-only | review | `url_reputation_unknown` | 40 | yes |
| IP literal, internal host, unparsable | review | `url_host_unsupported` | 40 | n/a (no lookup) |
| recent report with harmless votes | allow | `url_safe` | 0 | yes |
| missing key, timeout, HTTP/auth error, 429, local rate budget, bad JSON | block | `reputation_unavailable` | 100 | **no** (retries next time) |

Unavailable verification is never treated as safety. "Allow" means VirusTotal has
nothing on record — not that the site is genuine.

## Integration guidance (for the designated integrator — not done on this branch)

- `check(url)` is **synchronous** because the frozen protocol is; call it from the
  server via `asyncio.to_thread(...)` like other blocking work, and **outside**
  `app.state.operations` so a slow provider never stalls other clients. Reacquire
  the lock and re-check membership before saving.
- `evaluate_message(text)` is a convenience aggregate (worst decision wins; no
  URLs → allow/`no_urls`). `MessageSecurityPolicy` may call `check` per URL instead.
- `URL_SECURITY_INTEGRATION.patch` holds the pre-contract server/CLI/README wiring
  (two-phase send, readable CLI errors, log lines). It targets the *old* async dict
  API and is kept only as a reference for the integrator; do not apply it as-is.
- `requirements.txt` gained `httpx` (needed by this module). Flagged, since that
  file is shared.

## Contract notes and assumptions

- `URLReputationChecker.check` is sync in the contract; the pre-contract async
  implementation was converted to a thread-safe `httpx.Client` core (same cache,
  coalescing, rate-limit and policy logic) rather than wrapped, to avoid running
  a second event loop.
- The decisions file names `reputation_unavailable`; other URL reason codes above
  are this module's proposal and are trivial to rename if the policy owner prefers.
- `PERSON_3_URL_REPUTATION_SPEC.md` did not exist in the repository when this
  branch was updated; scope follows `COMMON_SECURITY_DECISIONS.md` ownership.
- Bare `example.com` mentions (no scheme/`www.`) are supported by the preserved
  `extract_domains(..., include_bare=True)` helper but are off by default, since the
  shared decision lists `http://`, `https://`, `www.` initially.

## Limitations

Process-local rate counter (other apps sharing the key can still cause 429s);
in-memory cache resets on restart; IDNA via the stdlib codec; subdomains often have
no VirusTotal report of their own and are then "unknown"; a curated common-TLD list
gates bare-domain detection. No live VirusTotal call has been made from this
branch — all verification uses mocked transports.

## Verify

```powershell
./.venv/Scripts/python.exe -m pytest -q tests/test_url_security.py
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/python.exe -m compileall -q url_security.py tests/test_url_security.py
git diff --check
```
