# Shared Security Decisions

This document and `chat_system/security_contracts.py` must be merged before parallel branches are created. Agents may read all repository files but must edit only their assigned files.

## Policy

- Inspect messages, usernames, and room names on the server. Never inspect passwords for DLP.
- Hard-forbidden concepts include every explicitly configured alias, spelling variation, abbreviation, homoglyph and evasion form. A hard match returns score 100 and is blocked without an LLM call.
- Recipe score: 0-29 allow; 30-99 local-LLM review; 100 deterministic block.
- Initial scoring: pizza/dough/sauce anchor +10; each ingredient +5 capped at 20; quantity/unit +20; preparation action +15; time/temperature +15; sequence markers +10; several categories in one message +10. Cap recipe-rule scores at 99.
- Keep the last 10 attempted messages per `(user_id, room_id)` in a bounded in-memory deque. Include blocked attempts in this security-only window. Approved messages are stored normally in SQLite; blocked messages are never stored as chat history or broadcast.
- A local-LLM timeout/unavailability blocks reviewed content with `security_check_unavailable`.
- Extract URLs from original text independently of DLP normalization. Support `http://`, `https://`, and `www.` initially.
- URL blacklist and reputation cache are separate. Cache safe, malicious and unknown verdicts for 24 hours; check cache before the provider.
- VirusTotal/provider unavailability blocks a URL message with `reputation_unavailable`. Provider calls must be mocked in automated tests.
- One malicious-engine detection produces review; two or more produce block, unless the provider's established verdict model requires an equivalent documented mapping.
- Never log passwords, tokens, full blocked content, or provider API keys. Log decision metadata and reason codes only.

## Integration Order

`authenticate/authorize -> validate -> deterministic DLP -> local LLM if score 30-99 -> URL reputation if URLs exist -> save approved message -> broadcast`

For username and room-name validation, run only the applicable deterministic DLP check; there is no message context or URL reputation requirement unless the final integration explicitly chooses otherwise.

## Ownership

- Person 1: `chat_system/dlp.py`, `config/dlp_rules.json`, `chat_system/security_policy.py`, `tests/test_dlp.py`, `tests/test_security_policy.py`.
- Person 2: `chat_system/local_llm.py`, `tests/test_local_llm.py`, and local-model setup notes.
- Person 3: `chat_system/url_security.py`, `tests/test_url_security.py`, URL cache/provider configuration notes. Preserve existing URL work.
- Person 4: `scripts/load_test.py`, `tests/test_concurrency.py`, `docs/LOAD_TEST_REPORT.md`.
- Nobody edits `chat_system/security_contracts.py`, `server.py`, `client.py`, `cli.py`, `chat_system/database.py`, `chat_system/auth.py`, shared README, or another owner's files during parallel work.
- Final server/client integration happens only after all branches are reviewed. One designated integrator performs it.

## Branch and Collaboration Rules

1. Merge the shared contracts commit first; all four branches start from that same commit.
2. One branch and pull request per person. Never commit directly to `main`.
3. Commit only owned files. If a contract problem is discovered, report it to the team instead of changing it locally.
4. Each module must be testable with fakes/mocks and without another person's implementation.
5. Before handoff, run focused tests, full tests, compile checks, and report exact results, assumptions and remaining limitations.

