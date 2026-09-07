# CheckPoint Bootcamp: Secure Chat System

A WebSocket CLI chat system with SQLite persistence, authentication, public rooms,
selected-room live delivery, and server-side content and URL checks. Only an
allowed message is stored or broadcast. History and live messages show the stored
normalized sender username.

## Install and run

Python 3.12 is tested (Python 3.10+ required). From the repository in PowerShell:

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000
```

If `python` resolves to the Windows Store stub, use an installed Python executable
for the first command. Startup initializes `chat.db` from `schema.sql`; no separate
initialization command is needed. `CHAT_DATABASE` and `CHAT_LOG` override `chat.db`
and `chat.log`. Run one server process/worker because sessions, room presence,
security windows and reputation caches are in memory.

In two or more separate terminals:

```powershell
./.venv/Scripts/python.exe client.py --uri ws://127.0.0.1:8000/ws
```

For another laptop, use the server's LAN IP and allow inbound port 8000. Health is
`http://127.0.0.1:8000/health`. Local tests do not prove LAN/firewall connectivity.

For example, on each remote laptop (replace the example IP with the server IP):

```powershell
./.venv/Scripts/python.exe client.py --uri ws://192.168.1.50:8000/ws
Invoke-RestMethod http://192.168.1.50:8000/health
```

Use the same LAN or a reachable private network. Allow inbound TCP 8000 for the
server on the appropriate private firewall profile; do not disable the firewall.
Only the chat server needs outbound HTTPS to VirusTotal. Keep Ollama on loopback;
remote clients need neither its port nor the API key. `/health` shares the chat
port and returns `ok: true, status: healthy`; it is a server liveness check, not
proof that either security service is available. Host/port and client URI are CLI
arguments with the defaults shown above, not environment variables.

## Environment configuration

The server loads `.env` beside `server.py` before importing database and URL
configuration, for both `python server.py` and `uvicorn server:app` startup.
This lookup does not depend on the terminal directory. Existing OS variables,
including empty values, take precedence (`override=False`). Restart after edits.
The file is optional: startup works without it, but required security checks fail
closed when their services are missing. Direct adapter/database imports do not
automatically load `.env`. Relative database/log overrides use the process working
directory; use absolute paths if launching elsewhere. Never use blank path values.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `CHAT_DATABASE` | No | `chat.db` beside `database.py` | SQLite file; initialized at startup |
| `CHAT_LOG` | No | `chat.log` in working directory | Server log file |
| `LOCAL_LLM_ENDPOINT` | No | `http://127.0.0.1:11434/api/generate` | Full Ollama URL, including API path; no separate base-URL variable |
| `LOCAL_LLM_MODEL` | No | `qwen2.5:1.5b` | Installed local model |
| `LOCAL_LLM_TIMEOUT_SECONDS` | No | `30` | Positive finite socket timeout |
| `VIRUSTOTAL_API_KEY` | For provider lookups | Unset | Private API credential; blank also fails closed |
| `VIRUSTOTAL_API_BASE_URL` | No | `https://www.virustotal.com/api/v3/domains` | Keep official endpoint; test override only |
| `URL_REPUTATION_REQUEST_TIMEOUT_SECONDS` | No | `10` | Provider timeout; no retries |
| `URL_REPUTATION_CACHE_TTL_SECONDS` | No | `86400` | Agreed 24-hour verdict lifetime |
| `URL_REPUTATION_CACHE_MAX_SIZE` | No | `512` | Maximum cached hostnames |
| `URL_REPUTATION_MAX_REPORT_AGE_SECONDS` | No | `604800` | Reports older than seven days become unknown |
| `URL_REPUTATION_RATE_LIMIT_PER_MINUTE` | No | `4` | Per-process request budget |
| `URL_REPUTATION_COOLDOWN_SECONDS` | No | `60` | Cooldown after HTTP 429 |
| `URL_REPUTATION_REVIEW_MALICIOUS_MIN` | No | `1` | Malicious detections requiring review |
| `URL_REPUTATION_BLOCK_MALICIOUS_MIN` | No | `2` | Malicious detections requiring block |
| `URL_REPUTATION_SUSPICIOUS_REVIEW_MIN` | No | `1` | Suspicious detections requiring review |
| `URL_REPUTATION_MAX_URLS_PER_MESSAGE` | No | `5` | Legacy helper only; integrated policy checks all extracted URLs |
| `PYTHON_DOTENV_DISABLED` | No | Unset | Set `1` in test process to skip loading developer `.env` |
| `OLLAMA_HOST` | Runtime setup | `127.0.0.1:11434` | Export in Ollama terminal; not configured by chat `.env` |
| `OLLAMA_NO_CLOUD` | This local-only setup | Set `1` explicitly | Export in Ollama terminal to disable cloud features |

Keep numeric URL settings at the agreed defaults; malformed numeric values can
prevent startup. The template contains only safe defaults and a blank API key.
`.env` is ignored; only `.env.example` belongs in Git.

## Using rooms and the CLI

Sign up (menu 1), then log in (menu 2). Usernames are trimmed/lowercased, 3-20
letters a-z, digits or underscores. Passwords are 8-32 letters, digits or
`@#$%^&*`, with at least two categories, and stored with salted bcrypt hashes.
Passwords never enter the content-security modules.

Client A: `/create General`; client B: `/join General`; then type a message.
Commands: `/list`, `/create NAME`, `/join NAME`, `/select NAME`, `/leave NAME`,
`/history`, `/reconnect`, `/quit`. Names may contain spaces. Create/join/select
select that room. Selection is per connection; stored membership in other rooms
remains unchanged. Both sending and live receiving require that room to be selected
and membership to remain active. Leave clears affected selections; reconnect
requires login/selection (or join if previously left). History is available to
active members even for messages missed while viewing another room.

## Security flow and architecture

`server.py` creates one long-lived `SecurityPolicy` in its FastAPI lifespan using
`RuleDLPChecker`, `OllamaRecipeClassifier`, `RegexURLExtractor`, and
`VirusTotalURLReputationChecker`. Production wiring uses the real adapters.

For message requests:

1. Validate the session, message and room fields, active membership and selection.
2. Run the policy in a worker thread outside the server's shared async lock.
3. Check deterministic DLP; call the local classifier only for scores 30-99;
   then check every distinct supported URL from the original text.
4. If allowed, reacquire the server lock and revalidate session, membership and
   selection before saving. Broadcast only to eligible connections selecting that
   room. If blocked, return a correlated structured rejection without persistence
   or delivery.

Signup and room creation run basic validation and deterministic name checks
before creating database records. Username normalization stays in `auth.py`;
room names retain the existing nonempty, already-trimmed rule. Names do not use
recipe scoring, LLM or URL checks. Existing accounts/rooms are not migrated.

`security_policy.py` holds up to ten prior attempted messages per `(user_id,
room_id)`, including blocked attempts, and evaluates them with the current text.
These security-only windows never enter SQLite. Per-user/room locks preserve their
order while unrelated windows can proceed during slow checks. The count of
user/room windows is not currently capped or expired; each window is capped at ten.
The shared async lock is never held for model/provider I/O. `/health`, other users,
and other rooms remain responsive under the tested workload; this is not a capacity
guarantee under arbitrary thread-pool saturation.

The client has one reader dispatching correlated responses and asynchronous events;
`cli.py` handles interaction. The database module uses parameterized SQL,
transactions and foreign keys. Repository-style persistence and room publish/
subscribe separate storage from routing, at the cost of explicit SQL and managing
connection/queue lifecycle. Each connection has a bounded outgoing queue; slow
consumers can be disconnected.

## DLP and local-model setup

Only **pineapple** and its configured aliases/typos/evasions in `dlp_rules.json`
receive deterministic score 100 and immediate blocking. Normal pizza discussion
is allowed. Recipe clues accumulate across the window: pizza/dough/sauce +10;
distinct ingredients +5 each (cap 20); quantity/unit +20; preparation +15;
time/temperature +15; sequence markers +10; at least three categories in one
attempt +10. Recipe scores cap at 99. Scores 0-29 skip the model; 30-99 request
review. These heuristics are not a guarantee of detection or zero false positives.

Install Ollama manually using [the official download](https://ollama.com/download).
In a separate terminal, configure its [local-only mode](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features) and start the runtime:

```powershell
$env:OLLAMA_NO_CLOUD = "1"
$env:OLLAMA_HOST = "127.0.0.1:11434"
ollama serve
```

Then download a local model explicitly (one-time internet access):

```powershell
ollama pull qwen2.5:1.5b
```

The application never downloads a model. If an Ollama tray process already owns
the port, configure/restart that process or stop it before the separate runtime.
The environment table above lists the adapter settings.

The teammate's adapter accepts only loopback HTTP(S), disables redirects/proxies,
requires strict JSON allow/block output, and preserves its configured socket
timeout. CPU/cold starts can exceed it. Configure the Ollama process with cloud
features disabled; localhost alone does not establish how a runtime executes a
model. See `LOCAL_LLM_SETUP.md` for manual adapter checks and limitations.

Missing/unavailable models, timeout or malformed/unresolved output fail closed.
With no model installed the chat still starts: ordinary low-score text works,
but messages needing review are rejected. Real-model accuracy and timing require
manual team verification; automated tests use controlled responses.

## URL reputation and secrets

Create/sign in to a VirusTotal account and obtain your key from its API-key page
following [VirusTotal's instructions](https://docs.virustotal.com/docs/please-give-me-an-api-key).
Paste it only into the ignored local `.env` value for `VIRUSTOTAL_API_KEY`, or
supply it through the server environment/secret manager. Do not put real keys in source, commands committed to Git, or a
shared terminal transcript. `.env`, logs, SQLite files and virtual environments are
ignored. No credentials are required for the offline automated tests.

`http://`, `https://` and `www.` links are extracted from original message text,
normalized and deduplicated. Every extracted URL is checked. Submitted URLs are
**never visited**: the adapter requests only existing hostname reports from
VirusTotal. Its separate in-memory LRU cache holds safe, malicious and unknown
verdicts for 24 hours, keyed by hostname. Different paths share that hostname
verdict. Failures are not cached. Two malicious detections block; one detection,
suspicious, unknown/stale results, and unsupported hosts return review, which the
final policy conservatively blocks. A known malicious URL takes precedence over
other URL failures; any failure otherwise prevents delivery.

`URL_SECURITY_NOTES.md` lists the module's other settings. Its legacy
`evaluate_message()` helper and URL limit are not used by the integrated policy;
the policy checks every URL via `check()`. `URL_SECURITY_INTEGRATION.patch` is a
historical reference targeting an old API: **do not apply it**. Its preserved
unified-diff context-marker spaces produce known Git whitespace warnings; source
and documentation whitespace checks exclude this reference artifact.

This is hostname reputation, not page-content scanning or proof of safety. Bare
domains without a supported prefix are not checked in the integrated flow.
Provider quota/rate limits, missing reports or connectivity can reject URL messages.

## Protocol, errors and logs

Each WebSocket text frame carries one JSON object. Requests have unique string
`id` (1-64 characters), `action`, and `token` for protected operations. Responses
have `type: response`, matching `id`, `ok`, and result fields or `error`.
Events use `type: event`, `action: room_message`, and authoritative sender/room
fields. Request IDs still correlate replies if events arrive first. The inbound
limit is 64 KiB; malformed envelopes may return `id: null`, and oversized frames
can close the connection. Identity always comes from the validated session.

Actions: `signup`, `login`, `list_groups`, `create_group`, `join_group`,
`leave_group`, `select_room`, `history`, `send_message`.

Security rejections include safe `security` fields: action, risk_score, source,
and reason_code. The CLI displays a readable explanation alongside the code:

| Code | Meaning |
| --- | --- |
| `forbidden_term` | Protected pineapple term/evasion in a message or new name |
| `recipe_blocked` | Local classifier identified recipe disclosure |
| `security_check_unavailable` | Model failure, timeout or invalid/unresolved result |
| `malicious_url` | Blocking URL reputation |
| `reputation_unavailable` | Missing key, provider failure, malformed result or rate limit |
| `reputation_review_required` | URL verdict remains uncertain or needs review |
| `room_not_selected` | Select the target room before sending |

Existing errors remain: `invalid_username`, `invalid_password`, `username_taken`,
`invalid_credentials`, `unauthenticated`, `invalid_request`, `invalid_json`,
`unsupported_operation`, `invalid_room_name`, `group_not_found`,
`group_already_exists`, `already_member`, `not_active_member`, `internal_error`.
Logs record timestamps, operation/user/room IDs, decision action, score, source and
reason, plus connection and message IDs. They exclude passwords, tokens, API keys,
model output and full blocked content. Unexpected failures return `internal_error`
and a generic log entry, never exception text that could contain secrets.

## Tests, load and security demo

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
./.venv/Scripts/python.exe -m pytest -q tests/test_environment.py
./.venv/Scripts/python.exe -m pytest -q tests/test_dlp.py tests/test_security_policy.py tests/test_local_llm.py tests/test_url_security.py
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/python.exe -m pytest -q tests/test_security_integration.py
./.venv/Scripts/python.exe -m compileall -q auth.py database.py server.py client.py cli.py dlp.py security_policy.py local_llm.py url_security.py security_contracts.py tests scripts
./.venv/Scripts/python.exe scripts/security_smoke.py
./.venv/Scripts/python.exe scripts/load_test.py --clients 3 --messages 2
./.venv/Scripts/python.exe scripts/load_test.py --clients 8 --messages 10
Remove-Item Env:PYTHON_DOTENV_DISABLED
```

Normal pytest includes the small concurrency scenario; the larger load command is
optional. Tests/harnesses use temporary databases and isolated loopback ports.
The smoke runs the real server and client processes/adapters against controlled
local HTTP model/provider fixtures. It does not use a real model or external API.
Windows subprocess tests stop only their owned process tree, including the venv
launcher child; a restrictive sandbox may need permission for this cleanup.

For a manual demo, sign up/login two clients, create/join General, exchange ordinary
pizza chat, then try `pineapple` and confirm rejection and absence from `/history`.
Try a forbidden username and room name. Send recipe clues over several messages
(e.g. `pizza`, then `200 g flour`, then preparation instructions) to trigger review.
With a configured model, inspect its safe decision; without one, expect
`security_check_unavailable`. Use the offline smoke for repeatable safe/malicious
URL demonstrations without opening URLs or consuming API quota. Select another
room on a third client, verify isolation, leave/rejoin and reconnect, and check
`/health` during pending checks. See `LOAD_TEST_REPORT.md` for measured results.

Remaining limits: in-memory sessions without expiry, unpaginated history,
unencrypted lab `ws://`, manually configured real services, bounded per-window
attempt count but unbounded number of windows, and heuristic/model false positives
and false negatives. No production capacity or cross-laptop validation is claimed.

For real-service verification later, configure `.env`, start Ollama as above and
run these commands from the repository on the server computer. The second command
makes real Ollama and VirusTotal requests, uses synthetic text, and prints only
safe decision fields. A URL verdict may legitimately be review/block; unavailable
means configuration/connectivity/quota still needs attention.

```powershell
ollama list
@'
import server  # Loads the root .env before the real adapters.
from local_llm import OllamaRecipeClassifier
from url_security import VirusTotalURLReputationChecker
llm = OllamaRecipeClassifier().classify("Mix 200 g flour and bake for 20 minutes.", [])
print(llm.action, llm.reason_code, llm.risk_score)
checker = VirusTotalURLReputationChecker()
try:
    result = checker.check("https://www.python.org")
    print(result.action, result.reason_code, result.risk_score)
finally:
    checker.close()
'@ | ./.venv/Scripts/python.exe -
./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000
```

Then use the two CLI terminals and demo above to verify the full message flow.
These real-service commands require manual team configuration and have not been
verified against a real model or provider by the automated/offline test runs.
