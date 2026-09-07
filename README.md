# CheckPoint Bootcamp: Secure Chat System

A WebSocket chat system with browser and CLI interfaces, SQLite persistence,
authentication, public rooms, selected-room live delivery, and server-side content
and URL checks. Only an allowed message is stored or broadcast. History and live
messages show the stored normalized sender username.

## Repository layout

```text
server.py, client.py, cli.py   # Stable server and CLI entry points
chat_system/                  # Authentication, database, security modules/contracts
config/                       # schema.sql and dlp_rules.json
scripts/                      # Offline smoke and load tools
tests/                        # Unit, integration and configuration tests
ui/                           # Modular browser UI (DOM, transport/state, health), styles and tests
docs/
  LOAD_TEST_REPORT.md
  setup/                      # Ollama and URL setup notes
  reference/                  # Historical URL integration patch (do not apply)
README.md, COMMON_SECURITY_DECISIONS.md
requirements.txt, .env.example, .gitignore
```

Application modules live in `chat_system`. Rules and schema resolve from the
project path regardless of working directory. `.env` and the default `chat.db`
remain in the project root; the default
log and relative path overrides still resolve against the working directory.

See the [local model setup](docs/setup/LOCAL_LLM_SETUP.md),
[URL setup notes](docs/setup/URL_SECURITY_NOTES.md),
[load report](docs/LOAD_TEST_REPORT.md). Component notes may retain historical
examples; the setup and integrated behavior described here apply to this product.
All executable commands below run from the repository root.

## Install and run

Python 3.12 is tested (Python 3.10+ required). Dependencies in `requirements.txt`
include FastAPI/Uvicorn, websockets, bcrypt, HTTPX, python-dotenv and pytest. SQLite
is included with Python. Node.js and Playwright are only needed for UI tests.
From the repository in PowerShell:

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000
```

If `python` resolves to the Windows Store stub, use an installed Python executable
for the first command. Startup initializes `chat.db` from `config/schema.sql`; no separate
initialization command is needed. `CHAT_DATABASE` and `CHAT_LOG` override `chat.db`
and `chat.log`. Run one server process/worker because sessions, room presence,
security windows and reputation caches are in memory.

Open `http://localhost:8000/` in two browser windows, or use the CLI as an
alternative in two or more separate terminals:

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

## Browser UI

Start the server once with the command above, then open `http://localhost:8000/`.
On another computer on the same network, open `http://SERVER_LAN_IP:8000/`.
No frontend server, npm install, or build is needed. FastAPI serves `/` and
`/static/*` from the project UI directory, alongside `/ws` and `/health`.
Only port 8000 needs to be reachable; see the firewall notes above.

The WebSocket address defaults to the current page's host/port: HTTP uses `ws://`
and HTTPS uses `wss://`. Click **Connect**; the optional address field supports
development against another server. This does not configure TLS: the included
server uses unencrypted HTTP/WS. HTTPS/WSS would require separate TLS deployment.
The UI itself needs neither Ollama nor a VirusTotal key.

The separate **Server online / Server unavailable** indicator checks HTTP health
on page load, reconnect, and every 30 seconds, with a five-second timeout. It does
not represent WebSocket login or security-service availability. WebSocket status
remains visible separately. Health requests send no credentials. A cross-origin
development override may show unavailable if that server does not permit CORS,
even while its WebSocket works; normal same-server use needs no CORS setup.
The optional `ui/serve.py` development helper remains available but is not needed
for normal use. Never serve the repository root containing `.env`.

1. **Sign up**, then **Log in**. Usernames are normalized; passwords are masked,
   never trimmed, and cleared after submission. Validation feedback does not
   replace the server's authentication or security checks.
2. Create a room or **Join** a public room. To return to an existing membership,
   choose **Select**. Create/join/select selects that room and loads its history.
   Only the selected room receives live messages. The server's room list contains
   no membership flags, so the UI labels only membership observed this session.
   **Filter rooms** searches loaded names case-insensitively without changing
   membership or selection; clear it to restore the list. A failed selection of
   another room preserves the current room.
3. Send a message. **Checking message…** remains visible during server security
   checks; incoming messages and draft editing continue. Commands are serialized
   while a request is pending, matching the server's per-connection processing.
   Only actual `room_message` events enter the conversation; rejected text stays
   in the composer for editing. History and events are deduplicated by `message_id`.
   History also refreshes timestamps on existing live-message entries.
4. **Leave room** ends membership. **Reconnect** or **Disconnect** clears the local
   session and displayed history. Log in and select a room again to recover history.
   No passwords, session tokens, or chat data are saved to browser storage.

The UI sends only the existing JSON WebSocket operations to `/ws`; the additional
HTTP routes serve static UI files only. Sender names come from server responses and events.
Security errors distinguish blocked content, unsafe links, uncertain link safety,
and unavailable checks without exposing scores, provider details or protected terms.
Message content is rendered as plain text, including HTML and links. A disconnect
or 180-second request timeout can leave delivery unknown: reconnect and check
history before retrying. Messages are never automatically resent. History is
unpaginated, as in the existing protocol. A membership change from another session
is learned on the next server operation; the protocol has no membership-change event.

### UI verification

Node.js 22+ runs the dependency-free transport tests. Python integration tests run
that same browser transport against the real server, SQLite, and real security
adapters with controlled external model/provider responses. Browser tests use
optional Playwright tooling; neither Node nor Playwright is needed to use the UI.

```powershell
node --test ui/tests/protocol.test.mjs ui/tests/health.test.mjs
./.venv/Scripts/python.exe -m pip install -r ui/requirements-test.txt
./.venv/Scripts/python.exe -m playwright install chromium
$env:PYTHON_DOTENV_DISABLED = "1"
./.venv/Scripts/python.exe -m pytest -q tests/test_ui_protocol.py tests/test_ui_browser.py tests/test_ui_serving.py
Remove-Item Env:PYTHON_DOTENV_DISABLED
```

The browser test exercises two users at desktop/mobile widths, signup without
automatic login, room lifecycle, history/live deduplication, safe text rendering,
incoming messages during delayed security rejection, preserved drafts, and
reconnect. Screenshots go to pytest's temporary test directory. External
Ollama/VirusTotal availability and real-model accuracy remain separate server-side checks.

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
| `CHAT_DATABASE` | No | `chat.db` in the project root | SQLite file; initialized at startup |
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
letters a-z, digits or underscores. Passwords are 8-32 characters, allowing
uppercase and lowercase English letters, digits, and only `@#$%^&*` as special
characters. At least two of three categories are required: letters (both cases
count together), digits, and allowed special characters. Letters plus digits
are sufficient; a special character is not mandatory. Passwords are not trimmed,
are masked during entry, and are stored only as salted bcrypt hashes. They never
enter the content-security modules. Login failures return the same
`invalid_credentials` error for an unknown username or incorrect password;
successful login creates an in-memory session.

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
3. Check deterministic DLP; suspicious context receives local classifier review.
   If content checks allow, check every distinct supported URL from the original text.
4. If allowed, reacquire the server lock and revalidate session, membership and
   selection before saving. Broadcast only to eligible connections selecting that
   room. If blocked, return a correlated structured rejection without persistence
   or delivery.

Signup and room creation run basic validation and deterministic name checks
before creating database records. Username normalization stays in `chat_system/auth.py`;
room names retain the existing nonempty, already-trimmed rule. Names do not use
recipe scoring, LLM or URL checks. Existing accounts/rooms are not migrated.

`chat_system/security_policy.py` evaluates at most ten total attempts including the current
message per `(user_id, room_id)`. Blocked attempts remain in that window. Entries
expire at five minutes using a monotonic clock; expiry is applied on the next
attempt for that key. At most nine valid previous attempts reach the classifier.
These security-only windows never enter SQLite. Per-user/room locks preserve their
order while unrelated windows can proceed during slow checks. The count of
user/room keys is not currently capped; expired data is pruned when that key is
next used, rather than by a background timer.
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

The deterministic policy immediately blocks the configured protected concept in
messages and new account/room names. Other recipe-related signals remain soft
signals: they accumulate across the recent user/room window and can trigger
local-model review rather than an immediate deterministic block. Low-risk
attempts do not call the model; hard blocks also skip it.

The LLM judges whether the current message discloses or materially continues a
pizza recipe using recent attempts as context. Ordinary pizza discussion,
recipe-existence mentions, neutral follow-ups and unrelated recipes such as
chocolate cake are intended to be allowed. This classification quality still
requires real-model evaluation; heuristics and models can make mistakes.

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

The local-model adapter accepts only loopback HTTP(S), disables redirects/proxies,
requires strict JSON allow/block output, and preserves its configured socket
timeout. CPU/cold starts can exceed it. Configure the Ollama process with cloud
features disabled; localhost alone does not establish how a runtime executes a
model. See `docs/setup/LOCAL_LLM_SETUP.md` for manual adapter checks and limitations.

Missing/unavailable models, timeout or malformed/unresolved output fail closed.
With no model installed the chat still starts: ordinary low-score text works,
but messages needing review are rejected. Real-model accuracy and timing require
manual verification; automated tests use controlled responses.

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
verdict. Failures are not cached. Malicious results block delivery; uncertain,
stale or unsupported results also prevent delivery until safety can be established.
A known malicious result takes precedence over other URL failures.

The integrated policy checks every extracted URL; the legacy helper's URL-count
limit is not used. See [URL setup notes](docs/setup/URL_SECURITY_NOTES.md) for
component configuration. Reputation checks assess hostname reports, not page
contents, and do not prove a link is safe. Provider quota/rate limits, missing
reports or connectivity problems can reject URL messages.

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
| `forbidden_term` | Protected content in a message or new name |
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
Message security logs use a shared attempt_id across stages: attempt user/room,
window size/age, current and full-window deterministic scores/category counts,
LLM action/score/duration/failure, URL count, each URL cache/API/local source and
status/duration/failure, and final action/score/reason. A score is not calibrated
confidence. Skipped URL stages are explicitly labelled not_evaluated, not
confused with no URL. Names retain deterministic
operation logs. Connection and message IDs are also logged. They exclude passwords, tokens, API keys,
model output and full blocked content. Unexpected failures return `internal_error`
and a generic log entry, never exception text that could contain secrets.
Successful sends display only the asynchronous chat event in the CLI; authentication
and room-operation success messages and friendly rejection messages remain.

## Tests, load and security demo

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
./.venv/Scripts/python.exe -m pytest -q tests/test_environment.py tests/test_dlp_corrections.py
./.venv/Scripts/python.exe -m pytest -q tests/test_dlp.py tests/test_security_policy.py tests/test_local_llm.py tests/test_url_security.py
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/python.exe -m pytest -q tests/test_security_integration.py
./.venv/Scripts/python.exe -m compileall -q chat_system server.py client.py cli.py tests scripts ui
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

For a manual demo, sign up/log in two browser or CLI clients, create/join General,
and exchange ordinary pizza chat. Use the offline smoke for repeatable content
and safe/malicious URL rejections without opening submitted URLs or consuming API
quota. Confirm rejected messages never appear in history. Select another room,
verify isolation, leave/rejoin and reconnect, and check `/health` during pending
checks. See [load results](docs/LOAD_TEST_REPORT.md) for local measurements.

Remaining limits: in-memory sessions without expiry, unpaginated history,
unencrypted HTTP/WS, manually configured real services, bounded per-window
attempt count but unbounded number of windows, and heuristic/model false positives
and false negatives. Local load results are not production-capacity claims.

For real-service verification, configure `.env` on the server computer, start
Ollama and pull the configured model as above, then run `ollama list` to confirm
it is installed. Follow the [local-model checks](docs/setup/LOCAL_LLM_SETUP.md)
and [URL setup notes](docs/setup/URL_SECURITY_NOTES.md) with synthetic test data.
Real provider checks consume API quota. Test the complete UI flow using ordinary
conversation, pizza-recipe disclosure, unrelated recipes, and controlled service
unavailability; verify expected allow/block outcomes and absence of rejected
messages from history. Use benign URLs for real reputation checks and mocked
responses for malicious cases; never visit a submitted URL to test reputation.

**Still requiring manual verification:** real Ollama classification quality and
timeouts, real VirusTotal access/quota, and access from another computer through
the LAN/firewall. Automated/offline results do not verify these services or TLS.
