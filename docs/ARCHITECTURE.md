# Architecture

Technical documentation for the TSPO Secret Slice Chat: components, protocol,
thread model, room routing, security pipeline and operational behaviour. Design
pattern rationale is in [DESIGN_PATTERNS.md](DESIGN_PATTERNS.md); the demo script
and lessons learned are in [DEMO.md](DEMO.md).

## 1. System overview

```text
 laptop A (browser)         laptop B (CLI)            laptop C (browser)
 static/app.js              cli.py + client.py        static/app.js
       │  ws://host:8000/ws        │                        │
       └───────────────┬───────────┴────────────────────────┘
                       ▼
        ┌──────────────────────────────────────────────────────────┐
        │ server.py  (FastAPI + uvicorn, one process)              │
        │  REST: GET /health  GET /api/reasons  GET / + /static    │
        │  WS:   /ws  one JSON object per frame                    │
        │                                                          │
        │  event loop ──► asyncio.to_thread ──► worker threads     │
        │   • per-connection state + bounded outgoing queue        │
        │   • operations lock (state transitions, recipient        │
        │     snapshots; never held during socket or provider I/O) │
        │                                                          │
        │  chat_system/                                            │
        │   auth.py ─ bcrypt, session tokens                       │
        │   database.py ─ SQLite repository (config/schema.sql)    │
        │   security_policy.py ─ DLP → local LLM → URL reputation  │
        │     dlp.py (rules, config/dlp_rules.json)                │
        │     local_llm.py (Ollama adapter, loopback only)         │
        │     url_security.py (VirusTotal adapter, cache, limits)  │
        │   reason_codes.py ─ display text shared by UI/CLI/docs   │
        └──────────────┬───────────────────────┬───────────────────┘
                       ▼                       ▼
                 chat.db (SQLite)         chat.log (events, decisions)
                                               │ optional, outbound only
                              ┌────────────────┴────────────────┐
                              ▼                                 ▼
                    Ollama on 127.0.0.1:11434          VirusTotal domains API
```

One teammate runs the server; everyone else connects over the LAN with a browser
(`http://<host>:8000/`) or the CLI (`python client.py --uri ws://<host>:8000/ws`).

## 2. Components

| Component | File(s) | Responsibility |
| --- | --- | --- |
| Server | `server.py` | FastAPI app: REST endpoints, WebSocket endpoint, request dispatch, room broadcast, logging, lifespan wiring of the security policy. |
| Web UI | `static/index.html`, `static/app.js`, `static/styles.css` | Browser client; identical protocol to the CLI; shows rooms, live messages, security decisions with reason codes, protocol log, disconnect/reconnect controls. |
| CLI | `cli.py`, `client.py` | Terminal client. `client.py` is the reusable network client (one reader task, request futures correlated by id, event queue); `cli.py` is the interactive menu. |
| Identity | `chat_system/auth.py` | Username normalization and validation, password policy, bcrypt hashing with per-password salt, random session tokens (in memory). |
| Persistence | `chat_system/database.py`, `config/schema.sql` | Users, rooms, memberships (join/leave/rejoin with `left_at`), messages and history. Parameterized SQL, transactions, foreign keys, short-lived connections. |
| Security contracts | `chat_system/security_contracts.py` | Frozen dataclasses and protocols shared by all security modules (`SecurityDecision`, `MessageSecurityContext`, checker/classifier/extractor/reputation protocols, score bands). |
| DLP rules | `chat_system/dlp.py`, `config/dlp_rules.json` | Deterministic detection of the protected term (pineapple) and its aliases, typos, leetspeak, homoglyphs and separator evasions; recipe-clue scoring across the recent-attempt window. |
| Local classifier | `chat_system/local_llm.py` | Adapter for a local Ollama model. Resolves recipe scores 30-99 to allow/block. Loopback endpoint only, strict JSON schema, timeout, fail closed. |
| URL reputation | `chat_system/url_security.py` | URL extraction/normalization, VirusTotal domain reports, 24 h LRU verdict cache, request coalescing, local rate budget, fail closed. Only hostnames leave the server; URLs are never visited. |
| Policy | `chat_system/security_policy.py` | Orders the checks, owns the ten-attempt security window per `(user, room)`, maps module decisions to final policy reason codes. |
| Reason catalog | `chat_system/reason_codes.py` | One source of human-readable explanations for every error and reason code, served at `GET /api/reasons`, printed by the CLI. |
| Tooling | `scripts/load_test.py`, `scripts/security_smoke.py`, `scripts/demo_services.py` | Load/reliability scenario, offline end-to-end security smoke, offline fake model/provider for demos. |
| Tests | `tests/` | Unit, integration (real server processes, real WebSocket clients), security, environment, concurrency and Web UI tests. Model/provider are always faked. |
| Packaging | `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml` | Container image with health check, compose service with persistent volume, CI pipeline (compile, tests, smoke, Docker build probe). |

## 3. Protocol

Transport: WebSocket at `/ws`. Each text frame carries exactly one JSON object.
WebSocket framing removes the need for a custom length prefix; the inbound frame
limit is 64 KiB (`ws_max_size`), and oversized frames close the connection.

Request envelope:

```json
{"id": "k3x9-1a2b3c", "action": "send_message", "token": "<session token>", "room_name": "General", "content": "hello"}
```

* `id`: unique client-chosen string, 1-64 characters, echoed in the response so
  a client with one socket can correlate concurrent requests and interleaved events.
* `action`: one of `signup`, `login`, `list_groups`, `create_group`, `join_group`,
  `leave_group`, `select_room`, `history`, `send_message`.
* `token`: required for every action except `signup`/`login`. The server derives
  the user from the token; client-supplied `user_id`/`username` fields are ignored.

Response envelope: `{"type": "response", "id": ..., "action": ..., "ok": true, ...}`
or `{"type": "response", "id": ..., "ok": false, "error": "<code>"}`. Security
rejections add `"security": {"action", "risk_score", "source", "reason_code"}`.
Malformed envelopes get `id: null` with `invalid_json` or `invalid_request`.

Event envelope (server push): `{"type": "event", "action": "room_message",
"room_name", "room_id", "message_id", "sender_id", "username", "content"}`.

REST: `GET /health` → `{"ok": true, "status": "healthy"}` (liveness only).
`GET /api/reasons` → display text for every error/reason code. `GET /` and
`/static/*` serve the Web UI.

Error codes: `invalid_request`, `invalid_json`, `unsupported_operation`,
`unauthenticated`, `invalid_username`, `invalid_password`, `username_taken`,
`invalid_credentials`, `invalid_room_name`, `group_not_found`,
`group_already_exists`, `already_member`, `not_active_member`,
`room_not_selected`, `internal_error`. Security reason codes: `forbidden_term`,
`recipe_blocked`, `security_check_unavailable`, `malicious_url`,
`reputation_review_required`, `reputation_unavailable`.

## 4. Concurrency and thread model

* **One process, one asyncio event loop** (uvicorn). Every WebSocket connection is
  a coroutine; the loop multiplexes thousands of idle sockets cheaply.
* **Blocking work runs in worker threads** via `asyncio.to_thread`: bcrypt hashing,
  every SQLite call, the DLP rules, the local-model HTTP call and the VirusTotal
  HTTP call. The event loop never blocks on CPU or network I/O. This satisfies the
  "multithreaded server" requirement while keeping socket handling simple.
* **`app.state.operations` (asyncio lock)** serializes state transitions that must
  be atomic relative to each other: validating a request against connection state,
  updating `selected_room`, taking the recipient snapshot for a broadcast. It is
  *never* held while awaiting socket I/O or while a security adapter waits on the
  model or the provider, so one slow check cannot stall other users or `/health`.
* **Security checks run outside the lock, then revalidate.** `handle_send` validates
  under the lock, releases it, evaluates the policy in a worker thread, then
  reacquires the lock and validates again (session, membership, selection, socket
  still open) before saving and broadcasting. Membership changes during a pending
  check are therefore respected.
* **Per-connection bounded outgoing queue** (256 messages) with one writer task.
  A consumer that stops reading fills its queue and is disconnected instead of
  consuming server memory; a slow writer never blocks the sender.
* **Per-`(user, room)` locks inside `SecurityPolicy`** order attempts so the
  ten-message window is consistent, while unrelated users proceed in parallel.
* **Thread safety of shared caches**: the URL verdict cache uses a lock plus
  per-hostname in-flight locks so concurrent lookups for the same host share one
  provider request.

## 5. Identity, rooms and routing

* Signup validates and normalizes the username (trim, lowercase, `[a-z0-9_]{3,20}`),
  enforces the password policy, runs the DLP name check, then stores a bcrypt hash.
  Duplicate usernames are rejected (case-insensitive unique index plus a check).
* Login verifies the hash and issues a random 256-bit token kept in memory. Tokens
  live for the server process; there is no expiry (documented limitation).
* Every protected action resolves the token to a user id on the server. A
  connection becomes "authenticated" only through a successful token-bearing
  request; unauthenticated connections receive no events.
* Rooms are public groups. Membership is stored (`room_members`, with `left_at`
  for leave/rejoin). **Selection** is per connection, not per user: a message is
  delivered live only to connections that have that room selected *and* whose
  user is still an active member. Clients in other rooms receive nothing; history
  is available to active members for messages missed while away.
* Sending requires membership *and* selection on that connection
  (`room_not_selected` otherwise), so the recent-attempt window and the delivery
  target always agree.

## 6. Security pipeline (DLP and Anti-Bot)

Order, per message, before anything is stored or delivered:

```text
authenticate → validate fields → active member? → room selected?
  → deterministic DLP (rules)            score 100 → block forbidden_term
  → local LLM review if score 30-99      block → recipe_blocked / unavailable → security_check_unavailable
  → URL reputation for every URL         2+ malicious → malicious_url
                                         review verdicts → reputation_review_required
                                         provider failure → reputation_unavailable
  → save to SQLite → broadcast to selected active members
```

* **DLP (sensitive information)**: the protected term is the pineapple secret;
  aliases, one-edit typos, leetspeak/homoglyph substitutions and separator
  evasions are matched after NFKC/casefold normalization. Recipe disclosure is
  scored from clues (anchor, ingredients, quantity, action, time/temperature,
  sequence markers, several categories) across the current attempt and up to ten
  prior attempts in that room, including blocked attempts, so splitting a recipe
  across messages still accumulates. Usernames and room names get the
  deterministic name check only.
* **Anti-Bot (malicious addresses)**: URLs are extracted from the original text,
  normalized, deduplicated and checked by hostname against VirusTotal's existing
  domain reports. Two or more malicious engine detections block; one detection,
  suspicious flags, unknown/stale reports and unsupported hosts are "review",
  which the policy conservatively blocks. Provider failure blocks with
  `reputation_unavailable` and is not cached, so the next attempt retries.
* **Visible actions and reasons**: every rejection carries the reason code and a
  `security` object (action, risk_score, source, reason_code). The Web UI shows
  them in a "Security decisions" panel and a banner; the CLI prints them; the
  server logs `security operation=... action=... score=... source=... reason=...`.
* **Fail closed everywhere**: a missing model, missing API key, timeout, malformed
  response or rate limit never results in delivery.
* **Privacy in logs and responses**: no passwords, tokens, API keys, model output,
  full URLs or blocked message bodies are logged or echoed. Only hostnames reach
  the provider; the linked page is never fetched.

## 7. Validation, recovery and logs

* Invalid input gets a stable error code and, via `/api/reasons`, a human
  explanation. Malformed JSON, non-object frames, bad ids, unknown actions,
  empty content, un-trimmed room names and oversized frames are all rejected
  without affecting other connections.
* A client can disconnect at any time; the server drops its connection state,
  cancels its writer and logs `connection_close`. Sessions and memberships are
  server-side, so on reconnect the client re-presents its token (Web UI does this
  automatically and re-selects the room) or logs in again (CLI), and history shows
  everything missed. The server keeps serving other clients throughout.
* `chat.log` (path from `CHAT_LOG`) records `server_start`, `connection_open`,
  `auth action=...`, `request action=... user=... ok=... error=...`,
  `security operation=...`, `slow_client_disconnect`, `malformed_request`,
  `connection_close`. The Web UI's protocol log shows the client-side view of the
  same exchange, which makes a demonstrated event explainable from both ends.

## 8. Configuration and deployment

Environment variables (loaded from `.env` next to `server.py`, OS values win) are
documented in the README table. `CHAT_DATABASE` and `CHAT_LOG` relocate the data
files; the Docker image sets them to `/data` on a named volume. Run exactly one
server process: sessions, selections, security windows and caches are in memory.

## 9. Known limitations

Plain `ws://` on a lab LAN (no TLS); in-memory sessions without expiry; unpaginated
history; heuristic DLP with possible false positives/negatives; hostname-level
reputation only; the local model cannot be reached from inside Docker unless the
container shares the host network (Linux) or the endpoint is otherwise loopback;
single-process design bounds capacity to one machine. See DEMO.md for the honest
limitation chosen for the presentation.
