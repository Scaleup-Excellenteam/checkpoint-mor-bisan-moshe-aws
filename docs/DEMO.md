# Demo script and lessons learned

A rehearsed walkthrough that covers every item of the final demo checklist and
the rubric, followed by the findings we present. Commands are PowerShell from the
repository root on the server laptop; teammates only need a browser.

## 0. Prepare (5 minutes before)

```powershell
./.venv/Scripts/python.exe -m pytest -q          # expect all green
ipconfig                                        # note the server laptop's LAN IPv4, e.g. 192.168.1.50
```

Choose one of the two service setups:

* **Real services** (preferred if available): Ollama running locally with
  `qwen2.5:1.5b` pulled, and `VIRUSTOTAL_API_KEY` set in `.env`.
* **Offline fixtures** (no internet, no keys): in a second terminal run
  `./.venv/Scripts/python.exe scripts/demo_services.py`, then copy the printed
  `$env:` lines into the terminal that will start the server. Fixture hosts:
  `evil.example.com` blocks, `review.example.com` needs review, anything else
  is allowed. The real adapters and policy are unchanged; only the endpoints differ.

Start the server:

```powershell
./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000
```

Allow inbound TCP 8000 on the private firewall profile if teammates cannot reach it.

## 1. Start the system and show health

* Browser on any laptop: `http://192.168.1.50:8000/` shows the Web UI with the
  connection pill **connected** and the health pill **health: healthy**.
* Also show `http://192.168.1.50:8000/health` raw and `/api/reasons`
  (small REST API alongside the WebSocket).
* Point at the server terminal: `server_start`, `connection_open peer=...`.

## 2. Identity checks

Laptop A (browser), Identity card:

1. Sign up `alice` / `Password1` → "Account created. Now log in."
2. Sign up `alice` again → `username_taken` (duplicate rejected).
3. Log in `alice` / `Wrong123` → `invalid_credentials`.
4. Log in `alice` / `Password1` → "Logged in as alice", rooms card enables.
5. Sign up `pineapple` / `Password1` → `forbidden_term` with a **DLP** badge in
   Security decisions (names are checked too).

Unauthenticated enforcement: on laptop C open the UI, do **not** log in, and use
the CLI to prove it on the server side:

```powershell
./.venv/Scripts/python.exe client.py --uri ws://192.168.1.50:8000/ws
# choose 2 (login) with a wrong password → invalid_credentials
```

or open the browser devtools console on the un-logged-in page and run
`new WebSocket("ws://192.168.1.50:8000/ws")` … then send
`{"id":"x","action":"join_group","room_name":"General"}` → `unauthenticated`.
Server log shows `request action=join_group user=None ok=False error=unauthenticated`.

Passwords are stored as bcrypt hashes with per-password salt:

```powershell
./.venv/Scripts/python.exe -c "import sqlite3; print(sqlite3.connect('chat.db').execute('select username, substr(password_hash,1,29) from users').fetchall())"
```

## 3. Chat between laptops

* Laptop A: Create room `General` (it opens automatically).
* Laptop B (another laptop, browser or CLI): sign up `bobby`, log in, click
  **Join** on `General`.
* Both type messages; they appear live on both sides with the server-authoritative
  username and message id.
* Laptop C: sign up `carol`, log in, create room `Other`. Messages in `General`
  do not reach C (room isolation). Have C **Join** General and then **Open**
  Other again: selection is per connection, history still shows General's
  messages via **Reload history**.

## 4. Security decisions (DLP and Anti-Bot)

All on laptop A in `General`, watching the Security decisions panel and laptop B:

| Send | Expected | Why |
| --- | --- | --- |
| `I love pizza` | delivered | ordinary pizza talk is allowed (low recipe score) |
| `pineapple` | **block · DLP · forbidden_term**, score 100 | protected term |
| `p!ne@pple`, `pine apple`, `ananas` | same block | leetspeak/separator/alias evasions |
| `https://evil.example.com/login` (fixtures) or a known-bad host with a real key | **block · Anti-Bot · malicious_url** | 2+ malicious engine detections |
| `https://review.example.com` | **block · Anti-Bot · reputation_review_required** | single detection: uncertain, not delivered |
| `https://safe.example.com/a` then `https://safe.example.com/b` | delivered; server log shows one provider call | 24 h hostname verdict cache |
| Stop `demo_services.py`, send `https://other.example.com` | **block · reputation_unavailable** | provider down → fail closed, not cached |
| **Last:** `pizza dough: 500 g flour` then `knead and bake at 250 C for 12 minutes` | **block · DLP · recipe_blocked** (fixtures or real model) or `security_check_unavailable` if no model | clues accumulate across recent messages, model resolves review |

Do the recipe step **last** (or from another user/room): the ten-attempt window
keeps the recipe clues hot, so the same user's next messages in that room are
also sent to review until ten more attempts have passed. That is the intended
"split the recipe across messages" defence, and it is worth saying out loud.

Show on laptop B that none of the blocked messages arrived, click **Reload
history** to show they were never stored, and read the server log line:
`security operation=send_message user=1 room=1 action=block score=100 source=policy reason=forbidden_term`.

## 5. Recovery

* Laptop B: click **Disconnect** (pill turns red, server logs `connection_close`).
* Laptop A sends `while you were away`.
* Laptop B: **Reconnect** → pill green, "Reconnected: room General selected
  again", history reloads including the missed message. Server log shows a new
  `connection_open` and the `select_room` request.
* Also kill the CLI client with Ctrl+C and restart it: the server never stopped.
* Invalid input: in the Web UI send an empty message (disabled) or via CLI send
  `/create   ` → `invalid_room_name`; raw `broken json` via a websocket client →
  `invalid_json`; the connection and other users are unaffected.

## 6. Explain the engineering

* Architecture and protocol: [ARCHITECTURE.md](ARCHITECTURE.md) (one process,
  asyncio loop + worker threads, operations lock never held during I/O, bounded
  per-connection queues).
* Patterns: Strategy/DI for the security pipeline, Observer for room routing,
  plus Repository and Adapter ([DESIGN_PATTERNS.md](DESIGN_PATTERNS.md)).
* Tests: `pytest -q` runs real server processes, real WebSocket clients, a
  scripted CLI, DLP/policy/LLM/URL unit tests with fakes, environment tests,
  a concurrency scenario and the Web UI tests. CI runs them on every push and
  builds the Docker image.
* Teamwork: four owners on four branches (`codex/person1-dlp-policy`,
  `LLM/bisan`, `aws/url-security`, `person-4/load-reliability`) against frozen
  contracts merged first; one integrator branch; final delivery branch adds the
  UI, packaging and docs. Ownership is recorded in `COMMON_SECURITY_DECISIONS.md`.

## 7. A test that exposed a problem, the fix, and the retest

**Finding 1 — client-supplied identity leaked into live chat.** An early
end-to-end test sent `send_message` with an extra `username: "bobby"` field from
Alice's connection and asserted the event carried `alice`. It failed: the
broadcast echoed the request payload. Fix (commit `c3ee647`): `save_message`
joins `users` and returns the stored username; the server builds the event from
the database result only. Retest: `tests/test_day1.py::test_real_websocket_flow`
asserts `sent['username'] == 'alice'` and the events contain no `token` or
`password_hash`; `tests/test_web_ui.py` additionally asserts the browser client
never sends `user_id`.

**Finding 2 — messages leaked to members who were viewing another room.**
`test_selected_room_routing` was written to pin down the room model: a member of
two rooms with room A selected received live events for room B. Fix (commit
`a2b667d`): delivery requires `selected_room == room_id` per connection *and*
active membership; leaving clears the selection on every connection of that
user. Retest: the test now passes, including reconnect (selection is not
restored implicitly) and rejoining from another connection.

**Finding 3 — a slow security check could have frozen everyone.** While wiring
the policy, `test_slow_security_health_other_clients_and_revalidation` paused
the fake model/provider and asserted that another user's send and `/health`
complete within two seconds and that a membership change during the pause is
honoured. The first implementation held the shared lock across the check. Fix
(commit `40077fa`): run the policy outside the lock, revalidate before saving,
and serialize only per `(user, room)` inside the policy. Retest: the parametrized
test passes for both the LLM and URL slow paths, and the load report shows no
latency regression at 8 clients (`docs/LOAD_TEST_REPORT.md`).

**Finding 4 — Windows teardown left a launcher child holding the log file.**
The load harness failed cleanup with `PermissionError`. Fix: `stop_process`
stops the owned process tree on Windows; all subprocess-based tests share it.

## 8. Lessons learned and honest limitations

* **Freeze the contract before splitting the work.** The one-file contract plus
  a decisions document let four modules merge without conflicts.
* **Fail closed is a product decision, not just a default.** With no model or
  key configured, review-range recipe text and every URL are rejected; the demo
  must say so and show the reason code, not hide it.
* **Selection is per connection, membership per user.** Most routing bugs came
  from conflating the two; naming them separately in code and docs fixed the
  reasoning.
* **Limitation we present:** sessions are in memory with no expiry and the
  server is a single process on plain `ws://`; a restart logs everyone out, and
  capacity is bounded by one laptop. Next improvement: persist sessions with
  expiry, put TLS in front, and page history.
* **Bonus status:** Docker image and compose file build and serve the UI
  (`docs/DEPLOYMENT.md`); GitHub Actions runs compile, tests, smoke and the Docker
  probe on every push; the load harness and report exist
  (`scripts/load_test.py`, `docs/LOAD_TEST_REPORT.md`). The local model is not
  reachable from inside the container unless it shares the host network.
