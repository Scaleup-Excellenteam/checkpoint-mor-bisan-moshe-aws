# CheckPoint Bootcamp: Chat System

A runnable public-group chat with signup/login, persistent SQLite messages,
room creation/listing, join/leave/rejoin, room selection, history, and live delivery.
Only authenticated active members can send, read history, or receive room events.

## Setup (PowerShell, Python 3.12 tested; Python 3.10+ required)

Install Python and run from this repository:

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

If `python` resolves to the Windows Store stub, use your installed Python's full
path for the first command. Server startup initializes the database automatically;
no separate initialization step is required.

Start the server:

```powershell
./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000
```

In each of two other terminals, start a client:

```powershell
./.venv/Scripts/python.exe client.py --uri ws://127.0.0.1:8000/ws
```

On other laptops replace `127.0.0.1` with the server laptop's LAN address and
allow inbound port 8000 through its firewall. Health: `http://127.0.0.1:8000/health`.

## Demo

Use menu 1 to sign up and menu 2 to log in on each client. Usernames are trimmed,
lowercased, and must contain 3–20 letters a–z, digits or underscores. Passwords
are 8–32 characters using letters, digits and `@#$%^&*`, with two categories.

On client A enter `/create General`; on B enter `/join General`. Both select the
room automatically. Enter ordinary text to chat; `/history` shows stored messages.
`/list` lists rooms; `/select General` selects an existing active membership.
`/leave General` stops delivery; `/join General` reactivates membership.
Create/join another room on a third client to demonstrate isolation.
`/reconnect` reconnects and prompts for login; `/quit` exits cleanly.
Events from every room you actively belong to display with a room label; selection
controls where your outgoing messages and history requests go.

## Architecture and protocol

- `server.py`: FastAPI `/ws` and REST `/health`. One process uses asynchronous
  connection I/O and worker threads for blocking bcrypt/SQLite operations. An
  async lock orders operations and membership snapshots; no socket I/O runs under
  it. Each connection has a bounded outgoing queue and one writer. Slow consumers
  are disconnected. This deliberately favors simple ordering over throughput.
- `client.py`: network client with one reader, request futures and an event queue.
  `cli.py` preserves the signup/login menu and handles interactive commands.
- `auth.py`: bcrypt with generated salts, normalization, credential verification,
  and cryptographically random in-memory tokens. `database.py`: parameterized SQL,
  transactions and short-lived connections with foreign keys; `schema.sql` unchanged.
- Repository pattern: the database module centralizes persistence, at the cost of
  explicit SQL functions. Observer/pub-sub pattern: room members subscribe through
  membership and receive server events, requiring disconnect and backpressure handling.

Each WebSocket text message contains one JSON object; WebSocket framing handles
partial/coalesced TCP traffic. Requests use a unique string `id` (1–64 characters),
`action`, and `token` for protected operations. Responses contain `type: response`,
matching `id`, `ok`, and either result fields or stable `error`. Malformed envelopes
may return `id: null`. Events use `type: event`, `action: room_message`, room and
message fields. Maximum inbound message size is 64 KiB; oversized frames can close
the connection. No identity is taken from a client-supplied user ID.

Actions: `signup`, `login` (username/password); `list_groups`; `create_group`,
`join_group`, `leave_group`, `select_room`, `history` (room_name);
`send_message` (room_name/content). Auth errors: `invalid_username`,
`invalid_password`, `username_taken`, `invalid_credentials`. Other errors include
`unauthenticated`, `invalid_request`, `invalid_json`, `unsupported_operation`,
`invalid_room_name`, `group_not_found`, `group_already_exists`, `already_member`,
`not_active_member`, and `internal_error` for unexpected failures.

## Verification and configuration

```powershell
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/python.exe -m compileall -q auth.py database.py server.py client.py cli.py tests
```

Tests use temporary databases, isolated ports, real server subprocesses, three
network clients, and a scripted CLI. They cover auth, membership/history, persistence,
room isolation, malformed input, leave/rejoin, reconnect, and health. The CLI smoke
uses piped input; interactive terminals hide passwords with getpass.

`CHAT_DATABASE` overrides the default repository `chat.db`; `CHAT_LOG` overrides
`chat.log`. Logs contain event metadata, not passwords, tokens or message bodies.
Both generated files and the virtual environment are ignored by Git.

Sessions are process-local, have no expiration and disappear on server restart;
run one server worker. Membership persists across disconnects. History is currently
unpaginated. Unexpected network loss requires restarting the CLI. This lab setup
uses unencrypted `ws://`; TLS is not configured. Cross-laptop connectivity must be
verified on the actual LAN. Day 2 DLP/Anti-Bot, Docker, CI/CD and load testing are
not implemented.
