# Deployment: Docker packaging and CI/CD

## Docker

The image bundles the server, the Web UI and the CLI. Data (SQLite database and
log) lives on a volume at `/data`.

Build and run with Docker:

```powershell
docker build -t tspo-chat .
docker run --rm -p 8000:8000 -v tspo-data:/data --env-file .env tspo-chat
```

Or with Compose (reads `.env` if present; it is optional):

```powershell
docker compose up --build
docker compose logs -f chat
docker compose down            # add -v to also delete the data volume
```

Then open `http://localhost:8000/` (Web UI) or `http://localhost:8000/health`.
Teammates on the LAN connect to `http://<host-ip>:8000/` or
`ws://<host-ip>:8000/ws` with the CLI; the host firewall must allow inbound TCP 8000.

Image facts:

* Base `python:3.12-slim`, dependencies from `requirements.txt`, non-root user.
* `HEALTHCHECK` probes `GET /health` every 15 s; `docker ps` shows `healthy`.
* `CHAT_DATABASE=/data/chat.db` and `CHAT_LOG=/data/chat.log` are set in the
  image; override with `-e` if needed.
* Secrets are passed at run time (`--env-file .env` or `-e VIRUSTOTAL_API_KEY=...`);
  `.dockerignore` excludes `.env`, databases, logs, tests and docs from the build
  context so no key is baked into a layer.

Limitation: the local classifier adapter accepts only loopback endpoints. Inside
a container, "loopback" is the container itself, so an Ollama instance on the host
is not reachable. Options: run the container with `--network host` (Linux only),
run Ollama in the same container/network namespace, or accept that review-range
recipe messages are rejected with `security_check_unavailable` in Docker. URL
reputation works from the container as long as it has outbound HTTPS and a key.

## CI/CD (GitHub Actions)

Workflow file: `.github/workflows/ci.yml`.

**Trigger:** every `push` to any branch and every `pull_request`.

**Job `test`** (Ubuntu, Python 3.12):

1. Check out and install `requirements.txt` (pip cache).
2. `python -m compileall` over the package, entry points, tests and scripts.
3. `pytest -q`: unit tests, real-server integration tests, security tests with
   fakes, environment tests, concurrency scenario and Web UI tests. No secrets
   are needed; `PYTHON_DOTENV_DISABLED=1` keeps a developer `.env` out of CI.
4. `scripts/security_smoke.py`: real server and clients against controlled
   loopback model/provider fixtures.

**Job `ui-e2e`** (Ubuntu): installs Playwright's Chromium and runs
`tests/test_web_ui_browser.py`, which drives two browser contexts through
signup, login, rooms, live chat, DLP and Anti-Bot rejections, disconnect and
reconnect. It runs after `test` and is isolated so a browser flake does not mask
a server failure.

**Job `docker`** (runs after `test`): builds the image, starts a container,
polls `GET /health` until it answers, asserts `"ok":true` and that `GET /`
serves the Web UI, prints container logs and removes the container.

Evidence of a run is the Actions tab of the repository (green check on the
commit). Locally the same steps are:

```powershell
$env:PYTHON_DOTENV_DISABLED = "1"
./.venv/Scripts/python.exe -m compileall -q chat_system server.py client.py cli.py tests scripts
./.venv/Scripts/python.exe -m pytest -q
./.venv/Scripts/python.exe scripts/security_smoke.py
docker build -t tspo-chat .
Remove-Item Env:PYTHON_DOTENV_DISABLED
```

## Load testing

`scripts/load_test.py` starts a temporary server, drives N clients through
signup, rooms, concurrent sends, isolation checks, reconnect and restart, and
prints attempted/successful/failed counts and latency percentiles.
`tests/test_concurrency.py` runs the small scenario in the normal suite. Results
and findings are in [LOAD_TEST_REPORT.md](LOAD_TEST_REPORT.md).

```powershell
./.venv/Scripts/python.exe scripts/load_test.py --clients 3 --messages 2
./.venv/Scripts/python.exe scripts/load_test.py --clients 8 --messages 10
```
