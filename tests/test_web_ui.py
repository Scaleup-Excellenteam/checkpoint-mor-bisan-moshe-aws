"""Web UI delivery: static assets, REST reason catalog, and code-catalog consistency.

The browser-driven end-to-end scenario lives in tests/test_web_ui_browser.py and
is skipped when Playwright is not installed; these tests need only the server.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from chat_system import reason_codes
from scripts.load_test import stop_process

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
ACTIONS = ("signup", "login", "list_groups", "create_group", "join_group",
           "leave_group", "select_room", "history", "send_message")


@pytest.fixture
def http_server(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "CHAT_DATABASE": str(tmp_path / "ui.db"), "CHAT_LOG": str(tmp_path / "ui.log"),
           "PYTHON_DOTENV_DISABLED": "1"}
    output = (tmp_path / "process.log").open("w")
    proc = subprocess.Popen([sys.executable, "server.py", "--host", "127.0.0.1", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=output, stderr=output)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=.2).close()
                break
            except OSError:
                if proc.poll() is not None:
                    pytest.fail("Server exited during startup")
                time.sleep(.1)
        else:
            pytest.fail("Server startup timeout")
        yield f"http://127.0.0.1:{port}"
    finally:
        stop_process(proc)
        output.close()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, response.headers.get("content-type", ""), response.read()


def test_web_ui_and_rest_endpoints(http_server):
    status, content_type, body = get(http_server + "/")
    page = body.decode("utf-8")
    assert status == 200 and content_type.startswith("text/html")
    assert "TSPO Secret Slice Chat" in page
    for asset in ("/static/app.js", "/static/styles.css"):
        assert asset in page
        asset_status, _, asset_body = get(http_server + asset)
        assert asset_status == 200 and asset_body == (STATIC / asset.rsplit("/", 1)[-1]).read_bytes()
    for element in ("auth-form", "room-list", "messages", "send-form", "decisions", "protocol-log",
                    "btn-disconnect", "btn-reconnect"):
        assert f'id="{element}"' in page

    status, content_type, body = get(http_server + "/health")
    assert status == 200 and json.loads(body) == {"ok": True, "status": "healthy"}

    status, content_type, body = get(http_server + "/api/reasons")
    catalog = json.loads(body)
    assert status == 200 and content_type.startswith("application/json")
    assert catalog == {"security": reason_codes.SECURITY_REASONS, "errors": reason_codes.REQUEST_ERRORS}
    assert {"forbidden_term", "recipe_blocked", "malicious_url"} <= set(catalog["security"])
    for entry in catalog["security"].values():
        assert entry["control"] in {"DLP", "Anti-Bot"} and entry["title"] and entry["explanation"]

    with pytest.raises(urllib.error.HTTPError) as missing:
        get(http_server + "/static/does-not-exist.js")
    assert missing.value.code == 404


def test_browser_client_speaks_the_full_protocol_safely():
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for action in ACTIONS:
        assert f'"{action}"' in script, action
    # Rendering must never interpret user-controlled text as markup or code.
    assert "innerHTML" not in script and "eval(" not in script and "document.write" not in script
    assert "textContent" in script
    # Identity must come from the server: the client never sends user_id or username on messages.
    assert "user_id" not in script
    assert 'request("send_message", { room_name: state.room, content })' in script
    # Tokens and passwords are redacted from the on-screen protocol log.
    assert '"<token>"' in script and '"<hidden>"' in script


def test_reason_catalog_covers_every_server_and_policy_code():
    server_source = (ROOT / "server.py").read_text(encoding="utf-8")
    policy_source = (ROOT / "chat_system" / "security_policy.py").read_text(encoding="utf-8")
    auth_source = (ROOT / "chat_system" / "auth.py").read_text(encoding="utf-8")
    db_source = (ROOT / "chat_system" / "database.py").read_text(encoding="utf-8")
    emitted_errors = set(re.findall(r'error\("([a-z_]+)"\)', server_source))
    emitted_errors |= set(re.findall(r'"error": "([a-z_]+)"', auth_source + db_source))
    emitted_errors |= set(re.findall(r'InvalidRequest\("([a-z_]+)"\)', server_source))
    policy_blocks = set(re.findall(r"SecurityDecision\('block', '([a-z_]+)'", policy_source))
    catalog = set(reason_codes.SECURITY_REASONS) | set(reason_codes.REQUEST_ERRORS)
    assert emitted_errors <= catalog, emitted_errors - catalog
    assert policy_blocks <= set(reason_codes.SECURITY_REASONS), policy_blocks - set(reason_codes.SECURITY_REASONS)
    for code in sorted(catalog):
        assert reason_codes.describe(code)
    assert reason_codes.describe("made_up_code") == ""
