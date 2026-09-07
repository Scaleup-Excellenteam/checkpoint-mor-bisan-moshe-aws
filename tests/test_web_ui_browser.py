"""Browser end-to-end scenario for the Web UI (Playwright; skipped when unavailable).

Two browser contexts act as two laptops against a real server subprocess whose
model/provider endpoints point at the offline demo fixtures from
scripts/demo_services.py, so DLP and Anti-Bot verdicts are shown without network.

Install locally with ``pip install playwright`` (uses the installed Edge/Chrome)
or ``playwright install chromium`` (as CI does).
"""
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts.demo_services import DemoServices
from scripts.load_test import stop_process

playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import expect  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Password1"


@pytest.fixture
def demo_stack(tmp_path):
    fixtures = ThreadingHTTPServer(("127.0.0.1", 0), DemoServices)
    DemoServices.llm_mode = "auto"
    fixture_thread = threading.Thread(target=fixtures.serve_forever, daemon=True)
    fixture_thread.start()
    base = f"http://127.0.0.1:{fixtures.server_port}"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ,
           "PYTHON_DOTENV_DISABLED": "1",
           "CHAT_DATABASE": str(tmp_path / "ui.db"), "CHAT_LOG": str(tmp_path / "ui.log"),
           "LOCAL_LLM_ENDPOINT": base + "/api/generate", "LOCAL_LLM_MODEL": "demo-fixture",
           "LOCAL_LLM_TIMEOUT_SECONDS": "5",
           "VIRUSTOTAL_API_BASE_URL": base + "/domains", "VIRUSTOTAL_API_KEY": "TEST_ONLY_KEY",
           "URL_REPUTATION_REQUEST_TIMEOUT_SECONDS": "5", "URL_REPUTATION_RATE_LIMIT_PER_MINUTE": "100"}
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
        yield f"http://127.0.0.1:{port}", tmp_path / "ui.log"
    finally:
        stop_process(proc)
        output.close()
        fixtures.shutdown()
        fixtures.server_close()


@pytest.fixture
def browser():
    with playwright.sync_playwright() as p:
        last_error = None
        for kwargs in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
            try:
                instance = p.chromium.launch(headless=True, **kwargs)
                break
            except Exception as exc:  # browser binary not available in this mode
                last_error = exc
        else:
            pytest.skip(f"No Chromium-based browser available for Playwright: {last_error}")
        try:
            yield instance
        finally:
            instance.close()


def open_client(browser, url):
    page = browser.new_context().new_page()
    page.goto(url)
    expect(page.locator("#ws-status")).to_have_text("connected")
    expect(page.locator("#health-status")).to_have_text("health: healthy")
    return page


def auth_tab(page, mode):
    page.click(f'.tab[data-mode="{mode}"]')


def sign_up_and_log_in(page, username):
    auth_tab(page, "signup")
    page.fill("#username", username)
    page.fill("#password", PASSWORD)
    page.click("#btn-signup")
    expect(page.locator("#auth-message")).to_contain_text("created")
    # Signup switches to the sign-in tab with the username prefilled.
    expect(page.locator("#username")).to_have_value(username)
    page.fill("#password", PASSWORD)
    page.click("#btn-login")
    expect(page.locator("#me")).to_have_text(username)
    expect(page.locator("#view-chat")).to_be_visible()
    expect(page.locator("#view-auth")).to_be_hidden()


def send(page, text):
    page.fill("#message", text)
    page.click("#btn-send")


def messages(page):
    return page.locator("#messages .msg:not(.system) .text").all_inner_texts()


def test_two_browsers_chat_with_visible_security_decisions_and_recovery(demo_stack, browser):
    url, log_path = demo_stack
    alice = open_client(browser, url)
    bobby = open_client(browser, url)
    guest = open_client(browser, url)

    # Identity: signup, duplicate, wrong password, login, forbidden username.
    sign_up_and_log_in(alice, "alice")
    auth_tab(bobby, "signup")
    bobby.fill("#username", "alice")
    bobby.fill("#password", PASSWORD)
    bobby.click("#btn-signup")
    expect(bobby.locator("#auth-message")).to_contain_text("username_taken")
    auth_tab(bobby, "login")
    bobby.fill("#username", "alice")
    bobby.fill("#password", "Wrong1234")
    bobby.click("#btn-login")
    expect(bobby.locator("#auth-message")).to_contain_text("invalid_credentials")
    expect(bobby.locator("#view-auth")).to_be_visible()
    auth_tab(bobby, "signup")
    bobby.fill("#username", "pineapple")
    bobby.fill("#password", PASSWORD)
    bobby.click("#btn-signup")
    expect(bobby.locator("#auth-message")).to_contain_text("forbidden_term")
    expect(bobby.locator("#decisions .decision.block .badge.control")).to_have_text("DLP")
    sign_up_and_log_in(bobby, "bobby")

    # Unauthenticated browser stays on the sign-in page; chat controls are disabled; nothing is delivered to it.
    expect(guest.locator("#view-auth")).to_be_visible()
    expect(guest.locator("#view-chat")).to_be_hidden()
    expect(guest.locator("#message")).to_be_disabled()
    expect(guest.locator("#btn-refresh-rooms")).to_be_disabled()
    if os.environ.get("UI_SCREENSHOT_PATH"):
        guest.set_viewport_size({"width": 1400, "height": 900})
        guest.screenshot(path=os.environ["UI_SCREENSHOT_PATH"].replace(".png", "-login.png"))

    # Rooms: create, join, live delivery to both, isolation from a non-member.
    alice.fill("#new-room", "General")
    alice.press("#new-room", "Enter")
    expect(alice.locator("#room-title")).to_have_text("# General")
    bobby.click("#btn-refresh-rooms")
    bobby.locator(".room-item", has_text="General").get_by_role("button", name="Join").click()
    expect(bobby.locator("#room-title")).to_have_text("# General")
    send(alice, "I love pizza")
    expect(alice.locator("#messages")).to_contain_text("I love pizza")
    expect(bobby.locator("#messages")).to_contain_text("I love pizza")
    expect(alice.locator("#messages .msg.own .who")).to_have_text("alice")

    # DLP: protected term and an evasion are blocked with visible reason; never delivered.
    for text in ("pineapple", "p!ne@pple"):
        send(alice, text)
        expect(alice.locator("#banner")).to_contain_text("forbidden_term")
        expect(alice.locator("#banner")).to_contain_text("score 100")
    expect(alice.locator("#decisions .decision.block")).to_have_count(2)
    expect(alice.locator("#decisions .decision").first).to_contain_text("DLP")

    # Anti-Bot: malicious, review-required and allowed hostnames.
    send(alice, "look https://evil.example.com/login")
    expect(alice.locator("#banner")).to_contain_text("malicious_url")
    expect(alice.locator("#decisions .decision").first).to_contain_text("Anti-Bot")
    send(alice, "https://review.example.com")
    expect(alice.locator("#banner")).to_contain_text("reputation_review_required")
    send(alice, "docs at https://safe.example.com/guide")
    expect(bobby.locator("#messages")).to_contain_text("https://safe.example.com/guide")

    assert messages(bobby) == ["I love pizza", "docs at https://safe.example.com/guide"]
    assert messages(guest) == []

    # Recovery: bobby disconnects, misses a message, reconnects and catches up, then receives live.
    bobby.click("#btn-disconnect")
    expect(bobby.locator("#ws-status")).to_have_text("disconnected")
    send(alice, "while you were away")
    expect(alice.locator("#messages")).to_contain_text("while you were away")
    bobby.click("#btn-reconnect")
    expect(bobby.locator("#ws-status")).to_have_text("connected")
    expect(bobby.locator("#room-title")).to_have_text("# General")
    expect(bobby.locator("#messages")).to_contain_text("while you were away")
    send(alice, "welcome back")
    expect(bobby.locator("#messages")).to_contain_text("welcome back")
    assert messages(bobby)[-2:] == ["while you were away", "welcome back"]

    # A page reload keeps the session (server-side token) and lands on the chat page.
    bobby.reload()
    expect(bobby.locator("#view-chat")).to_be_visible()
    expect(bobby.locator("#me")).to_have_text("bobby")
    expect(bobby.locator("#room-title")).to_have_text("# General")
    expect(bobby.locator("#messages")).to_contain_text("welcome back")

    # Logging out returns to the sign-in page.
    # Leaving stops delivery; history is refused to non-members.
    bobby.click("#btn-leave")
    expect(bobby.locator("#room-title")).to_have_text("No room selected")
    send(alice, "after bobby left")
    expect(alice.locator("#messages")).to_contain_text("after bobby left")
    bobby.wait_for_timeout(300)
    assert "after bobby left" not in messages(bobby)
    bobby.click("#btn-logout")
    expect(bobby.locator("#view-auth")).to_be_visible()
    expect(bobby.locator("#auth-message")).to_contain_text("Signed out")

    # DLP recipe review resolved by the (fixture) local model. Done last on purpose:
    # the ten-attempt window keeps recipe clues "hot", so later messages by the same
    # user in this room would be reviewed as recipe continuations too.
    send(alice, "pizza dough: 500 g flour, knead and bake 12 minutes")
    expect(alice.locator("#banner")).to_contain_text("recipe_blocked")
    expect(alice.locator("#banner")).to_contain_text("score 85")
    alice.wait_for_timeout(300)
    assert "500 g flour" not in " ".join(messages(alice))

    if os.environ.get("UI_SCREENSHOT_PATH"):  # documentation aid, not an assertion
        alice.set_viewport_size({"width": 1400, "height": 900})
        alice.screenshot(path=os.environ["UI_SCREENSHOT_PATH"])

    # Protocol log redacts secrets; server log records decisions without content.
    protocol_log = alice.locator("#protocol-log").inner_text()
    assert PASSWORD not in protocol_log and '"token":"<token>"' in protocol_log
    server_log = log_path.read_text(encoding="utf-8")
    for reason in ("forbidden_term", "malicious_url", "reputation_review_required", "recipe_blocked"):
        assert f"reason={reason}" in server_log, reason
    assert "connection_close" in server_log
    assert "p!ne@pple" not in server_log and PASSWORD not in server_log
