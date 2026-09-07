"""Rendered UI checks against the existing server; external security services are controlled."""
from http.server import ThreadingHTTPServer
import threading

import pytest
from test_security_integration import secured_server
from ui.serve import UIHandler

playwright = pytest.importorskip('playwright.sync_api')


@pytest.fixture
def ui_address():
    class QuietHandler(UIHandler):
        def log_message(self, *args):
            pass

    http = ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{http.server_port}'
    finally:
        http.shutdown()
        http.server_close()
        thread.join(5)


def login(page, name):
    page.locator('#username').fill(name)
    page.locator('#password').fill('Password1')
    page.locator('#auth-submit').click()
    playwright.expect(page.locator('#chat-view')).to_be_visible()
    playwright.expect(page.locator('#refresh-rooms')).to_be_enabled()


def register(page, ui_address, uri, name):
    page.goto(ui_address)
    page.locator('#address').fill(uri)
    page.locator('#connect').click()
    playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
    page.locator('#signup-tab').click()
    page.locator('#username').fill(name)
    page.locator('#password').fill('Password1')
    page.locator('#auth-submit').click()
    playwright.expect(page.locator('#notice')).to_have_text('Account created. Log in with your new account.')
    playwright.expect(page.locator('#chat-view')).to_be_hidden()
    playwright.expect(page.locator('#password')).to_have_value('')
    login(page, name)


def send(page, text):
    page.locator('#message').fill(text)
    page.locator('#send').click()


def test_rendered_chat_security_and_reconnect(secured_server, ui_address, tmp_path):
    controls = secured_server
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            alice = browser.new_page(viewport={'width': 1440, 'height': 1000})
            bob = browser.new_page(viewport={'width': 390, 'height': 844})
            errors = []
            alice.on('pageerror', lambda error: errors.append(str(error)))
            bob.on('pageerror', lambda error: errors.append(str(error)))
            alice.goto(ui_address)
            alice.screenshot(path=str(tmp_path / 'ui-welcome.png'), full_page=True)
            register(alice, ui_address, controls.uri, ' ALICE ')
            register(bob, ui_address, controls.uri, 'bobby')
            alice.locator('#room-name').fill('General')
            alice.get_by_role('button', name='Create', exact=True).click()
            playwright.expect(alice.locator('#room-title')).to_have_text('# General')
            bob.locator('#refresh-rooms').click()
            bob.get_by_role('button', name='Join General', exact=True).click()
            playwright.expect(bob.locator('#room-title')).to_have_text('# General')
            send(alice, '<img src=x onerror=alert(1)> hello')
            playwright.expect(bob.locator('.message-body')).to_have_text('<img src=x onerror=alert(1)> hello')
            assert bob.locator('#messages img').count() == 0
            playwright.expect(alice.locator('#send')).to_be_enabled()
            alice.locator('#history').click()
            playwright.expect(alice.locator('#send')).to_be_enabled()
            assert alice.locator('.message-body').count() == 1
            assert 'alice' in alice.locator('.message-meta').inner_text()

            controls.slow = 'llm'
            controls.mode = 'block'
            send(alice, 'pizza 200 g flour')
            assert controls.entered.wait(3)
            playwright.expect(alice.locator('#send-status')).to_have_text('Checking message…')
            send(bob, 'hello while checking')
            playwright.expect(alice.locator('.message-body').last).to_have_text('hello while checking')
            assert alice.locator('.message-body').count() == 2
            alice.locator('#message').fill('my next draft')
            controls.release.set()
            playwright.expect(alice.locator('#notice')).to_have_text('This message was blocked by the security policy.')
            playwright.expect(alice.locator('#message')).to_have_value('my next draft')
            controls.slow = None
            send(alice, 'pineapple')
            playwright.expect(alice.locator('#notice')).to_have_text('This name or message is not allowed.')
            alice.locator('#history').click()
            playwright.expect(alice.locator('#send')).to_be_enabled()
            assert alice.locator('.message-body').count() == 2

            alice.locator('#room-name').fill('Other')
            alice.get_by_role('button', name='Create', exact=True).click()
            playwright.expect(alice.locator('#room-title')).to_have_text('# Other')
            playwright.expect(alice.locator('#send')).to_be_enabled()
            send(bob, 'catch up later')
            playwright.expect(bob.locator('#send')).to_be_enabled()
            assert alice.locator('.message-body').count() == 0
            alice.get_by_role('button', name='Select General', exact=True).click()
            playwright.expect(alice.locator('.message-body')).to_have_count(3)
            alice.screenshot(path=str(tmp_path / 'ui-chat.png'), full_page=True)
            bob.screenshot(path=str(tmp_path / 'ui-mobile.png'), full_page=True)
            assert bob.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            assert alice.evaluate('localStorage.length + sessionStorage.length') == 0

            alice.locator('#leave').click()
            playwright.expect(alice.locator('#room-title')).to_have_text('Select a room')
            alice.get_by_role('button', name='Select General', exact=True).click()
            playwright.expect(alice.locator('#notice')).to_have_text('You are not a member of this room. Join it first.')
            alice.get_by_role('button', name='Join General', exact=True).click()
            playwright.expect(alice.locator('.message-body')).to_have_count(3)
            alice.locator('#connect').click()
            playwright.expect(alice.locator('#connection-status')).to_have_text('Connected')
            playwright.expect(alice.locator('#auth-view')).to_be_visible()
            assert alice.locator('.message-body').count() == 0
            login(alice, 'alice')
            playwright.expect(alice.locator('#send')).to_be_disabled()
            alice.get_by_role('button', name='Select General', exact=True).click()
            playwright.expect(alice.locator('.message-body')).to_have_count(3)
            alice.locator('#disconnect').click()
            playwright.expect(alice.locator('#connection-status')).to_have_text('Disconnected')
            assert not errors
        finally:
            controls.release.set()
            browser.close()
