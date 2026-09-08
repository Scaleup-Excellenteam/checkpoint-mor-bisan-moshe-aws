"""Rendered UI checks against the existing server; external security services are controlled."""
import pytest
from test_security_integration import secured_server

playwright = pytest.importorskip('playwright.sync_api')


@pytest.fixture
def ui_address(secured_server):
    return secured_server.health.removesuffix('/health')


def login(page, name):
    page.locator('#username').fill(name)
    page.locator('#password').fill('Password1')
    page.locator('#auth-submit').click()
    playwright.expect(page.locator('#chat-view')).to_be_visible()
    playwright.expect(page.locator('#refresh-rooms')).to_be_enabled()


def register(page, ui_address, uri, name):
    page.goto(ui_address)
    assert page.locator('#address, #connect, #disconnect').count() == 0
    playwright.expect(page.locator('#health-status')).to_have_text('Server online')
    playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
    page.locator('#signup-tab').click()
    page.locator('#username').fill(name)
    page.locator('#password').fill('Password1')
    page.locator('#auth-submit').click()
    playwright.expect(page.locator('#auth-notice')).to_have_text('Account created. Log in with your new account.')
    playwright.expect(page.locator('#chat-view')).to_be_hidden()
    playwright.expect(page.locator('#password')).to_have_value('')
    login(page, name)


def send(page, text):
    page.locator('#message').fill(text)
    page.locator('#send').click()


def close_browser(browser):
    for context in browser.contexts:
        for page in context.pages:
            if not page.is_closed():
                page.evaluate("window.dispatchEvent(new Event('pagehide'))")
    browser.close()


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
            alice.add_init_script("window.__testSockets=[]; const Native=window.WebSocket; window.WebSocket=class extends Native { constructor(...args) { super(...args); window.__testSockets.push(this); } };")
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
            playwright.expect(alice.locator('.message-meta')).to_have_text('alice')
            alice.locator('.message').evaluate('(node) => { window.originalMessage = node; }')
            alice.locator('#history').click()
            playwright.expect(alice.locator('#send')).to_be_enabled()
            assert alice.locator('.message-body').count() == 1
            assert 'alice' in alice.locator('.message-meta').inner_text()
            assert ' · ' in alice.locator('.message-meta').inner_text()
            assert alice.locator('.message').evaluate('(node) => node === window.originalMessage')

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
            playwright.expect(alice.locator('#composer-notice')).to_have_text('This message was blocked by the security policy.')
            playwright.expect(alice.locator('#message')).to_have_value('my next draft')
            controls.slow = None
            send(alice, 'pineapple')
            playwright.expect(alice.locator('#composer-notice')).to_have_text('This name or message is not allowed.')
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
            playwright.expect(alice.locator('#room-notice')).to_have_text('You are not a member of this room. Join it first.')
            alice.get_by_role('button', name='Join General', exact=True).click()
            playwright.expect(alice.locator('.message-body')).to_have_count(3)
            alice.evaluate('window.__testSockets.at(-1).close()')
            playwright.expect(alice.locator('#connection-status')).to_have_text('Reconnecting…')
            playwright.expect(alice.locator('#connection-status')).to_have_text('Connected')
            playwright.expect(alice.locator('#auth-view')).to_be_visible()
            assert alice.locator('.message-body').count() == 0
            login(alice, 'alice')
            playwright.expect(alice.locator('#send')).to_be_disabled()
            alice.get_by_role('button', name='Select General', exact=True).click()
            playwright.expect(alice.locator('.message-body')).to_have_count(3)
            alice.locator('#logout').click()
            playwright.expect(alice.locator('#auth-view')).to_be_visible()
            playwright.expect(alice.locator('#logout')).to_be_hidden()
            assert not errors
        finally:
            controls.release.set()
            close_browser(browser)


def test_target_room_errors_filter_and_security_messages(secured_server, ui_address):
    controls = secured_server
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            alice, bob = browser.new_page(), browser.new_page(viewport={'width': 390, 'height': 844})
            register(alice, ui_address, controls.uri, 'alice')
            register(bob, ui_address, controls.uri, 'bobby')
            playwright.expect(alice.locator('#rooms-empty')).to_have_text('No rooms yet. Create the first one.')
            for page, room in [(alice, 'General'), (bob, 'Other')]:
                page.locator('#room-name').fill(room)
                page.get_by_role('button', name='Create', exact=True).click()
                playwright.expect(page.locator('#room-title')).to_have_text('# ' + room)
                playwright.expect(page.locator('#send')).to_be_enabled()
            alice.locator('#refresh-rooms').click()
            alice.get_by_role('button', name='Select Other', exact=True).click()
            playwright.expect(alice.locator('#room-notice')).to_have_text('You are not a member of this room. Join it first.')
            playwright.expect(alice.locator('#room-title')).to_have_text('# General')
            playwright.expect(alice.locator('.room.selected .room-meta')).to_have_text('Selected · live')
            playwright.expect(alice.locator('#send')).to_be_enabled()
            alice.locator('#room-filter').fill('gEnE')
            playwright.expect(alice.locator('#rooms .room')).to_have_count(1)
            playwright.expect(alice.locator('#rooms .room-name')).to_have_text('# General')
            alice.locator('#room-filter').fill('not found')
            playwright.expect(alice.locator('#rooms-empty')).to_have_text('No rooms match your filter.')
            playwright.expect(alice.locator('#room-title')).to_have_text('# General')
            alice.locator('#room-filter').fill('')
            playwright.expect(alice.locator('#rooms .room')).to_have_count(2)
            # Filtering never mutates membership: after a successful switch the old room remains active.
            alice.get_by_role('button', name='Join Other', exact=True).click()
            playwright.expect(alice.locator('#room-title')).to_have_text('# Other')
            playwright.expect(alice.locator('.room').filter(has_text='# General').locator('.room-meta')).to_have_text('Member · not selected')
            alice.get_by_role('button', name='Select General', exact=True).click()
            playwright.expect(alice.locator('#room-title')).to_have_text('# General')

            send(alice, 'I enjoy pizza')
            playwright.expect(alice.locator('.message-body')).to_have_count(1)
            # Controlled model allow verifies the UI flow, not actual model accuracy.
            controls.mode = 'allow'
            send(alice, 'Chocolate cake: mix 200 g flour with sugar and bake for 20 minutes')
            playwright.expect(alice.locator('.message-body')).to_have_count(2)
            assert controls.llm_calls
            for text, mode, message in [
                ('pizza 200 g flour', 'block', 'This message was blocked by the security policy.'),
                ('another recipe fragment', 'timeout', 'The security check is unavailable. Try again later.'),
                ('https://evil.example.com', 'allow', 'This message contains an unsafe link.'),
                ('https://timeout.example.com', 'allow', 'Link safety could not be checked. Try again later.'),
                ('https://review.example.com', 'allow', 'This link could not be confirmed safe. Remove it before sending.'),
                ('pineapple', 'allow', 'This name or message is not allowed.'),
            ]:
                controls.mode = mode
                send(alice, text)
                playwright.expect(alice.locator('#composer-notice')).to_have_text(message)
                playwright.expect(alice.locator('.message-body')).to_have_count(2)
            alice.locator('#history').click()
            playwright.expect(alice.locator('#send')).to_be_enabled()
            playwright.expect(alice.locator('.message-body')).to_have_count(2)
            assert alice.locator('#password').get_attribute('type') == 'password'
            assert alice.evaluate('localStorage.length + sessionStorage.length') == 0
        finally:
            close_browser(browser)


def test_http_health_is_independent_of_websocket(ui_address):
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.route('**/health', lambda route: route.fulfill(status=503, body='unavailable'))
            page.goto(ui_address)
            playwright.expect(page.locator('#health-status')).to_have_text('Server unavailable')
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            page.unroute('**/health')
            page.reload()
            playwright.expect(page.locator('#health-status')).to_have_text('Server online')
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
        finally:
            close_browser(browser)
