"""Product-facing auth/composer feedback and automatic connections; offline only."""
import pytest
from test_ui_browser import playwright, ui_address, secured_server, login, send, close_browser


def fill_auth(page, name, password):
    page.locator('#username').fill(name)
    page.locator('#password').fill(password)
    page.locator('#auth-submit').click()


@pytest.mark.parametrize('host', ['localhost', 'chat.lan.test'])
def test_signup_errors_composer_and_logout(ui_address, host):
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch(args=['--host-resolver-rules=MAP chat.lan.test 127.0.0.1', '--no-proxy-server'])
        try:
            page = browser.new_page(viewport={'width': 390, 'height': 844})
            page.goto(ui_address.replace('127.0.0.1', host))
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            playwright.expect(page.locator('#health-status')).to_have_text('Server online')
            assert page.locator('#address, #connect, #disconnect').count() == 0
            assert 'ws://' not in page.locator('body').inner_text()
            playwright.expect(page.locator('#username-help')).to_have_text('3–20 English letters, numbers, or underscores. Usernames are not case-sensitive.')
            assert 'Spaces are not allowed.' in page.locator('#password-help').inner_text()
            assert 'Passwords are not trimmed' not in page.locator('body').inner_text()
            page.locator('#signup-tab').click()
            for name, password, message in [
                ('x', 'Password1', 'Username is invalid. Use 3–20 English letters, numbers, or underscores.'),
                ('alice', 'short1', 'Password is invalid.'),
                ('alice', 'Pass 123@', 'Spaces are not allowed in passwords.'),
                ('alice', 'Pass\t123@', 'Spaces are not allowed in passwords.'),
                ('pineapple', 'Password1', 'This name or message is not allowed.'),
            ]:
                # Use DOM assignment for tabs: HTML single-line inputs sanitize some whitespace.
                page.locator('#username').fill(name)
                page.locator('#password').evaluate('(node, value) => { node.value = value; }', password)
                page.locator('#auth-submit').click()
                playwright.expect(page.locator('#auth-form #auth-notice')).to_contain_text(message)
                playwright.expect(page.locator('#auth-notice')).to_be_visible()
                playwright.expect(page.locator('#notice')).to_be_hidden()
                assert page.locator('#auth-notice').bounding_box()['y'] < page.locator('#username').bounding_box()['y']
                playwright.expect(page.locator('#password')).to_have_value('')
                playwright.expect(page.locator('#chat-view')).to_be_hidden()
            fill_auth(page, '  ALICE ', '  Pass123@  ')
            playwright.expect(page.locator('#auth-notice')).to_have_text('Account created. Log in with your new account.')
            page.locator('#signup-tab').click()
            fill_auth(page, 'Alice', 'Pass123@')
            playwright.expect(page.locator('#auth-notice')).to_have_text('Username is already taken.')
            page.locator('#login-tab').click()
            fill_auth(page, 'alice', 'pass123@')
            playwright.expect(page.locator('#auth-notice')).to_have_text('Incorrect username or password.')
            fill_auth(page, 'alice', ' Pass123@ ')
            playwright.expect(page.locator('#chat-view')).to_be_visible()
            playwright.expect(page.get_by_role('button', name='Log out', exact=True)).to_be_visible()
            page.locator('#room-name').fill('General')
            page.get_by_role('button', name='Create', exact=True).click()
            playwright.expect(page.locator('#room-title')).to_have_text('# General')
            playwright.expect(page.locator('#send')).to_be_enabled()
            playwright.expect(page.locator('#logout')).to_be_visible()
            send(page, 'pineapple')
            playwright.expect(page.locator('#message-form #composer-notice')).to_have_text('This name or message is not allowed.')
            playwright.expect(page.locator('#composer-notice')).to_be_visible()
            playwright.expect(page.locator('#notice')).to_be_hidden()
            playwright.expect(page.locator('#message')).to_have_value('pineapple')
            playwright.expect(page.locator('.message')).to_have_count(0)
            assert page.locator('#composer-notice').bounding_box()['y'] < page.locator('#message').bounding_box()['y']
            page.locator('#message').fill('hello')
            playwright.expect(page.locator('#composer-notice')).to_be_hidden()
            page.locator('#send').click()
            playwright.expect(page.locator('.message-body')).to_have_text('hello')
            send(page, 'pineapple')
            playwright.expect(page.locator('#composer-notice')).to_be_visible()
            page.locator('#room-name').fill('Other')
            page.get_by_role('button', name='Create', exact=True).click()
            playwright.expect(page.locator('#room-title')).to_have_text('# Other')
            playwright.expect(page.locator('#composer-notice')).to_be_hidden()
            page.locator('#leave').click()
            playwright.expect(page.locator('#room-title')).to_have_text('Select a room')
            playwright.expect(page.locator('#logout')).to_be_visible()
            page.locator('#logout').click()
            playwright.expect(page.locator('#auth-notice')).to_have_text('You have logged out.')
            playwright.expect(page.locator('#chat-view')).to_be_hidden()
            playwright.expect(page.locator('#logout')).to_be_hidden()
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            playwright.expect(page.locator('#password')).to_have_value('')
            assert page.evaluate('localStorage.length + sessionStorage.length') == 0
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            fill_auth(page, 'alice', 'Pass123@')
            playwright.expect(page.locator('#chat-view')).to_be_visible()
            playwright.expect(page.locator('#send')).to_be_disabled()
        finally:
            close_browser(browser)


def test_reconnect_preserves_auth_fields_and_never_duplicates_sockets(ui_address):
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.add_init_script("""
                window.__sockets=[]; window.__reject=false;
                const Native=window.WebSocket;
                window.WebSocket=class extends Native {
                    constructor(url) {
                        super(window.__reject ? url + '/unavailable' : url); window.__sockets.push(this);
                        document.documentElement.dataset.testSockets = String(window.__sockets.length);
                    }
                };
            """)
            page.goto(ui_address)
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            page.locator('#username').fill('draft_user')
            page.locator('#password').fill('Draft123@')
            page.evaluate('window.__reject=true; window.__sockets.at(-1).close()')
            playwright.expect(page.locator('#connection-status')).to_have_text('Reconnecting…')
            playwright.expect(page.locator('#auth-submit')).to_be_disabled()
            playwright.expect(page.locator('html')).to_have_attribute('data-test-sockets', '2')
            playwright.expect(page.locator('#username')).to_have_value('draft_user')
            playwright.expect(page.locator('#password')).to_have_value('Draft123@')
            assert page.evaluate('window.__sockets.filter(s => s.readyState < 2).length') <= 1
            page.evaluate('window.__reject=false')
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected', timeout=10000)
            playwright.expect(page.locator('#auth-submit')).to_be_enabled()
            playwright.expect(page.locator('#password')).to_have_value('Draft123@')
            playwright.expect(page.locator('#health-status')).to_have_text('Server online')
            assert page.evaluate('window.__sockets.filter(s => s.readyState < 2).length') == 1
        finally:
            close_browser(browser)


@pytest.mark.parametrize('failure', ['response', 'offline'])
def test_logout_failure_still_leaves_account_safely(ui_address, failure):
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.add_init_script("""
                const Native=window.WebSocket;
                window.WebSocket=class extends Native {
                    send(raw) {
                        const request=JSON.parse(raw);
                        if (request.action === 'logout') {
                            if (window.__logoutFailure === 'offline') { this.close(); return; }
                            queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', {data:JSON.stringify({
                                type:'response', id:request.id, ok:false, error:'internal_error'
                            })}))); return;
                        }
                        super.send(raw);
                    }
                };
            """)
            page.goto(ui_address)
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            page.locator('#signup-tab').click()
            fill_auth(page, 'alice', 'Password1')
            playwright.expect(page.locator('#auth-notice')).to_contain_text('Account created.')
            login(page, 'alice')
            page.evaluate('(value) => { window.__logoutFailure=value; }', failure)
            page.locator('#logout').click()
            playwright.expect(page.locator('#auth-notice')).to_have_text('Logged out on this device. Server logout could not be confirmed.')
            playwright.expect(page.locator('#chat-view')).to_be_hidden()
            playwright.expect(page.locator('#logout')).to_be_hidden()
            playwright.expect(page.locator('#notice')).to_be_hidden()
            assert 'internal_error' not in page.locator('body').inner_text()
        finally:
            close_browser(browser)


@pytest.mark.parametrize('failure', ['response', 'offline'])
def test_signup_server_failure_is_visible_in_auth_form(ui_address, failure):
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            page.add_init_script("""
                const Native=window.WebSocket;
                window.WebSocket=class extends Native {
                    send(raw) {
                        const request=JSON.parse(raw);
                        if (request.action !== 'signup') { super.send(raw); return; }
                        if (window.__failure === 'offline') { this.close(); return; }
                        queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', {data:JSON.stringify({
                            type:'response', id:request.id, ok:false, error:'internal_error'
                        })})));
                    }
                };
            """)
            page.goto(ui_address)
            playwright.expect(page.locator('#connection-status')).to_have_text('Connected')
            page.evaluate('(value) => { window.__failure=value; }', failure)
            page.locator('#signup-tab').click()
            fill_auth(page, 'alice', 'Password1')
            message = ('Connection lost. Please wait while we reconnect.' if failure == 'offline'
                       else 'The server could not complete the request. Try again later.')
            playwright.expect(page.locator('#auth-form #auth-notice')).to_have_text(message)
            playwright.expect(page.locator('#auth-notice')).to_be_visible()
            playwright.expect(page.locator('#notice')).to_be_hidden()
            playwright.expect(page.locator('#password')).to_have_value('')
            playwright.expect(page.locator('#chat-view')).to_be_hidden()
            assert 'internal_error' not in page.locator('body').inner_text()
            assert 'Account created' not in page.locator('body').inner_text()
        finally:
            close_browser(browser)
