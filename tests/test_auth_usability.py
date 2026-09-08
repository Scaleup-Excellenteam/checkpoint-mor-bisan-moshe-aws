"""Password and logout contracts through auth, real WebSockets and the CLI client."""
import asyncio

import pytest
from chat_system import auth, database as db
from client import ChatClient
from test_day1 import database
from test_security_integration import secured_server, account, quiet


@pytest.mark.parametrize('edge', [' ', '\t', '\r\n', '\u0085', '\u001c', '\u3000'])
def test_password_edges_normalize_consistently(database, edge):
    value = edge + 'Pass123@' + edge
    assert auth.normalize_password(value) == 'Pass123@'
    assert auth.signup(' Alice ', value)['ok']
    hashed = db.get_user_by_username('alice')['password_hash']
    assert hashed != 'Pass123@' and auth.verify_password(value, hashed)
    assert auth.login('ALICE', 'Pass123@')['ok']
    assert auth.login('alice', value)['ok']
    assert auth.login('alice', 'pass123@')['error'] == 'invalid_credentials'
    assert auth.signup('ALICE', value)['error'] == 'username_taken'


@pytest.mark.parametrize('value', ['Pass 123@', 'Pass\t123@', 'Pass\n123@', 'Pass\u0085123@',
                                  '  short1  ', 'a1' * 17, 'abcdefgh', 'abc123!!'])
def test_invalid_passwords_remain_invalid(database, value):
    assert not auth.validate_password(value)
    assert auth.signup('alice', value)['error'] == 'invalid_password'
    assert auth.login('alice', value)['error'] == 'invalid_credentials'
    assert db.get_user_by_username('alice') is None


def test_logout_revokes_only_supplied_token_without_changing_account(database):
    auth.signup('alice', 'Password1')
    before = db.get_user_by_username('alice')
    one = auth.login('alice', 'Password1')['token']
    two = auth.login('alice', 'Password1')['token']
    assert auth.logout(one) == {'ok': True}
    assert auth.validate_session(one) is None
    assert auth.validate_session(two) == before['user_id']
    for token in (one, 'already-invalid', None):
        assert auth.logout(token) == {'ok': True}
    assert db.get_user_by_username('alice') == before
    assert auth.login('alice', 'Password1')['ok']


def test_websocket_normalized_password_logout_and_revoked_presence(secured_server):
    async def run():
        a, shared = ChatClient(secured_server.uri), ChatClient(secured_server.uri)
        await a.connect(); await shared.connect()
        b = await account(secured_server.uri, 'bobby')
        try:
            assert (await a.request('signup', username=' ALICE ', password='  Pass123@  '))['ok']
            assert (await a.request('login', username='alice', password='\tPass123@\n'))['ok']
            saved = db.get_user_by_username('alice')
            token = a.token
            shared.token = token
            assert (await a.request('create_group', room_name='General'))['ok']
            assert (await shared.request('select_room', room_name='General'))['ok']
            assert (await b.request('join_group', room_name='General'))['ok']
            assert (await a.request('logout'))['ok']
            assert a.token is None
            assert auth.validate_session(token) is None
            for action in ('list_groups', 'history', 'select_room', 'send_message'):
                result = await shared.request(action, room_name='General', content='hello')
                assert result['error'] == 'unauthenticated'
            assert (await b.request('send_message', room_name='General', content='hello'))['ok']
            await b.events.get()
            await quiet(a); await quiet(shared)
            assert (await a.request('logout'))['ok']
            assert (await shared.request('logout'))['ok']
            assert db.get_user_by_username('alice') == saved
            assert (await a.request('login', username='ALICE', password='Pass123@'))['ok']
            assert (await a.request('select_room', room_name='General'))['ok']
            assert (await a.request('history', room_name='General'))['messages'][0]['content'] == 'hello'
            assert (await a.request('signup', username='badpassword', password='Pass 123@'))['error'] == 'invalid_password'
        finally:
            await asyncio.gather(a.close(), b.close(), shared.close())
    asyncio.run(run())


def test_cli_uses_server_password_normalization_and_logout(secured_server, monkeypatch, capsys):
    import cli
    entries = iter(['1', 'cli_user', '  Pass123@  ', '2', 'CLI_USER', 'Pass123@', '/logout', '3'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(entries))
    monkeypatch.setattr(cli.sys.stdin, 'isatty', lambda: False)
    asyncio.run(cli.chat_client(secured_server.uri))
    output = capsys.readouterr().out
    assert 'signup: success' in output and 'login: success' in output and 'Logged out.' in output
    assert 'Pass123@' not in output
    assert not auth.sessions
    assert auth.verify_password('Pass123@', db.get_user_by_username('cli_user')['password_hash'])
