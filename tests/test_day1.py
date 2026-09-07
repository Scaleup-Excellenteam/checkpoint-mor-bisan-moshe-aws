import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
import websockets
import auth
import database as db
from client import ChatClient

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "test.db")
    db.initialize_database()
    auth.sessions.clear()
    yield
    auth.sessions.clear()


@pytest.mark.parametrize('name,valid', [('abc', True), ('a_1', True), ('a'*20, True), ('ab', False), ('a'*21, False), ('ABC', False), ('a-b', False), ('éabc', False)])
def test_username(name, valid):
    assert auth.validate_username(name) is valid
    assert auth.normalize_username('  MoR_1 ') == 'mor_1'


@pytest.mark.parametrize('password,valid', [('abcd1234', True), ('abcd@#$%', True), ('1234@#$%', True), ('abcdefgh', False), ('12345678', False), ('abc123!', False), ('abc123', False), ('a1'*17, False)])
def test_password(password, valid):
    assert auth.validate_password(password) is valid


def test_auth(database):
    result = auth.signup('  Alice ', 'Password1')
    assert result['ok'] and result['username'] == 'alice'
    stored = db.get_user_by_username('alice')['password_hash']
    assert stored != 'Password1' and auth.verify_password('Password1', stored)
    assert not auth.verify_password('Wrong123', stored)
    assert auth.signup('ALICE', 'Password1')['error'] == 'username_taken'
    assert auth.signup('x', 'Password1')['error'] == 'invalid_username'
    assert auth.signup('valid', 'bad')['error'] == 'invalid_password'
    for name, password in [('alice', 'Wrong123'), ('nobody', 'Password1'), ('alice', 'x'*100)]:
        assert auth.login(name, password)['error'] == 'invalid_credentials'
    login = auth.login(' ALICE ', 'Password1')
    assert auth.validate_session(login['token']) == result['user_id']
    assert auth.validate_session('invalid') is None


def test_database(database):
    a = db.create_user('alice', 'already_hashed')
    b = db.create_user('bobby', 'already_hashed')
    group = db.create_group('General', a)
    room = group['room_id']
    assert db.is_active_member(a, room)
    assert db.list_groups()[0]['room_name'] == 'General'
    assert db.save_message(room, b, 'forbidden')['error'] == 'not_active_member'
    with pytest.raises(PermissionError): db.get_room_history(b, room)
    assert db.join_group(b, 'general')['ok']
    assert db.join_group(b, 'General')['error'] == 'already_member'
    assert db.leave_group(b, 'General')['ok']
    assert db.leave_group(b, 'General')['error'] == 'not_active_member'
    assert db.join_group(b, 'General')['ok']
    message = db.save_message(room, a, 'persistent')
    assert db.get_room_history(b, room)[0]['message_id'] == message['message_id']
    conn = db.get_connection()
    try:
        conn.execute('UPDATE messages SET deleted_at=CURRENT_TIMESTAMP')
        conn.commit()
        assert conn.execute('SELECT COUNT(*) FROM room_members WHERE user_id=?', (b,)).fetchone()[0] == 1
    finally: conn.close()
    assert db.get_room_history(a, room) == []


@pytest.fixture
def running_server(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = {**os.environ, 'CHAT_DATABASE': str(tmp_path / 'server.db'), 'CHAT_LOG': str(tmp_path / 'server.log')}
    output = (tmp_path / 'process.log').open('w')
    proc = subprocess.Popen([sys.executable, 'server.py', '--host', '127.0.0.1', '--port', str(port)], cwd=ROOT, env=env, stdout=output, stderr=output)
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=.2) as response:
                    assert json.load(response) == {'ok': True, 'status': 'healthy'}
                break
            except OSError:
                if proc.poll() is not None: pytest.fail('Server exited during startup')
                time.sleep(.1)
        else: pytest.fail('Server startup timeout')
        yield f'ws://127.0.0.1:{port}/ws'
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        output.close()


async def scenario(uri):
    clients = [ChatClient(uri) for _ in range(3)]
    a, b, outsider = clients
    try:
        await asyncio.gather(*(c.connect() for c in clients))
        assert (await a.request('list_groups'))['error'] == 'unauthenticated'
        for c, name in zip(clients, ('  ALIce ', 'bobby', 'outside')):
            assert (await c.request('signup', username=name, password='Password1'))['ok']
            assert (await c.request('login', username=name, password='Password1'))['ok']
        assert (await a.request('create_group', room_name='General'))['ok']
        assert (await b.request('create_group', room_name='general'))['error'] == 'group_already_exists'
        assert (await b.request('list_groups'))['groups'][0]['room_name'] == 'General'
        assert (await b.request('join_group', room_name='General'))['ok']
        assert (await b.request('join_group', room_name='General'))['error'] == 'already_member'
        assert (await b.request('select_room', room_name='General'))['ok']
        assert (await outsider.request('create_group', room_name='Other'))['ok']
        assert (await outsider.request('send_message', room_name='General', content='bad', user_id=1))['error'] == 'not_active_member'
        assert (await outsider.request('history', room_name='General'))['error'] == 'not_active_member'
        sent = await a.request('send_message', room_name='General', content='hello', username='bobby')
        assert sent['ok'] and sent['username'] == 'alice'
        for c in (a,b):
            event = await asyncio.wait_for(c.events.get(), 2)
            assert event['content'] == 'hello' and event['username'] == 'alice'
            assert not {'password_hash', 'token'} & event.keys()
        history = (await b.request('history', room_name='General'))['messages']
        assert history[0]['username'] == 'alice' and history[0]['content'] == 'hello'
        with pytest.raises(asyncio.TimeoutError): await asyncio.wait_for(outsider.events.get(), .2)
        assert (await b.request('send_message', room_name='General', content='reply'))['ok']
        for c in (a,b): assert (await asyncio.wait_for(c.events.get(), 2))['content'] == 'reply'
        assert (await b.request('leave_group', room_name='General'))['ok']
        assert (await b.request('history', room_name='General'))['error'] == 'not_active_member'
        await a.request('send_message', room_name='General', content='after leave')
        await a.events.get()
        with pytest.raises(asyncio.TimeoutError): await asyncio.wait_for(b.events.get(), .2)
        await b.close()
        await b.connect()
        assert (await b.request('join_group', room_name='General'))['ok']
        assert len((await b.request('history', room_name='General'))['messages']) == 3
        await a.request('send_message', room_name='General', content='reconnected')
        assert (await asyncio.wait_for(b.events.get(), 2))['content'] == 'reconnected'
        async with websockets.connect(uri) as raw:
            for payload, code in [('broken', 'invalid_json'), ('[]', 'invalid_request'), ('{"id":"1","action":"unknown"}', 'unsupported_operation')]:
                await raw.send(payload)
                assert json.loads(await raw.recv())['error'] == code
            await raw.send(json.dumps({'id':'2','action':'history','room_name':'General','token':a.token}))
            assert json.loads(await raw.recv())['ok']
    finally:
        await asyncio.gather(*(c.close() for c in clients))


def test_real_websocket_flow(running_server):
    asyncio.run(scenario(running_server))


def test_real_cli(running_server):
    script = '1\ncliuser\nPassword1\n2\ncliuser\nPassword1\n/create CLI Room\n/list\n/history\nhello from CLI\n/history\n/leave CLI Room\n/join CLI Room\n/select CLI Room\n/reconnect\n2\ncliuser\nPassword1\n/select CLI Room\n/history\n/quit\n'
    result = subprocess.run([sys.executable, 'client.py', '--uri', running_server], input=script, text=True, capture_output=True, timeout=30, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    for expected in ('signup: success', 'login: success', 'create_group: success', 'hello from CLI', 'leave_group: success', 'join_group: success', 'select_room: success', 'Reconnected.'):
        assert expected in result.stdout, result.stdout
    assert '[CLI Room] cliuser: hello from CLI' in result.stdout
    assert any('cliuser: hello from CLI' in line and '[CLI Room]' not in line
               for line in result.stdout.splitlines())


def test_selected_room_routing(running_server):
    async def check():
        mor, bisan, other_mor = [ChatClient(running_server) for _ in range(3)]
        clients = (mor, bisan, other_mor)

        async def receive(client, content):
            event = await asyncio.wait_for(client.events.get(), 2)
            assert event['content'] == content and event['username'] == 'bisan'

        async def silent(client):
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client.events.get(), .2)

        async def send(content):
            result = await bisan.request('send_message', room_name='room_b', content=content, username='mor')
            assert result['ok'] and result['username'] == 'bisan'
            await receive(bisan, content)

        try:
            await asyncio.gather(*(c.connect() for c in clients))
            for client, name in ((mor, ' Mor '), (bisan, 'BISAN')):
                assert (await client.request('signup', username=name, password='Password1'))['ok']
                assert (await client.request('login', username=name, password='Password1'))['ok']
            assert (await mor.request('create_group', room_name='room_a'))['ok']
            assert (await bisan.request('create_group', room_name='room_b'))['ok']
            assert (await mor.request('join_group', room_name='room_b'))['ok']
            await send('both selected')
            await receive(mor, 'both selected')
            await silent(other_mor)  # Unauthenticated connections receive nothing.

            assert (await mor.request('select_room', room_name='room_a'))['ok']
            assert (await other_mor.request('login', username='mor', password='Password1'))['ok']
            assert (await other_mor.request('select_room', room_name='room_b'))['ok']
            await send('missed while away')
            await receive(other_mor, 'missed while away')
            await silent(mor)  # Selection is per connection, not per user.
            history = (await mor.request('history', room_name='room_b'))['messages']
            assert history[-1]['content'] == 'missed while away'
            assert history[-1]['username'] == 'bisan'
            await send('history does not select')
            await receive(other_mor, 'history does not select')
            await silent(mor)

            assert (await mor.request('select_room', room_name='room_b'))['ok']
            await send('selected again')
            await receive(mor, 'selected again')
            await receive(other_mor, 'selected again')
            assert (await mor.request('leave_group', room_name='room_b'))['ok']
            assert (await mor.request('select_room', room_name='room_b'))['error'] == 'not_active_member'
            await send('after leave')
            await silent(mor)
            await silent(other_mor)
            # Rejoining elsewhere must not revive a cleared connection selection.
            assert (await other_mor.request('join_group', room_name='room_b'))['ok']
            await send('rejoined elsewhere')
            await receive(other_mor, 'rejoined elsewhere')
            await silent(mor)
            assert (await mor.request('select_room', room_name='room_a'))['ok']
            assert (await mor.request('select_room', room_name='room_b'))['ok']
            # Leaving a different room preserves the selected room.
            assert (await mor.request('leave_group', room_name='room_a'))['ok']
            await send('other room left')
            await receive(mor, 'other room left')
            await receive(other_mor, 'other room left')

            await mor.close()
            await mor.connect()
            assert (await mor.request('login', username='mor', password='Password1'))['ok']
            await send('before reselect')
            await receive(other_mor, 'before reselect')
            await silent(mor)
            assert (await mor.request('select_room', room_name='room_b'))['ok']
            await send('after reconnect')
            await receive(mor, 'after reconnect')
            await receive(other_mor, 'after reconnect')
        finally:
            await asyncio.gather(*(c.close() for c in clients))

    asyncio.run(check())
