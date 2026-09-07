"""Real WebSocket integration with real adapters and offline model/provider fakes."""
import asyncio
import json
import logging
import socket
import threading
import time
import urllib.request
from types import SimpleNamespace

import httpx
import pytest
import uvicorn

import auth
import database as db
import local_llm
import server
import url_security
from client import ChatClient


@pytest.fixture
def secured_server(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DATABASE_PATH', tmp_path / 'security.db')
    monkeypatch.setenv('CHAT_LOG', str(tmp_path / 'security.log'))
    for name in ('LOCAL_LLM_MODEL', 'LOCAL_LLM_ENDPOINT', 'LOCAL_LLM_TIMEOUT_SECONDS'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(url_security, 'RATE_LIMIT_PER_MINUTE', 100)
    auth.sessions.clear()
    controls = SimpleNamespace(mode='allow', llm_calls=[], urls=[], dlp_inputs=[],
                               slow=None, entered=threading.Event(), release=threading.Event())

    def model(endpoint, payload, timeout):
        controls.llm_calls.append(json.loads(payload['prompt']))
        if controls.slow == 'llm':
            controls.entered.set()
            assert controls.release.wait(5), 'Test did not release model'
        if controls.mode == 'timeout':
            raise TimeoutError('SENSITIVE_INTERNAL_TEXT')
        if controls.mode == 'malformed':
            return b'invalid model output SENSITIVE_INTERNAL_TEXT'
        return json.dumps({'done': True, 'response': json.dumps({
            'action': controls.mode, 'risk_score': 80 if controls.mode == 'block' else 5,
        })}).encode()

    def provider(request):
        host = request.url.path.rsplit('/', 1)[-1]
        controls.urls.append(host)
        if controls.slow == 'url':
            controls.entered.set()
            assert controls.release.wait(5), 'Test did not release provider'
        if host == 'timeout.example.com':
            raise httpx.ReadTimeout('SENSITIVE_INTERNAL_TEXT', request=request)
        if host == 'unknown.example.com':
            return httpx.Response(404)
        malicious = 2 if host == 'evil.example.com' else 1 if host == 'review.example.com' else 0
        return httpx.Response(200, json={'data': {'attributes': {
            'last_analysis_stats': {'malicious': malicious, 'harmless': 10},
            'last_analysis_date': time.time(),
        }}})

    def forbidden_http(self, request):
        raise AssertionError('Automated tests cannot use the real provider')

    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', forbidden_http)
    monkeypatch.setattr(local_llm, '_call_model', model)
    real_check = server.RuleDLPChecker.check

    def observed_check(self, field, text, context=None):
        controls.dlp_inputs.append((field, text))
        return real_check(self, field, text, context)

    monkeypatch.setattr(server.RuleDLPChecker, 'check', observed_check)
    reputation = url_security.VirusTotalURLReputationChecker(
        api_key='TEST_ONLY_KEY', http_client=httpx.Client(transport=httpx.MockTransport(provider)))
    monkeypatch.setattr(server, 'VirusTotalURLReputationChecker', lambda: reputation)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    runner = uvicorn.Server(uvicorn.Config(server.app, log_config=None, access_log=False))
    thread = threading.Thread(target=runner.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if runner.started:
                break
            if not thread.is_alive(): pytest.fail('Test server failed at startup')
            time.sleep(.05)
        else: pytest.fail('Test server startup timeout')
        controls.uri = f'ws://127.0.0.1:{port}/ws'
        controls.health = f'http://127.0.0.1:{port}/health'
        assert isinstance(server.app.state.policy.classifier, local_llm.OllamaRecipeClassifier)
        assert isinstance(server.app.state.policy.reputation, url_security.VirusTotalURLReputationChecker)
        yield controls
    finally:
        controls.release.set()
        runner.should_exit = True
        thread.join(10)
        listener.close()
        assert not thread.is_alive(), 'Server did not stop'
        auth.sessions.clear()


async def account(uri, username):
    client = ChatClient(uri)
    await client.connect()
    assert (await client.request('signup', username=username, password='Pineapple1'))['ok']
    assert (await client.request('login', username=username, password='Pineapple1'))['ok']
    return client


async def quiet(client):
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(client.events.get(), .15)


async def event(client, content, username):
    received = await asyncio.wait_for(client.events.get(), 2)
    assert received['content'] == content and received['username'] == username
    assert 'token' not in received and 'password_hash' not in received


async def history(client, room='General'):
    response = await client.request('history', room_name=room)
    assert response['ok']
    return response['messages']


def test_security_chat_and_names(secured_server, caplog):
    controls = secured_server
    caplog.set_level(logging.INFO, logger='chat')

    async def run():
        a, b, c = [await account(controls.uri, name) for name in (' Alice ', 'bobby', 'outside')]
        try:
            assert (await a.request('signup', username=' PINEAPPLE ', password='Password1'))['error'] == 'forbidden_term'
            assert db.get_user_by_username('pineapple') is None
            assert (await a.request('create_group', room_name='P!NE@PPLE'))['error'] == 'forbidden_term'
            assert db.get_group_by_name('P!NE@PPLE') is None
            assert (await a.request('create_group', room_name='General'))['ok']
            assert (await b.request('join_group', room_name='General'))['ok']
            assert (await c.request('join_group', room_name='General'))['ok']
            assert (await c.request('create_group', room_name='Other'))['ok']
            assert (await c.request('send_message', room_name='General', content='not selected'))['error'] == 'room_not_selected'
            assert (await a.request('send_message', room_name='General', content='I love pizza', username='bobby', user_id=2))['ok']
            await event(a, 'I love pizza', 'alice')
            await event(b, 'I love pizza', 'alice')
            await quiet(c)
            for text in ('pineapple', 'p!ne@pple', 'ananas', 'pine\u200bapple'):
                result = await a.request('send_message', room_name='General', content=text)
                assert result['error'] == 'forbidden_term' and result['security']['risk_score'] == 100
                assert text not in json.dumps(result)
            assert controls.llm_calls == [] and controls.urls == []
            await quiet(a)
            await quiet(b)
            assert [m['content'] for m in await history(b)] == ['I love pizza']
            key = (db.get_user_by_username('alice')['user_id'], db.get_group_by_name('General')['room_id'])
            assert list(server.app.state.policy._attempts[key])[-1] == 'pine\u200bapple'
            assert not any(text == 'Pineapple1' for _, text in controls.dlp_inputs)
            assert (await c.request('select_room', room_name='General'))['ok']
            assert (await b.request('leave_group', room_name='General'))['ok']
            assert (await a.request('send_message', room_name='General', content='hello again'))['ok']
            await event(a, 'hello again', 'alice')
            await event(c, 'hello again', 'alice')
            await quiet(b)
            await b.close()
            await b.connect()
            assert (await b.request('join_group', room_name='General'))['ok']
            assert len(await history(b)) == 2
        finally:
            await asyncio.gather(*(client.close() for client in (a,b,c)))

    asyncio.run(run())
    assert 'security operation=send_message' in caplog.text
    for secret in ('Pineapple1', 'p!ne@pple', 'TEST_ONLY_KEY', 'SENSITIVE_INTERNAL_TEXT'):
        assert secret not in caplog.text


@pytest.mark.parametrize('mode,reason', [('allow', None), ('block', 'recipe_blocked'),
    ('timeout', 'security_check_unavailable'), ('malformed', 'security_check_unavailable'),
    ('review', 'security_check_unavailable')])
def test_real_classifier_adapter_in_flow(secured_server, mode, reason):
    controls = secured_server
    controls.mode = mode

    async def run():
        a, b = await account(controls.uri, 'alice'), await account(controls.uri, 'bobby')
        try:
            assert (await a.request('create_group', room_name='General'))['ok']
            assert (await b.request('join_group', room_name='General'))['ok']
            text = 'pizza 200 g https://safe.example.com/Path'
            result = await a.request('send_message', room_name='General', content=text)
            assert len(controls.llm_calls) == 1 and controls.llm_calls[0]['text'] == text
            if reason:
                assert result['error'] == reason and controls.urls == []
                await quiet(a)
                await quiet(b)
                assert await history(b) == []
            else:
                assert result['ok'] and controls.urls == ['safe.example.com']
                await event(a, text, 'alice')
                await event(b, text, 'alice')
                assert (await history(b))[0]['content'] == text
        finally:
            await asyncio.gather(a.close(), b.close())
    asyncio.run(run())


def test_url_cache_and_all_urls_before_persistence(secured_server):
    controls = secured_server

    async def run():
        a = await account(controls.uri, 'alice')
        try:
            await a.request('create_group', room_name='General')
            for path in ('first', 'second'):
                text = f'https://safe.example.com/{path}'
                assert (await a.request('send_message', room_name='General', content=text))['ok']
                await event(a, text, 'alice')
            assert controls.urls == ['safe.example.com']
            text = 'https://evil.example.com https://second.example.com https://third.example.com'
            assert (await a.request('send_message', room_name='General', content=text))['error'] == 'malicious_url'
            assert controls.urls[-3:] == ['evil.example.com', 'second.example.com', 'third.example.com']
            for host, reason in [('evil', 'malicious_url'), ('timeout', 'reputation_unavailable'),
                                 ('review', 'reputation_review_required'), ('unknown', 'reputation_review_required')]:
                result = await a.request('send_message', room_name='General', content=f'https://{host}.example.com')
                assert result['error'] == reason
            assert controls.urls.count('evil.example.com') == 1
            assert len(await history(a)) == 2
            await quiet(a)
        finally:
            await a.close()
    asyncio.run(run())


def test_split_recipe_windows_isolated(secured_server):
    controls = secured_server

    async def run():
        a, b = await account(controls.uri, 'alice'), await account(controls.uri, 'bobby')
        try:
            await a.request('create_group', room_name='General')
            await b.request('join_group', room_name='General')
            assert (await a.request('send_message', room_name='General', content='pizza'))['ok']
            assert (await b.request('send_message', room_name='General', content='200 g'))['ok']
            await a.request('create_group', room_name='Other')
            assert (await a.request('send_message', room_name='Other', content='200 g'))['ok']
            assert controls.llm_calls == []
            await a.request('select_room', room_name='General')
            controls.mode = 'block'
            assert (await a.request('send_message', room_name='General', content='200 g'))['error'] == 'recipe_blocked'
            assert controls.llm_calls == [{'text': '200 g', 'recent_attempts': ['pizza']}]
            assert [m['content'] for m in await history(a)] == ['pizza', '200 g']
        finally:
            await asyncio.gather(a.close(), b.close())
    asyncio.run(run())


@pytest.mark.parametrize('slow', ['llm', 'url'])
def test_slow_security_health_other_clients_and_revalidation(secured_server, slow):
    controls = secured_server
    controls.slow = slow

    async def run():
        a, b = await account(controls.uri, 'alice'), await account(controls.uri, 'bobby')
        other_a = ChatClient(controls.uri)
        await other_a.connect()
        pending = None
        try:
            await a.request('create_group', room_name='General')
            await b.request('join_group', room_name='General')
            await other_a.request('login', username='alice', password='Pineapple1')
            text = 'pizza 200 g' if slow == 'llm' else 'https://slow.example.com'
            pending = asyncio.create_task(a.request('send_message', room_name='General', content=text))
            assert await asyncio.to_thread(controls.entered.wait, 3)
            assert not server.app.state.operations.locked()
            started = time.monotonic()
            response = await asyncio.wait_for(b.request('send_message', room_name='General', content='hello'), 2)
            assert response['ok']
            health_response = await asyncio.to_thread(urllib.request.urlopen, controls.health, timeout=1)
            with health_response:
                assert json.load(health_response)['ok']
            assert time.monotonic() - started < 2
            assert not pending.done()
            # Membership can change via another connection during a pending check.
            assert (await other_a.request('leave_group', room_name='General'))['ok']
            assert (await other_a.request('join_group', room_name='General'))['ok']
            controls.release.set()
            assert (await pending)['error'] == 'room_not_selected'
            assert [m['content'] for m in await history(b)] == ['hello']
        finally:
            controls.release.set()
            if pending: await pending
            await asyncio.gather(a.close(), b.close(), other_a.close())
    asyncio.run(run())
