"""Offline smoke: real server/clients/adapters, controlled loopback HTTP services.

This verifies transport and integration, not real-model accuracy or VirusTotal.
"""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from client import ChatClient
from scripts.load_test import ServerProcess


class Service(BaseHTTPRequestHandler):
    mode = 'allow'
    llm_calls = 0
    domains = []

    def log_message(self, *args):
        pass

    def reply(self, result):
        payload = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        assert self.path == '/api/generate'
        payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert 'recent_attempts' in json.loads(payload['prompt'])
        Service.llm_calls += 1
        self.reply({'done': True, 'response': json.dumps({'action': Service.mode, 'risk_score': 60 if Service.mode == 'block' else 5})})

    def do_GET(self):
        assert self.path.startswith('/domains/')
        domain = self.path.rsplit('/', 1)[-1]
        Service.domains.append(domain)
        self.reply({'data': {'attributes': {'last_analysis_date': time.time(),
                    'last_analysis_stats': {'malicious': 2 if domain == 'evil.example.com' else 0,
                                            'harmless': 10}}}})


async def verify(uri):
    clients = [ChatClient(uri) for _ in range(3)]
    a, b, outside = clients
    allowed = []
    try:
        for client, name in zip(clients, ('mor', 'bisan', 'moshe')):
            await client.connect()
            assert (await client.request('signup', username=name, password='Pineapple1'))['ok']
            assert (await client.request('login', username=name, password='Pineapple1'))['ok']
        assert (await a.request('signup', username='pineapple', password='Password1'))['error'] == 'forbidden_term'
        assert (await a.request('create_group', room_name='P!NE@PPLE'))['error'] == 'forbidden_term'
        await a.request('create_group', room_name='General')
        await b.request('join_group', room_name='General')
        await outside.request('join_group', room_name='General')
        await outside.request('create_group', room_name='Other')

        async def send(text, reason=None):
            result = await a.request('send_message', room_name='General', content=text)
            if reason:
                assert result['error'] == reason, result
                for client in (a, b):
                    try:
                        await asyncio.wait_for(client.events.get(), .15)
                    except asyncio.TimeoutError:
                        pass
                    else:
                        raise AssertionError('Blocked content was delivered')
            else:
                assert result['ok'], result
                allowed.append(text)
                for client in (a,b):
                    event = await asyncio.wait_for(client.events.get(), 2)
                    assert event['content'] == text and event['username'] == 'mor'
            try:
                await asyncio.wait_for(outside.events.get(), .15)
            except asyncio.TimeoutError:
                pass
            else:
                raise AssertionError('Other selected room received a message')

        await send('I love pizza')
        await send('p!ne@pple', 'forbidden_term')
        assert Service.llm_calls == 0
        Service.mode = 'block'
        await send('then add 200 g flour', 'recipe_blocked')
        assert Service.llm_calls == 1
        Service.mode = 'allow'
        await send('hello after review')
        await send('https://safe.example.com/one')
        await send('https://safe.example.com/two')
        assert Service.domains.count('safe.example.com') == 1
        await send('https://evil.example.com https://other.example.com', 'malicious_url')
        assert Service.domains[-2:] == ['evil.example.com', 'other.example.com']
        await b.request('leave_group', room_name='General')
        await b.close()
        await b.connect()
        await b.request('login', username='bisan', password='Pineapple1')
        await b.request('join_group', room_name='General')
        messages = (await b.request('history', room_name='General'))['messages']
        assert [message['content'] for message in messages] == allowed
        assert all(message['username'] == 'mor' for message in messages)
        return {'allowed_messages': len(allowed), 'blocked_cases': 5,
                'model_http_calls': Service.llm_calls, 'provider_http_calls': len(Service.domains),
                'room_isolation': True, 'history_and_reconnect': True,
                'services': 'controlled loopback HTTP fakes; no real model/provider'}
    finally:
        await asyncio.gather(*(client.close() for client in clients))


def main():
    Service.mode, Service.llm_calls, Service.domains = 'allow', 0, []
    service = ThreadingHTTPServer(('127.0.0.1', 0), Service)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{service.server_port}'
    try:
        with tempfile.TemporaryDirectory(prefix='security-smoke-') as directory, patch.dict('os.environ', {
            'LOCAL_LLM_MODEL': 'controlled-local-fixture', 'LOCAL_LLM_ENDPOINT': base + '/api/generate',
            'LOCAL_LLM_TIMEOUT_SECONDS': '2', 'VIRUSTOTAL_API_BASE_URL': base + '/domains',
            'VIRUSTOTAL_API_KEY': 'TEST_ONLY_KEY', 'URL_REPUTATION_RATE_LIMIT_PER_MINUTE': '100',
        }):
            root = Path(directory)
            server = ServerProcess(ROOT, root / 'chat.db', root / 'chat.log')
            try:
                uri = server.start()
                result = asyncio.run(verify(uri))
                print(json.dumps(result, indent=2))
            finally:
                server.stop()
    finally:
        service.shutdown()
        service.server_close()
        thread.join()


if __name__ == '__main__':
    main()
