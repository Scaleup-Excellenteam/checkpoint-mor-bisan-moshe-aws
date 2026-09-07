"""Production HTTP and WebSocket routes coexist without external services."""
import asyncio
import urllib.request

from test_security_integration import secured_server
from client import ChatClient


def test_static_health_websocket_and_project_paths(secured_server, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    base = secured_server.health.removesuffix('/health')
    for path, mime, expected in [('/', 'text/html', 'id="auth-form"'),
                                ('/static/app.mjs', 'text/javascript', 'ChatConnection'),
                                ('/static/health.mjs', 'text/javascript', 'HealthMonitor'),
                                ('/static/theme.css', 'text/css', '.connection'),
                                ('/health', 'application/json', 'healthy')]:
        with urllib.request.urlopen(base + path, timeout=3) as response:
            assert response.status == 200
            assert response.headers.get_content_type() == mime
            assert expected in response.read().decode()

    async def request():
        client = ChatClient(secured_server.uri)
        await client.connect()
        try:
            assert (await client.request('list_groups'))['error'] == 'unauthenticated'
        finally:
            await client.close()
    asyncio.run(request())
    assert not secured_server.llm_calls and not secured_server.urls
