"""Startup configuration in fresh processes; no developer .env or network."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.parametrize("mode", ["file", "os", "defaults", "disabled"])
def test_server_environment(tmp_path, mode):
    root = Path(__file__).resolve().parents[1]
    project = tmp_path / "project"
    project.mkdir()
    for source in root.glob("*.py"):
        shutil.copy2(source, project / source.name)
    for name in ("chat_system", "config"):
        shutil.copytree(root / name, project / name, ignore=shutil.ignore_patterns("__pycache__"))
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("CHAT_", "LOCAL_LLM_", "URL_REPUTATION_", "VIRUSTOTAL_", "PYTHON_DOTENV_"))}
    env["PYTHONPATH"] = str(project)
    env["CHAT_LOG"] = str(tmp_path / "test.log")
    if mode != "defaults":
        (project / ".env").write_text(
            "LOCAL_LLM_MODEL=file-model\nLOCAL_LLM_TIMEOUT_SECONDS=17\n"
            "URL_REPUTATION_REQUEST_TIMEOUT_SECONDS=7\n"
            "CHAT_DATABASE=file.db\nVIRUSTOTAL_API_KEY=\n", encoding="utf-8")
    if mode == "os":
        env.update(LOCAL_LLM_MODEL="os-model", LOCAL_LLM_TIMEOUT_SECONDS="19",
                   URL_REPUTATION_REQUEST_TIMEOUT_SECONDS="9", CHAT_DATABASE="os.db")
    if mode == "disabled":
        env["PYTHON_DOTENV_DISABLED"] = "1"
    expected = {"file": ("file-model", 17, 7, "file.db"),
                "os": ("os-model", 19, 9, "os.db"),
                "defaults": ("qwen2.5:1.5b", 30, 10, str(project / "chat.db")),
                "disabled": ("qwen2.5:1.5b", 30, 10, str(project / "chat.db"))}[mode]
    code = '''
import asyncio
import socket
def forbidden(*args, **kwargs):
    raise AssertionError("External network must not be contacted")
socket.create_connection = forbidden
import server
from chat_system import local_llm
from chat_system import url_security
expected = EXPECTED
model, endpoint, timeout = local_llm._configuration()
assert (model, timeout) == expected[:2]
assert endpoint == "http://127.0.0.1:11434/api/generate"
assert url_security.REQUEST_TIMEOUT_SECONDS == expected[2]
assert str(server.db.DATABASE_PATH) == expected[3]
assert url_security.CACHE_TTL_SECONDS == 86400
async def check():
    # Windows creates an internal socket pair while constructing the event loop.
    socket.socket.connect = forbidden
    async with server.lifespan(server.app):
        assert isinstance(server.app.state.reputation, url_security.VirusTotalURLReputationChecker)
        assert isinstance(server.app.state.policy.classifier, local_llm.OllamaRecipeClassifier)
        decision = server.app.state.reputation.check("https://example.com")
        assert decision.action == "block"
        assert decision.reason_code == "reputation_unavailable"
        assert server.health()["ok"]
asyncio.run(check())
'''.replace("EXPECTED", repr(expected))
    result = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                            env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VIRUSTOTAL_API_KEY" not in result.stdout + result.stderr
