"""Use the browser transport against the real server and isolated security fixtures."""
import shutil
import subprocess
from pathlib import Path

import pytest
from test_security_integration import secured_server

ROOT = Path(__file__).resolve().parents[1]


def test_browser_transport_real_server(secured_server):
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js 22+ is required for browser transport integration')
    result = subprocess.run(
        [node, str(ROOT / 'ui/tests/server-scenario.mjs'), secured_server.uri],
        cwd=ROOT, capture_output=True, text=True, timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
