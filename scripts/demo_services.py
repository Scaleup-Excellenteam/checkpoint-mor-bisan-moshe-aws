"""Offline stand-ins for the local model and VirusTotal, for live demos without keys.

Runs one loopback HTTP server that answers both adapter protocols:

  POST /api/generate         Ollama-style generation endpoint used by
                             chat_system.local_llm (strict JSON allow/block).
  GET  /domains/{hostname}   VirusTotal-style domain report used by
                             chat_system.url_security.

Deterministic fixture verdicts (hostnames are reserved example names, never visited):

  evil.example.com       2 malicious engines   -> policy: malicious_url (block)
  review.example.com     1 malicious engine    -> policy: reputation_review_required
  unknown.example.com    no report (404)       -> policy: reputation_review_required
  timeout.example.com    request hangs         -> policy: reputation_unavailable
  anything else          recent harmless report -> allowed

Model verdicts: the fake classifier says "block" when the text plus recent attempts
contain at least two recipe clues (ingredient, quantity/unit, action, time/temperature),
otherwise "allow". Set ``--llm-mode allow|block|timeout`` to force a verdict.

Start it, then start the server in a shell where these variables are set (the
script prints the exact PowerShell/bash lines). This changes only where the real
adapters connect; policy code, thresholds and fail-closed behavior are untouched.
The real adapters still validate the endpoint (loopback only) and parse responses
exactly as they would for the real services.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLUE_PATTERNS = {
    "ingredient": re.compile(r"\b(flour|water|yeast|salt|sugar|oil|tomato(?:es)?|cheese|mozzarella|basil)\b", re.I),
    "quantity": re.compile(r"\b\d+(?:\.\d+)?\s*(?:g|kg|ml|l|cups?|tbsp|tsp|grams?|ounces?|oz)\b", re.I),
    "action": re.compile(r"\b(mix|knead|bake|stir|combine|preheat|roll|spread|proof|rest)\b", re.I),
    "time_temperature": re.compile(r"\b\d+\s*(?:°|degrees|c|f|min(?:utes)?|hours?|h)\b", re.I),
}


class DemoServices(BaseHTTPRequestHandler):
    llm_mode = "auto"
    request_log: list[str] = []

    def log_message(self, *args):  # quiet; we print our own summary lines
        pass

    def _reply(self, status: int, body: dict | None = None) -> None:
        payload = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    # -- fake local model -------------------------------------------------
    def do_POST(self) -> None:
        if self.path != "/api/generate":
            self._reply(404, {"error": "unknown endpoint"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        try:
            prompt = json.loads(body.get("prompt", "{}"))
        except json.JSONDecodeError:
            prompt = {}
        text = " ".join([str(prompt.get("text", "")), *map(str, prompt.get("recent_attempts", []))])
        mode = DemoServices.llm_mode
        if mode == "timeout":
            time.sleep(120)
            return
        if mode == "auto":
            clues = {name for name, pattern in CLUE_PATTERNS.items() if pattern.search(text)}
            mode = "block" if len(clues) >= 2 else "allow"
            print(f"[demo-llm] clues={sorted(clues)} -> {mode}", flush=True)
        else:
            print(f"[demo-llm] forced -> {mode}", flush=True)
        result = {"action": mode, "risk_score": 85 if mode == "block" else 10}
        self._reply(200, {"done": True, "response": json.dumps(result)})

    # -- fake VirusTotal --------------------------------------------------
    def do_GET(self) -> None:
        if not self.path.startswith("/domains/"):
            self._reply(404, {"error": "unknown endpoint"})
            return
        hostname = self.path.rsplit("/", 1)[-1]
        if not self.headers.get("x-apikey"):
            self._reply(401, {"error": "missing key"})
            return
        if hostname == "timeout.example.com":
            print(f"[demo-vt] {hostname} -> hang (timeout)", flush=True)
            time.sleep(120)
            return
        if hostname == "unknown.example.com":
            print(f"[demo-vt] {hostname} -> 404 no report", flush=True)
            self._reply(404, {"error": {"code": "NotFoundError"}})
            return
        malicious = {"evil.example.com": 2, "review.example.com": 1}.get(hostname, 0)
        print(f"[demo-vt] {hostname} -> malicious={malicious} harmless=60", flush=True)
        self._reply(200, {"data": {"attributes": {
            "last_analysis_date": int(time.time()),
            "last_analysis_stats": {"malicious": malicious, "suspicious": 0,
                                    "harmless": 60, "undetected": 10},
        }}})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--llm-mode", choices=["auto", "allow", "block", "timeout"], default="auto")
    args = parser.parse_args()
    DemoServices.llm_mode = args.llm_mode
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoServices)
    base = f"http://127.0.0.1:{args.port}"
    print(f"Demo services listening on {base} (fake local model + fake VirusTotal).")
    print("Start the chat server from a shell with these variables set:\n")
    print("  PowerShell:")
    print(f'    $env:LOCAL_LLM_ENDPOINT = "{base}/api/generate"')
    print('    $env:LOCAL_LLM_MODEL = "demo-fixture"')
    print('    $env:LOCAL_LLM_TIMEOUT_SECONDS = "5"')
    print(f'    $env:VIRUSTOTAL_API_BASE_URL = "{base}/domains"')
    print('    $env:VIRUSTOTAL_API_KEY = "DEMO_ONLY_KEY"')
    print('    $env:URL_REPUTATION_REQUEST_TIMEOUT_SECONDS = "5"')
    print('    $env:URL_REPUTATION_RATE_LIMIT_PER_MINUTE = "100"')
    print("    ./.venv/Scripts/python.exe server.py --host 0.0.0.0 --port 8000\n")
    print("  bash:")
    print(f"    LOCAL_LLM_ENDPOINT={base}/api/generate LOCAL_LLM_MODEL=demo-fixture LOCAL_LLM_TIMEOUT_SECONDS=5 \\")
    print(f"    VIRUSTOTAL_API_BASE_URL={base}/domains VIRUSTOTAL_API_KEY=DEMO_ONLY_KEY \\")
    print("    URL_REPUTATION_REQUEST_TIMEOUT_SECONDS=5 URL_REPUTATION_RATE_LIMIT_PER_MINUTE=100 python server.py\n")
    print("Fixture hosts: evil.example.com (block), review.example.com / unknown.example.com (review),")
    print("timeout.example.com (unavailable), anything else allowed. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
