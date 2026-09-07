"""Reproducible local concurrency and reliability scenario for the chat server."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

import websockets
from websockets.exceptions import ConnectionClosed

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Password1"


@dataclass
class Metrics:
    attempted: int = 0
    successful: int = 0
    failed: int = 0
    unexpected_disconnects: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def record(self, elapsed: float, ok: bool) -> None:
        self.attempted += 1
        self.latencies_ms.append(elapsed * 1000)
        if ok:
            self.successful += 1
        else:
            self.failed += 1

    def summary(self) -> dict[str, object]:
        values = sorted(self.latencies_ms)
        percentile = lambda fraction: values[min(len(values) - 1, int(len(values) * fraction))] if values else 0.0
        return {
            "attempted": self.attempted,
            "successful": self.successful,
            "failed": self.failed,
            "unexpected_disconnects": self.unexpected_disconnects,
            "latency_ms": {
                "min": round(values[0], 2) if values else 0.0,
                "p50": round(percentile(0.50), 2),
                "p95": round(percentile(0.95), 2),
                "max": round(values[-1], 2) if values else 0.0,
            },
        }


class Client:
    def __init__(self, uri: str, metrics: Metrics):
        self.uri = uri
        self.metrics = metrics
        self.ws = None
        self.reader = None
        self.pending: dict[str, asyncio.Future] = {}
        self.events: asyncio.Queue[dict] = asyncio.Queue()
        self.intentional_close = False

    async def connect(self) -> None:
        self.intentional_close = False
        self.ws = await websockets.connect(self.uri, max_size=None)
        self.reader = asyncio.create_task(self._receive())

    async def _receive(self) -> None:
        try:
            async for raw in self.ws:
                message = json.loads(raw)
                if message.get("type") == "event":
                    await self.events.put(message)
                else:
                    future = self.pending.get(message.get("id"))
                    if future and not future.done():
                        future.set_result(message)
        except (ConnectionClosed, asyncio.CancelledError):
            pass
        finally:
            if not self.intentional_close:
                self.metrics.unexpected_disconnects += 1
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("connection closed"))

    async def request(self, action: str, **fields) -> dict:
        request_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        started = time.perf_counter()
        try:
            await self.ws.send(json.dumps({"id": request_id, "action": action, "token": getattr(self, "token", None), **fields}))
            response = await asyncio.wait_for(future, 30)
            self.metrics.record(time.perf_counter() - started, bool(response.get("ok")))
            if action == "login" and response.get("ok"):
                self.token = response["token"]
            return response
        except Exception:
            self.metrics.record(time.perf_counter() - started, False)
            raise
        finally:
            self.pending.pop(request_id, None)

    async def close(self) -> None:
        if self.ws is None:
            return
        self.intentional_close = True
        await self.ws.close()
        if self.reader:
            await self.reader
        self.ws = None
        self.reader = None

    async def drain_events(self, expected: set[str], timeout: float = 5) -> list[dict]:
        received = []
        deadline = time.perf_counter() + timeout
        while len(received) < len(expected):
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            event = await asyncio.wait_for(self.events.get(), remaining)
            if event.get("content") in expected:
                received.append(event)
        return received


class ServerProcess:
    def __init__(self, root: Path, database_path: Path, log_path: Path):
        self.root = root
        self.database_path = database_path
        self.log_path = log_path
        self.process = None
        self.port = None
        self.output = None

    def start(self) -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        env = {**os.environ, "CHAT_DATABASE": str(self.database_path), "CHAT_LOG": str(self.log_path)}
        self.output = self.log_path.open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            [sys.executable, "server.py", "--host", "127.0.0.1", "--port", str(self.port)],
            cwd=self.root,
            env=env,
            stdout=self.output,
            stderr=self.output,
        )
        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=0.2) as response:
                    if json.load(response) == {"ok": True, "status": "healthy"}:
                        return f"ws://127.0.0.1:{self.port}/ws"
            except (OSError, ValueError):
                if self.process.poll() is not None:
                    raise RuntimeError(f"server exited during startup; see {self.log_path}")
            time.sleep(0.05)
        raise TimeoutError(f"server startup timeout; see {self.log_path}")

    def stop(self) -> None:
        if self.process is None:
            return
        process = self.process
        output = self.output
        self.process = None
        self.output = None
        process.terminate()
        try:
            process.wait(timeout=10)
        finally:
            if output:
                output.close()


async def _assert_no_event(client: Client, timeout: float = 0.25) -> None:
    try:
        event = await asyncio.wait_for(client.events.get(), timeout)
    except asyncio.TimeoutError:
        return
    raise AssertionError(f"unexpected event: {event}")


async def scenario(client_count: int, message_count: int) -> dict[str, object]:
    if client_count < 3:
        raise ValueError("client_count must be at least 3")
    if message_count < 1:
        raise ValueError("message_count must be positive")

    metrics = Metrics()
    scenario_started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="chat-load-") as temporary:
        temporary_path = Path(temporary)
        server = ServerProcess(ROOT, temporary_path / "chat.db", temporary_path / "chat.log")
        uri = server.start()
        clients = [Client(uri, metrics) for _ in range(client_count)]
        alpha_messages: list[str] = []
        usernames: list[str] = []
        try:
            await asyncio.gather(*(client.connect() for client in clients))
            for index, client in enumerate(clients):
                username = f"load_{index}_{uuid.uuid4().hex[:6]}"
                usernames.append(username)
                assert (await client.request("signup", username=username, password=PASSWORD))["ok"]
                assert (await client.request("login", username=username, password=PASSWORD))["ok"]

            assert (await clients[0].request("create_group", room_name="alpha"))["ok"]
            for client in clients[1:]:
                assert (await client.request("join_group", room_name="alpha"))["ok"]
                assert (await client.request("select_room", room_name="alpha"))["ok"]
            assert (await clients[0].request("select_room", room_name="alpha"))["ok"]

            async def send_from(client: Client, content: str) -> dict:
                return await client.request("send_message", room_name="alpha", content=content)

            for round_number in range(message_count):
                contents = [f"alpha-{round_number}-{index}" for index in range(2)]
                alpha_messages.extend(contents)
                responses = await asyncio.gather(
                    send_from(clients[0], contents[0]),
                    send_from(clients[1], contents[1]),
                )
                assert all(response["ok"] for response in responses)
                for client in clients[:2]:
                    events = await client.drain_events(set(contents))
                    assert Counter(event["content"] for event in events) == Counter(contents)

            assert (await clients[2].request("leave_group", room_name="alpha"))["ok"]
            assert (await clients[2].request("create_group", room_name="beta"))["ok"]
            assert (await clients[2].request("select_room", room_name="beta"))["ok"]
            beta_content = "beta-isolated"
            assert (await clients[2].request("send_message", room_name="beta", content=beta_content))["ok"]
            assert (await clients[2].drain_events({beta_content}))
            await _assert_no_event(clients[0])
            await _assert_no_event(clients[1])

            assert (await clients[1].request("leave_group", room_name="alpha"))["ok"]
            after_leave = "alpha-after-leave"
            assert (await clients[0].request("send_message", room_name="alpha", content=after_leave))["ok"]
            alpha_messages.append(after_leave)
            assert (await clients[0].drain_events({after_leave}))
            await _assert_no_event(clients[1])

            assert (await clients[1].request("join_group", room_name="alpha"))["ok"]
            assert (await clients[1].request("select_room", room_name="alpha"))["ok"]
            history = (await clients[1].request("history", room_name="alpha"))["messages"]
            assert [message["content"] for message in history] == alpha_messages

            await clients[1].close()
            await clients[1].connect()
            assert (await clients[1].request("login", username=usernames[1], password=PASSWORD))["ok"]
            assert (await clients[1].request("select_room", room_name="alpha"))["ok"]
            persisted = (await clients[1].request("history", room_name="alpha"))["messages"]
            assert [message["content"] for message in persisted] == alpha_messages

            for client in clients:
                await client.close()
            server.stop()
            uri = server.start()
            reconnected = Client(uri, metrics)
            await reconnected.connect()
            assert (await reconnected.request("login", username=usernames[0], password=PASSWORD))["ok"]
            assert (await reconnected.request("select_room", room_name="alpha"))["ok"]
            restarted_history = (await reconnected.request("history", room_name="alpha"))["messages"]
            assert [message["content"] for message in restarted_history] == alpha_messages
            await reconnected.close()
            server.stop()
        finally:
            await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)
            server.stop()

    result = metrics.summary()
    result["elapsed_seconds"] = round(time.perf_counter() - scenario_started, 3)
    result["verified_alpha_messages"] = len(alpha_messages)
    result["verified_beta_isolation"] = True
    return result


def run_scenario(client_count: int = 3, message_count: int = 2) -> dict[str, object]:
    started = time.perf_counter()
    result = asyncio.run(scenario(client_count, message_count))
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clients", type=int, default=3, help="number of concurrent accounts (default: 3)")
    parser.add_argument("--messages", type=int, default=2, help="messages per sender round (default: 2)")
    args = parser.parse_args()
    result = run_scenario(args.clients, args.messages)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["failed"] == 0 and result["unexpected_disconnects"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
