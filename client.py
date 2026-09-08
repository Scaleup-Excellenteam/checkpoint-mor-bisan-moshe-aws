"""Network client with one receive task dispatching responses and events."""
import asyncio
import json
import uuid
import websockets
from websockets.exceptions import ConnectionClosed


class ChatClient:
    def __init__(self, uri="ws://127.0.0.1:8000/ws"):
        self.uri = uri
        self.token = None
        self.pending = {}
        self.events = asyncio.Queue()

    async def connect(self):
        self.ws = await websockets.connect(self.uri, max_size=None)
        self.reader = asyncio.create_task(self._receive())

    async def _receive(self):
        try:
            async for raw in self.ws:
                message = json.loads(raw)
                if message.get("type") == "event":
                    await self.events.put(message)
                else:
                    future = self.pending.get(message.get("id"))
                    if future and not future.done():
                        future.set_result(message)
        except ConnectionClosed:
            pass
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("Disconnected; reconnect and log in."))

    async def request(self, action, **fields):
        request_id = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        try:
            await self.ws.send(json.dumps({"id": request_id, "action": action, "token": self.token, **fields}))
            response = await asyncio.wait_for(future, 30)
            if action == "login" and response["ok"]:
                self.token = response["token"]
            elif action == "logout" and response["ok"]:
                self.token = None
            return response
        finally:
            self.pending.pop(request_id, None)

    async def close(self):
        await self.ws.close()
        await self.reader


if __name__ == "__main__":
    from cli import main
    main()
