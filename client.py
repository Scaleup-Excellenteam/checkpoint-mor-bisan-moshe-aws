import asyncio
import websockets


async def test_client():
    uri = "ws://127.0.0.1:8000/ws" #change 127.0.0.1 to the real IPv4 Address of server laptop
    async with websockets.connect(uri) as ws:
        await ws.send("Hello FastAPI server!")
        response = await ws.recv()
        print("Server replied:", response)

asyncio.run(test_client())