import asyncio
import websockets

async def client():
    async with websockets.connect("ws://localhost:8000") as websocket:
        await websocket.send("Hello server!")
        response = await websocket.recv()
        print("Server replied:", response)

asyncio.run(client())