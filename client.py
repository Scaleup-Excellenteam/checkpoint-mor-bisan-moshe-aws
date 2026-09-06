import asyncio
import websockets


async def receive_messages(ws):
    while True:
        message = await ws.recv()
        print("\nReceived:", message)


async def send_messages(ws):
    while True:
        message = await asyncio.to_thread(input, "> ")
        await ws.send(message)


async def chat_client():
    uri = "ws://127.0.0.1:8000/ws"

    async with websockets.connect(uri) as ws:
        print("Connected to server")

        await asyncio.gather(
            receive_messages(ws),
            send_messages(ws)
        )


asyncio.run(chat_client())