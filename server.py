import asyncio
import websockets

async def handler(connection):
    print("Client connected")

    message = await connection.recv()
    print("Received from client:", message)
    await connection.send("Hello client!")


async def main():
    async with websockets.serve(handler, "localhost", 8000):
        print("Server running at ws://localhost:8000")
        #await asyncio.Future()  # runs forever
        await asyncio.sleep(30)

asyncio.run(main())