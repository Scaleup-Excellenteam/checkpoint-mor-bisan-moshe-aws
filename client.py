from websockets.sync.client import connect

URL = "ws://127.0.0.1:65432"

with connect(URL) as websocket:
    websocket.send("Hello, world")
    data = websocket.recv()

    print(f"Received: {data}")