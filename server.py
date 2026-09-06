from websockets.sync.server import serve

HOST = "127.0.0.1"
PORT = 65432


def handle_client(websocket):
    print("Client connected")

    for message in websocket:
        print(f"Client sent: {message}")
        websocket.send(message)  # Echo back to this client

    print("Client disconnected")


with serve(handle_client, HOST, PORT) as server:
    print(f"Server listening on ws://{HOST}:{PORT}")
    server.serve_forever()