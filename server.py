from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI()

connected_clients = []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)

    print(f"Client connected. Total clients: {len(connected_clients)}")

    try:
        while True:
            data = await websocket.receive_text()
            print("Received:", data)

            for client in connected_clients:
                if client != websocket:
                    await client.send_text(data)

    except WebSocketDisconnect:
        connected_clients.remove(websocket)
        print(f"Client disconnected. Total clients: {len(connected_clients)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)