import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

import auth
from database import initialize_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(lifespan=lifespan)

connected_clients = []


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)

    print(f"Client connected. Total clients: {len(connected_clients)}")

    try:
        while True:
            data = await websocket.receive_text()

            try:
                request = json.loads(data)
            except json.JSONDecodeError:
                # Keep ordinary text chat, but reject malformed JSON requests.
                if data.lstrip().startswith(("{", "[")):
                    await websocket.send_text(json.dumps({
                        "ok": False, "error": "invalid_json",
                    }))
                    continue
                request = None

            if isinstance(request, dict):
                action = request.get("action")
                if not isinstance(action, str):
                    await websocket.send_text(json.dumps({
                        "ok": False, "error": "invalid_request",
                    }))
                    continue

                if action in ("signup", "login"):
                    username = request.get("username")
                    password = request.get("password")
                    if not isinstance(username, str) or not isinstance(password, str):
                        response = {"ok": False, "error": "invalid_request"}
                    elif action == "signup":
                        response = auth.signup(username, password)
                    else:
                        response = auth.login(username, password)

                    await websocket.send_text(json.dumps(response))
                    continue

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
