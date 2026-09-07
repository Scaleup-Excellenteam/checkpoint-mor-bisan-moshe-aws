"""WebSocket chat server; blocking database/auth work runs in worker threads."""
import asyncio
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import auth
import database as db

log = logging.getLogger("chat")


@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(os.getenv("CHAT_LOG", "chat.log"))])
    db.initialize_database()
    app.state.clients = {}
    app.state.operations = asyncio.Lock()
    log.info("server_start")
    yield
    log.info("server_stop")


app = FastAPI(lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "status": "healthy"}


class InvalidRequest(Exception):
    pass


def error(code):
    return {"ok": False, "error": code}


def execute(request):
    action = request["action"]
    if action in ("signup", "login"):
        if not all(isinstance(request.get(k), str) for k in ("username", "password")):
            return error("invalid_request"), None
        result = getattr(auth, action)(request["username"], request["password"])
        log.info("auth action=%s ok=%s", action, result["ok"])
        return result, result.get("user_id") if action == "login" and result["ok"] else None
    if action not in {"list_groups", "create_group", "join_group", "leave_group", "select_room", "history", "send_message"}:
        return error("unsupported_operation"), None
    token = request.get("token")
    user = auth.validate_session(token) if isinstance(token, str) else None
    if user is None:
        return error("unauthenticated"), None
    if action == "list_groups":
        return {"ok": True, "groups": db.list_groups()}, user
    name = request.get("room_name")
    if not isinstance(name, str) or not name.strip() or name != name.strip():
        return error("invalid_room_name"), user
    if action == "create_group":
        try:
            return {"ok": True, **db.create_group(name, user)}, user
        except sqlite3.IntegrityError as exc:
            if "UNIQUE constraint failed: chat_rooms.room_name" in str(exc):
                return error("group_already_exists"), user
            raise
    if action in {"join_group", "leave_group"}:
        return getattr(db, action)(user, name), user
    room = db.get_group_by_name(name)
    if room is None:
        return error("group_not_found"), user
    if not db.is_active_member(user, room["room_id"]):
        return error("not_active_member"), user
    if action == "select_room":
        return {"ok": True, **room}, user
    if action == "history":
        return {"ok": True, "messages": db.get_room_history(user, room["room_id"])}, user
    content = request.get("content")
    if not isinstance(content, str) or not content.strip():
        return error("invalid_request"), user
    return db.save_message(room["room_id"], user, content), user


async def writer(ws, queue):
    try:
        while True:
            await asyncio.wait_for(ws.send_json(await queue.get()), timeout=10)
    except (Exception, asyncio.CancelledError):
        try:
            await ws.close()
        except Exception:
            pass


def enqueue(ws, state, message):
    try:
        state["queue"].put_nowait(message)
    except asyncio.QueueFull:
        log.warning("slow_client_disconnect")
        state["writer"].cancel()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    state = {"user": None, "selected_room": None, "queue": asyncio.Queue(maxsize=256)}
    state["writer"] = asyncio.create_task(writer(ws, state["queue"]))
    app.state.clients[ws] = state
    log.info("connection_open peer=%s", ws.client)
    try:
        while True:
            packet = await ws.receive()
            if packet["type"] == "websocket.disconnect":
                break
            request = None
            request_id = None
            action = None
            try:
                raw = packet.get("text")
                if raw is None or len(raw.encode("utf-8")) > 65536:
                    raise InvalidRequest("invalid_request")
                try:
                    request = json.loads(raw)
                except json.JSONDecodeError:
                    raise InvalidRequest("invalid_json") from None
                if not isinstance(request, dict):
                    raise InvalidRequest("invalid_request")
                request_id = request.get("id")
                action = request.get("action")
                if not isinstance(request_id, str) or not 1 <= len(request_id) <= 64 or not isinstance(action, str):
                    request_id = None
                    raise InvalidRequest("invalid_request")
                # Serialize state transitions and recipient snapshots, never socket I/O.
                async with app.state.operations:
                    result, user = await asyncio.to_thread(execute, request)
                    if user is not None:
                        if state["user"] != user:
                            state["selected_room"] = None
                        state["user"] = user
                    if result["ok"]:
                        if action in {"create_group", "join_group", "select_room"}:
                            state["selected_room"] = result["room_id"]
                        elif action == "leave_group":
                            # Membership is shared, but selection belongs to each connection.
                            for recipient in app.state.clients.values():
                                if recipient["user"] == user and recipient["selected_room"] == result["room_id"]:
                                    recipient["selected_room"] = None
                    enqueue(ws, state, {"type": "response", "id": request_id, "action": action, **result})
                    if action == "send_message" and result["ok"]:
                        event = {"type": "event", "action": "room_message", "room_name": request["room_name"], **result}
                        for peer, recipient in list(app.state.clients.items()):
                            if (recipient["user"] is not None
                                    and recipient["selected_room"] == result["room_id"]
                                    and await asyncio.to_thread(db.is_active_member, recipient["user"], result["room_id"])):
                                enqueue(peer, recipient, event)
                    log.info("request action=%s user=%s ok=%s error=%s message_id=%s", action, user, result["ok"], result.get("error"), result.get("message_id"))
            except InvalidRequest as exc:
                code = str(exc) if str(exc) in {"invalid_request", "invalid_json"} else "invalid_request"
                enqueue(ws, state, {"type": "response", "id": request_id, **error(code)})
                log.warning("malformed_request error=%s", code)
            except Exception:
                log.exception("request_failed")
                enqueue(ws, state, {"type": "response", "id": request_id, **error("internal_error")})
    except WebSocketDisconnect:
        pass
    finally:
        app.state.clients.pop(ws, None)
        state["writer"].cancel()
        await state["writer"]
        log.info("connection_close user=%s peer=%s; login or token required on reconnect", state["user"], ws.client)


if __name__ == "__main__":
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, ws_max_size=65536)
