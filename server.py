"""WebSocket chat server; blocking database/auth work runs in worker threads."""
import asyncio
import json
import logging
import os
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

# Load before auth/database and URL imports read configuration. OS values win.
load_dotenv(Path(__file__).resolve().parent / ".env", override=False)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from chat_system import auth
from chat_system import database as db
from chat_system.dlp import RuleDLPChecker
from chat_system.local_llm import OllamaRecipeClassifier
from chat_system.security_contracts import MessageSecurityContext
from chat_system.security_policy import SecurityPolicy
from chat_system.url_security import RegexURLExtractor, VirusTotalURLReputationChecker

log = logging.getLogger("chat")


@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        handlers=[logging.StreamHandler(), logging.FileHandler(os.getenv("CHAT_LOG", "chat.log"))])
    db.initialize_database()
    app.state.clients = {}
    app.state.operations = asyncio.Lock()
    app.state.checker = RuleDLPChecker()
    app.state.reputation = VirusTotalURLReputationChecker()
    app.state.policy = SecurityPolicy(app.state.checker, OllamaRecipeClassifier(),
                                     RegexURLExtractor(), app.state.reputation)
    # HTTP client INFO logs include provider URLs; security logs contain metadata only.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    log.info("server_start")
    try:
        yield
    finally:
        await asyncio.to_thread(app.state.reputation.close)
        log.info("server_stop")


app = FastAPI(lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "status": "healthy"}


class InvalidRequest(Exception):
    pass


def error(code):
    return {"ok": False, "error": code}


def security_result(decision, operation, user=None, room=None):
    if operation != 'send_message':  # Message stages are correlated inside the policy.
        log.info("security operation=%s user=%s room=%s action=%s rules_score=%s source=%s reason=%s",
                 operation, user, room, decision.action, decision.risk_score,
                 decision.source, decision.reason_code)
    if decision.action != "allow":
        return {"ok": False, "error": decision.reason_code,
                "security": {"action": decision.action, "risk_score": decision.risk_score,
                             "source": decision.source, "reason_code": decision.reason_code}}
    return None


def execute(request):
    action = request["action"]
    if action in ("signup", "login"):
        if not all(isinstance(request.get(k), str) for k in ("username", "password")):
            return error("invalid_request"), None
        if action == "signup":
            username = auth.normalize_username(request["username"])
            if not auth.validate_username(username):
                return error("invalid_username"), None
            if not auth.validate_password(request["password"]):
                return error("invalid_password"), None
            blocked = security_result(app.state.checker.check("username", username), action)
            if blocked:
                return blocked, None
        result = getattr(auth, action)(request["username"], request["password"])
        log.info("auth action=%s ok=%s", action, result["ok"])
        return result, result.get("user_id") if action == "login" and result["ok"] else None
    if action not in {"list_groups", "create_group", "join_group", "leave_group", "select_room", "history"}:
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
        blocked = security_result(app.state.checker.check("room_name", name), action, user)
        if blocked:
            return blocked, user
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
    return {"ok": True, "messages": db.get_room_history(user, room["room_id"])}, user


def validate_send(request, state):
    """No side effects: validate before checks and again before persistence."""
    token = request.get("token")
    user = auth.validate_session(token) if isinstance(token, str) else None
    if user is None:
        return error("unauthenticated"), None, None
    content = request.get("content")
    if not isinstance(content, str) or not content.strip():
        return error("invalid_request"), user, None
    name = request.get("room_name")
    if not isinstance(name, str) or not name.strip() or name != name.strip():
        return error("invalid_room_name"), user, None
    room = db.get_group_by_name(name)
    if room is None:
        return error("group_not_found"), user, None
    if not db.is_active_member(user, room["room_id"]):
        return error("not_active_member"), user, room
    if state["user"] != user or state["selected_room"] != room["room_id"]:
        return error("room_not_selected"), user, room
    return None, user, room


async def handle_send(ws, state, request):
    async with app.state.operations:
        invalid, user, room = await asyncio.to_thread(validate_send, request, state)
    if invalid:
        return invalid, user
    decision = await asyncio.to_thread(
        app.state.policy.evaluate, request["content"],
        MessageSecurityContext(user, room["room_id"]))
    blocked = security_result(decision, "send_message", user, room["room_id"])
    if blocked:
        return blocked, user
    async with app.state.operations:
        # Another connection may have left/rejoined while security I/O was pending.
        invalid, current_user, current_room = await asyncio.to_thread(validate_send, request, state)
        if invalid:
            return invalid, user
        if (current_user != user or current_room["room_id"] != room["room_id"]
                or ws not in app.state.clients):
            return error("unauthenticated"), user
        result = await asyncio.to_thread(db.save_message, room["room_id"], user, request["content"])
        if result["ok"]:
            event = {"type": "event", "action": "room_message", "room_name": room["room_name"], **result}
            for peer, recipient in list(app.state.clients.items()):
                if (recipient["user"] is not None
                        and recipient["selected_room"] == room["room_id"]
                        and await asyncio.to_thread(db.is_active_member, recipient["user"], room["room_id"])):
                    enqueue(peer, recipient, event)
        return result, user


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
                if action == "send_message":
                    result, user = await handle_send(ws, state, request)
                    enqueue(ws, state, {"type": "response", "id": request_id, "action": action, **result})
                    log.info("request action=send_message user=%s ok=%s error=%s message_id=%s",
                             user, result["ok"], result.get("error"), result.get("message_id"))
                    continue
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
                    log.info("request action=%s user=%s ok=%s error=%s message_id=%s", action, user, result["ok"], result.get("error"), result.get("message_id"))
            except InvalidRequest as exc:
                code = str(exc) if str(exc) in {"invalid_request", "invalid_json"} else "invalid_request"
                enqueue(ws, state, {"type": "response", "id": request_id, **error(code)})
                log.warning("malformed_request error=%s", code)
            except Exception:
                log.error("request_failed: unexpected server or database error")
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
