"""Interactive UI; all communication is delegated to ChatClient."""
import argparse
import asyncio
import sys
from getpass import getpass
from websockets.exceptions import ConnectionClosed
from client import ChatClient


SECURITY_ERRORS = {
    "forbidden_term": "Blocked: forbidden protected term.",
    "recipe_blocked": "Blocked: suspected recipe disclosure.",
    "malicious_url": "Blocked: malicious URL reputation.",
    "security_check_unavailable": "Blocked: local security check unavailable.",
    "reputation_unavailable": "Blocked: URL reputation unavailable.",
    "reputation_review_required": "Blocked: URL reputation needs review.",
    "room_not_selected": "Select this room before sending a message.",
}


async def display_events(client):
    while True:
        event = await client.events.get()
        print(f"\n[{event['room_name']}] {event['username']}: {event['content']}", flush=True)


async def chat_client(uri):
    client = ChatClient(uri)
    await client.connect()
    print("Connected to server")
    display = asyncio.create_task(display_events(client))
    selected = None
    try:
        while True:
            if client.token is None:
                print("\n1. Signup\n2. Login\n3. Exit")
                choice = await asyncio.to_thread(input, "Choose an option: ")
                if choice == "3":
                    break
                if choice not in ("1", "2"):
                    print("Please choose 1, 2, or 3.")
                    continue
                username = await asyncio.to_thread(input, "Username: ")
                password = await asyncio.to_thread(getpass if sys.stdin.isatty() else input, "Password: ")
                action = "signup" if choice == "1" else "login"
                response = await client.request(action, username=username, password=password)
            else:
                line = await asyncio.to_thread(input, f"[{selected or '-'}] /list /create /join /leave /select /history /logout /reconnect /quit > ")
                command, _, argument = line.partition(" ")
                if command == "/quit":
                    break
                if command == "/logout":
                    response = await client.request("logout")
                    if response["ok"]:
                        selected = None
                        print("Logged out.")
                    else:
                        print("Could not log out. Please try again.")
                    continue
                if command == "/reconnect":
                    await client.close()
                    await client.connect()
                    client.token = None
                    selected = None
                    print("Reconnected. Please log in.")
                    continue
                mapping = {"/list": "list_groups", "/create": "create_group", "/join": "join_group", "/leave": "leave_group", "/select": "select_room", "/history": "history"}
                action = mapping.get(command, "send_message")
                if command.startswith("/") and command not in mapping:
                    print("Unknown command")
                    continue
                room = argument if action in {"create_group", "join_group", "leave_group", "select_room"} else selected
                if action != "list_groups" and not room:
                    print("Specify or select a room first.")
                    continue
                response = await client.request(action, room_name=room, content=line)
                if response["ok"] and action in {"create_group", "join_group", "select_room"}:
                    selected = response["room_name"]
                if response["ok"] and action == "leave_group" and room == selected:
                    selected = None
            if not response["ok"]:
                print("Error:", response["error"], SECURITY_ERRORS.get(response["error"], ""))
            elif "groups" in response:
                for group in response["groups"]:
                    print(group["room_name"])
            elif "messages" in response:
                for message in response["messages"]:
                    print(f"{message['sent_at']} {message['username']}: {message['content']}")
            elif action != "send_message":
                print(f"{action}: success")
    except (EOFError, ConnectionError, ConnectionClosed, OSError, asyncio.TimeoutError) as exc:
        print("Connection ended:", exc, "Restart the client to reconnect.")
    finally:
        display.cancel()
        await client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uri", default="ws://127.0.0.1:8000/ws")
    args = parser.parse_args()
    try:
        asyncio.run(chat_client(args.uri))
    except (KeyboardInterrupt, OSError) as exc:
        print("Client stopped:", exc)


if __name__ == "__main__":
    main()
