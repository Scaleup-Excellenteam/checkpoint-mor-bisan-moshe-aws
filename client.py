import asyncio
import json
import websockets


async def chat_client():
    uri = "ws://127.0.0.1:8000/ws"
    token = None

    async with websockets.connect(uri) as ws:
        print("Connected to server")

        while True:
            print("\n1. Signup\n2. Login\n3. Exit")
            choice = await asyncio.to_thread(input, "Choose an option: ")

            if choice == "3":
                break
            if choice not in ("1", "2"):
                print("Please choose 1, 2, or 3.")
                continue

            username = await asyncio.to_thread(input, "Username: ")
            password = await asyncio.to_thread(input, "Password: ")
            action = "signup" if choice == "1" else "login"
            request = {
                "action": action,
                "username": username,
                "password": password,
            }
            await ws.send(json.dumps(request))
            response = json.loads(await ws.recv())

            if action == "signup":
                if response["ok"]:
                    print("Signup successful")
                    print("Username:", response["username"])
                else:
                    print("Signup failed:", response["error"])
            elif response["ok"]:
                token = response["token"]
                print("Logged in as:", response["username"])
            else:
                print("Login failed:", response["error"])


if __name__ == "__main__":
    asyncio.run(chat_client())
