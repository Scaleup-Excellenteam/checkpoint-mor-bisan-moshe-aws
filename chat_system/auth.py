import re
import secrets
import sqlite3
from typing import Any

import bcrypt

from chat_system.database import create_user, get_user_by_username


sessions: dict[str, int] = {}

def normalize_username(username: str) -> str:
    """Remove surrounding spaces and convert a username to lowercase."""
    return username.strip().lower()


def validate_username(username: str) -> bool:
    """
    Return whether the username satisfies the required format.

    A valid username contains 3-20 lowercase English letters,
    digits or underscores.
    """
    pattern = r'[a-z0-9_]{3,20}'

    if re.fullmatch(pattern, username):
        return True
    return False


def validate_password(password: str) -> bool:
    """
    Return whether the password satisfies the password policy.

    The password must contain 8-32 allowed characters and at least
    two of these categories: letters, digits and special characters.
    """
    special_char_set = r'[@#$%^&*]'
    allowed_char_set = r'[a-zA-Z0-9@#$%^&*]{8,32}'

    valid_characters = bool(re.fullmatch(allowed_char_set, password))
    has_letters = bool(re.search(r'[a-zA-Z]', password))
    has_numbers = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(special_char_set, password))

    # True = 1, False = 0
    return (
        valid_characters
        and (has_letters + has_numbers + has_special) >= 2
    )


def hash_password(password: str) -> str:
    """Create and return a bcrypt password hash containing its salt."""
    password_bytes = password.encode("utf-8")
    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return password_hash.decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Return whether a plaintext password matches a stored bcrypt hash."""
    password_bytes = password.encode("utf-8")
    password_hash_bytes = password_hash.encode("utf-8")
    return bcrypt.checkpw(password_bytes, password_hash_bytes)


def create_session(user_id: int) -> str:
    """Create a secure session token and associate it with the user."""
    token = secrets.token_urlsafe(32)

    while token in sessions:
        token = secrets.token_urlsafe(32)

    sessions[token] = user_id
    return token


def signup(username: str, password: str) -> dict[str, Any]:
    """
    Validate the input and create a new account.

    Return a success result containing user_id and username, or an
    error result.
    """
    normalized_username = normalize_username(username)

    if not validate_username(normalized_username):
        return {
            "ok": False,
            "error": "invalid_username",
        }

    if not validate_password(password):
        return {
            "ok": False,
            "error": "invalid_password",
        }

    if get_user_by_username(normalized_username):
        return {
            "ok": False,
            "error": "username_taken",
        }

    password_hash = hash_password(password)

    try:
        user_id = create_user(normalized_username, password_hash)
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed: users.username" not in str(exc):
            raise
        return {
            "ok": False,
            "error": "username_taken",
        }

    return {
        "ok": True,
        "user_id": user_id,
        "username": normalized_username,
    }


def login(username: str, password: str) -> dict[str, Any]:
    """
    Validate credentials and create a session.

    Return a success result containing token, user_id and username,
    or invalid_credentials.
    """
    if not validate_password(password):
        return {"ok": False, "error": "invalid_credentials"}
    normalized_username = normalize_username(username)
    user = get_user_by_username(normalized_username)

    if not user or not verify_password(password, user["password_hash"]):
        return {
            "ok": False,
            "error": "invalid_credentials",
        }

    token = create_session(user["user_id"])

    return {
        "ok": True,
        "token": token,
        "user_id": user["user_id"],
        "username": user["username"],
    }


def validate_session(token: str) -> int | None:
    """Return the session's user_id, or None if the token is invalid."""
    return sessions.get(token)