import sqlite3
import os
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
DATABASE_PATH = Path(os.environ.get("CHAT_DATABASE", str(BASE_DIR / "chat.db")))
SCHEMA_PATH = BASE_DIR / "config" / "schema.sql"


def get_connection() -> sqlite3.Connection:
    """Open and configure a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    """Create the database tables and indexes from schema.sql."""
    conn = get_connection()

    try:
        with open(SCHEMA_PATH, 'r', encoding="utf-8") as f:
            schema_script = f.read()
        conn.executescript(schema_script)
    finally:
        conn.close()


def create_user(username: str, password_hash: str) -> int:
    """Create a user and return the generated user_id."""
    conn = get_connection()
    sql = '''INSERT INTO users(username,password_hash)
            VALUES(?,?)'''

    try:
        cursor = conn.execute(sql, (username, password_hash))
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    """Return a user by username, or None if the user does not exist."""
    conn = get_connection()
    sql = '''SELECT user_id, username, password_hash
            FROM users
            WHERE username = ?'''

    try:
        cursor = conn.execute(sql, (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def create_group(room_name: str, creator_id: int) -> dict[str, Any]:
    """
    Create a group and add its creator as a member.

    Return information about the created group or an error result.
    """
    conn = get_connection()
    sql_room = '''INSERT INTO chat_rooms(room_name, room_type)
                VALUES(?, ?)'''
    sql_room_member = '''INSERT INTO room_members(user_id,room_id)
                VALUES(?,?)'''
    
    try:
        cursor = conn.execute(sql_room, (room_name, 'group'))
        room_id = cursor.lastrowid
        conn.execute(sql_room_member, (creator_id,room_id))
        conn.commit()

        return {
            "room_id" : room_id,
            "room_name" : room_name,
            "creator_id" : creator_id,
        }
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_group_by_name(room_name: str) -> dict[str, Any] | None:
    """Return a group by name, or None if it does not exist."""
    conn = get_connection()
    sql = '''SELECT room_id, room_name, room_type, created_at
                FROM chat_rooms
                WHERE room_name = ? 
                AND room_type = 'group' '''
    
    try:
        cursor = conn.execute(sql, (room_name,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def list_groups() -> list[dict[str, Any]]:
    """Return all public group rooms."""
    conn = get_connection()
    sql = """SELECT room_id, room_name, room_type, created_at
            FROM chat_rooms
            WHERE room_type = 'group'
            ORDER BY room_name"""

    try:
        cursor = conn.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def join_group(user_id: int, room_name: str) -> dict[str, Any]:
    """
    Add a user to an existing group.

    Return an error if the group does not exist or the user is already
    an active member.
    """
    conn = get_connection()

    sql_group = """SELECT room_id
                   FROM chat_rooms
                   WHERE room_name = ?
                   AND room_type = 'group'"""

    sql_membership = """SELECT left_at
                        FROM room_members
                        WHERE room_id = ?
                        AND user_id = ?"""

    sql_insert = """INSERT INTO room_members (room_id, user_id)
                    VALUES (?, ?)"""

    sql_rejoin = """UPDATE room_members
                    SET joined_at = CURRENT_TIMESTAMP,
                        left_at = NULL
                    WHERE room_id = ?
                    AND user_id = ?"""

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(sql_group, (room_name,))
        group = cursor.fetchone()

        if not group:
            return {
                "ok": False,
                "error": "group_not_found",
            }

        room_id = group["room_id"]

        cursor = conn.execute(
            sql_membership,
            (room_id, user_id),
        )
        membership = cursor.fetchone()

        if membership and membership["left_at"] is None:
            return {
                "ok": False,
                "error": "already_member",
            }

        if membership:
            conn.execute(sql_rejoin, (room_id, user_id))
        else:
            conn.execute(sql_insert, (room_id, user_id))

        conn.commit()

        return {
            "ok": True,
            "room_id": room_id,
            "room_name": room_name,
            "user_id": user_id,
        }
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def leave_group(user_id: int, room_name: str) -> dict[str, Any]:
    """
    Mark a user's membership in a group as inactive.

    Return an error if the group does not exist or the user is not
    an active member.
    """
    conn = get_connection()

    sql_group = """SELECT room_id
                   FROM chat_rooms
                   WHERE room_name = ?
                   AND room_type = 'group'"""

    sql_leave = """UPDATE room_members
                   SET left_at = CURRENT_TIMESTAMP
                   WHERE room_id = ?
                   AND user_id = ?
                   AND left_at IS NULL"""

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(sql_group, (room_name,))
        group = cursor.fetchone()

        if not group:
            return {
                "ok": False,
                "error": "group_not_found",
            }

        room_id = group["room_id"]
        cursor = conn.execute(sql_leave, (room_id, user_id))

        if cursor.rowcount == 0:
            return {
                "ok": False,
                "error": "not_active_member",
            }

        conn.commit()

        return {
            "ok": True,
            "room_id": room_id,
            "room_name": room_name,
            "user_id": user_id,
        }
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def is_active_member(user_id: int, room_id: int) -> bool:
    """Return whether the user is currently an active member of the room."""
    conn = get_connection()
    sql = """SELECT 1
             FROM room_members
             WHERE user_id = ?
             AND room_id = ?
             AND left_at IS NULL"""

    try:
        cursor = conn.execute(sql, (user_id, room_id))
        row = cursor.fetchone()
        return row is not None
    finally:
        conn.close()


def save_message(room_id: int, sender_id: int, content: str) -> dict[str, Any]:
    """
    Save a message and return its stored information.

    The sender must be an active member of the room.
    """
    conn = get_connection()

    sql_member = """SELECT users.username
                    FROM room_members
                    JOIN users ON users.user_id = room_members.user_id
                    WHERE room_id = ?
                    AND room_members.user_id = ?
                    AND left_at IS NULL"""

    sql_message = """INSERT INTO messages (room_id, sender_id, content)
                     VALUES (?, ?, ?)"""

    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            sql_member,
            (room_id, sender_id),
        )
        membership = cursor.fetchone()

        if not membership:
            return {
                "ok": False,
                "error": "not_active_member",
            }

        cursor = conn.execute(
            sql_message,
            (room_id, sender_id, content),
        )
        message_id = cursor.lastrowid
        conn.commit()

        return {
            "ok": True,
            "message_id": message_id,
            "room_id": room_id,
            "sender_id": sender_id,
            "username": membership["username"],
            "content": content,
        }
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_room_history(user_id: int, room_id: int) -> list[dict[str, Any]]:
    """
    Return the room's stored messages in chronological order.

    The requesting user must be an active member of the room.
    """
    conn = get_connection()

    sql_member = """SELECT 1
                    FROM room_members
                    WHERE room_id = ?
                    AND user_id = ?
                    AND left_at IS NULL"""

    sql_history = """SELECT messages.message_id,
                            messages.room_id,
                            messages.sender_id,
                            users.username,
                            messages.content,
                            messages.sent_at
                     FROM messages
                     JOIN users
                        ON users.user_id = messages.sender_id
                     WHERE messages.room_id = ?
                     AND messages.deleted_at IS NULL
                     ORDER BY messages.sent_at,
                              messages.message_id"""

    try:
        conn.execute("BEGIN")
        cursor = conn.execute(sql_member, (room_id, user_id))
        membership = cursor.fetchone()

        if not membership:
            raise PermissionError("not_active_member")

        cursor = conn.execute(sql_history, (room_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
