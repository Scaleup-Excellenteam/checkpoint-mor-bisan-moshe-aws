PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    username TEXT NOT NULL
        COLLATE NOCASE
        UNIQUE,
    password_hash TEXT NOT NULL,

    CHECK (
        length(username) BETWEEN 3 AND 20
        AND username = lower(username)
        AND username NOT GLOB '*[^a-z0-9_]*'
    )
);


CREATE TABLE IF NOT EXISTS chat_rooms (
    room_id INTEGER PRIMARY KEY,
    room_type TEXT NOT NULL
        DEFAULT 'group',
    room_name TEXT
        COLLATE NOCASE
        UNIQUE,
    created_at TEXT NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        room_type IN ('group', 'private')
    ),

    CHECK (
        (
            room_type = 'group'
            AND room_name IS NOT NULL
            AND length(trim(room_name)) > 0
            AND room_name = trim(room_name)
        )
        OR
        (
            room_type = 'private'
            AND room_name IS NULL
        )
    )
);


CREATE TABLE IF NOT EXISTS room_members (
    room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at TEXT NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    left_at TEXT DEFAULT NULL,

    PRIMARY KEY (room_id, user_id),

    FOREIGN KEY (room_id)
        REFERENCES chat_rooms(room_id)
        ON DELETE CASCADE,

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    CHECK (
        left_at IS NULL
        OR left_at >= joined_at
    )
);


CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY,
    room_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    sent_at TEXT NOT NULL
        DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT DEFAULT NULL,
    
    FOREIGN KEY (room_id)
        REFERENCES chat_rooms(room_id)
        ON DELETE CASCADE,

    FOREIGN KEY (sender_id)
        REFERENCES users(user_id)
        ON DELETE RESTRICT,

    CHECK (
        length(trim(content)) > 0
    ),

    CHECK (
        deleted_at IS NULL
        OR deleted_at >= sent_at
    )
);


CREATE INDEX IF NOT EXISTS idx_messages_room_history
    ON messages (room_id, sent_at, message_id);


CREATE INDEX IF NOT EXISTS idx_active_memberships_by_user
    ON room_members (user_id)
    WHERE left_at IS NULL;


COMMIT;