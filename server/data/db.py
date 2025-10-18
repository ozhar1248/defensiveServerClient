# data/db.py
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime, timezone

_DB_FILE = "defensive.db"

_CREATE_CLIENTS = """
CREATE TABLE IF NOT EXISTS Clients (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    publicKey  TEXT,
    lastSeen   TEXT
);
"""

_CREATE_MESSAGES = """
CREATE TABLE IF NOT EXISTS Messages (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    toClient    INTEGER,
    fromClient  INTEGER,
    type        TEXT NOT NULL,
    content     TEXT NOT NULL,
    createdAt   TEXT NOT NULL,
    FOREIGN KEY (toClient)   REFERENCES Clients(ID),
    FOREIGN KEY (fromClient) REFERENCES Clients(ID)
);
"""

class Database:
    """Single entry point for DB access. Responsible for connection + schema + queries."""
    def __init__(self, base_dir: Optional[Path] = None, db_filename: str = _DB_FILE):
        base = base_dir or Path(__file__).resolve().parent.parent  # server_py/
        self.db_path = (base / db_filename) if not Path(db_filename).is_absolute() else Path(db_filename)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        # Create file if missing (sqlite does this on connect)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._ensure_schema()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self) -> None:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute(_CREATE_CLIENTS)
        cur.execute(_CREATE_MESSAGES)
        self._conn.commit()

    # ----- Client ops -----
    def upsert_client(self, username: str, public_key: Optional[str] = None) -> int:
        """
        Ensure a client exists; update lastSeen and publicKey (if provided).
        Return client ID.
        """
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.cursor()
        # Try insert
        try:
            cur.execute(
                "INSERT INTO Clients (username, publicKey, lastSeen) VALUES (?, ?, ?)",
                (username, public_key, now)
            )
            self._conn.commit()
            return cur.lastrowid
        except sqlite3.IntegrityError:
            # Already exists -> update lastSeen (+ publicKey if given)
            if public_key is not None:
                cur.execute(
                    "UPDATE Clients SET publicKey = ?, lastSeen = ? WHERE username = ?",
                    (public_key, now, username)
                )
            else:
                cur.execute(
                    "UPDATE Clients SET lastSeen = ? WHERE username = ?",
                    (now, username)
                )
            self._conn.commit()
            # fetch ID
            cur.execute("SELECT ID FROM Clients WHERE username = ?", (username,))
            row = cur.fetchone()
            return int(row[0]) if row else -1

    def update_last_seen(self, client_id: int) -> None:
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute("UPDATE Clients SET lastSeen = ? WHERE ID = ?", (now, client_id))
        self._conn.commit()

    # ----- Message ops -----
    def insert_message(self, to_client_id: Optional[int], from_client_id: int,
                       msg_type: str, content: str) -> int:
        """
        Insert a message record. to_client_id may be None for server-only ack/logging.
        """
        assert self._conn is not None
        created_at = datetime.now(timezone.utc).isoformat()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO Messages (toClient, fromClient, type, content, createdAt) VALUES (?, ?, ?, ?, ?)",
            (to_client_id, from_client_id, msg_type, content, created_at)
        )
        self._conn.commit()
        return cur.lastrowid

    # Context manager helpers
    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
