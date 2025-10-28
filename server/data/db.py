# data/db.py
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

_DB_FILE = "defensive.db"

_CREATE_CLIENTS = """
CREATE TABLE IF NOT EXISTS Clients (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    publicKey  TEXT,
    lastSeen   TEXT,
    uniqueId   BLOB UNIQUE
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
    """Single entry point for DB access."""
    def __init__(self, base_dir: Optional[Path] = None, db_filename: str = _DB_FILE):
        base = base_dir or Path(__file__).resolve().parent.parent  # server_py/
        self.db_path = (base / db_filename) if not Path(db_filename).is_absolute() else Path(db_filename)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
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
        # Minimal migration: ensure 'uniqueId' exists
        cur.execute("PRAGMA table_info(Clients)")
        cols = {row[1] for row in cur.fetchall()}
        if "uniqueId" not in cols:
            cur.execute("ALTER TABLE Clients ADD COLUMN uniqueId BLOB UNIQUE")
        self._conn.commit()

    # ----- Client ops -----
    def username_exists(self, username: str) -> bool:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute("SELECT 1 FROM Clients WHERE username = ?", (username,))
        return cur.fetchone() is not None

    def insert_client_with_uuid(self, username: str, public_key: str, unique_id_bytes: bytes) -> int:
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO Clients (username, publicKey, lastSeen, uniqueId) VALUES (?,?,?,?)",
            (username, public_key, now, unique_id_bytes)
        )
        self._conn.commit()
        return cur.lastrowid

    def get_client_id_by_uuid(self, unique_id_bytes: bytes) -> Optional[int]:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute("SELECT ID FROM Clients WHERE uniqueId = ?", (unique_id_bytes,))
        row = cur.fetchone()
        return int(row[0]) if row else None

    def update_last_seen_by_id(self, client_id: int) -> None:
        assert self._conn is not None
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute("UPDATE Clients SET lastSeen = ? WHERE ID = ?", (now, client_id))
        self._conn.commit()

    # ----- Message ops -----
    def insert_message(self, to_client_id: Optional[int], from_client_id: int,
                       msg_type: str, content: str) -> int:
        assert self._conn is not None
        created_at = datetime.now(timezone.utc).isoformat()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO Messages (toClient, fromClient, type, content, createdAt) VALUES (?,?,?,?,?)",
            (to_client_id, from_client_id, msg_type, content, created_at)
        )
        self._conn.commit()
        return cur.lastrowid
    
    def get_clients_excluding_uuid(self, exclude_unique_id: bytes):
        """Return list of (uniqueId_bytes, username) excluding the given unique id."""
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute(
            "SELECT uniqueId, username FROM Clients WHERE uniqueId IS NOT NULL AND uniqueId != ? ORDER BY username ASC",
            (exclude_unique_id,)
        )
        return [(bytes(row[0]), row[1]) for row in cur.fetchall()]

    def get_rowid_by_uuid(self, unique_id_bytes: bytes) -> Optional[int]:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute("SELECT ID FROM Clients WHERE uniqueId = ?", (unique_id_bytes,))
        row = cur.fetchone()
        return int(row[0]) if row else None

    def get_uuid_by_rowid(self, client_rowid: int) -> Optional[bytes]:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute("SELECT uniqueId FROM Clients WHERE ID = ?", (client_rowid,))
        row = cur.fetchone()
        return bytes(row[0]) if row and row[0] is not None else None
    
    def get_public_key_by_uuid(self, unique_id_bytes: bytes) -> Optional[str]:
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute("SELECT publicKey FROM Clients WHERE uniqueId = ?", (unique_id_bytes,))
        row = cur.fetchone()
        return row[0] if row and row[0] is not None else None

    def save_message(self, to_client_rowid: int, from_client_rowid: int,
                     msg_type: int, content: bytes) -> int:
        assert self._conn is not None
        created_at = datetime.now(timezone.utc).isoformat()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO Messages (toClient, fromClient, type, content, createdAt) VALUES (?,?,?,?,?)",
            (to_client_rowid, from_client_rowid, str(msg_type), sqlite3.Binary(content), created_at)
        )
        self._conn.commit()
        return cur.lastrowid

    def get_waiting_messages_for(self, to_client_rowid: int):
        """Return list of rows for a recipient, then delete them."""
        assert self._conn is not None
        cur = self._conn.cursor()
        cur.execute(
            "SELECT ID, fromClient, type, content FROM Messages WHERE toClient = ? ORDER BY ID ASC",
            (to_client_rowid,)
        )
        rows = cur.fetchall()
        # delete after fetch
        if rows:
            ids = [r[0] for r in rows]
            qmarks = ",".join("?" for _ in ids)
            cur.execute(f"DELETE FROM Messages WHERE ID IN ({qmarks})", ids)
            self._conn.commit()
        return rows

    # Context manager
    def __enter__(self) -> "Database":
        self.connect()
        return self
    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
