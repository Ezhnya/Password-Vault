from __future__ import annotations
import sqlite3, os, time
from typing import Optional, List, Tuple, Any, Dict

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "vault.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT,
    url TEXT,
    notes TEXT,
    nonce BLOB NOT NULL,
    blob BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
"""

def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.executescript(SCHEMA)
    return conn

def get_meta(conn: sqlite3.Connection, key: str) -> Optional[bytes]:
    cur = conn.execute("SELECT v FROM meta WHERE k=?", (key,))
    row = cur.fetchone()
    return row[0] if row else None

def set_meta(conn: sqlite3.Connection, key: str, value: bytes) -> None:
    conn.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    conn.commit()

def add_entry(conn: sqlite3.Connection, name: str, username: str, url: str, notes: str,
              nonce: bytes, blob: bytes) -> int:
    ts = int(time.time())
    cur = conn.execute("""
        INSERT INTO entries(name, username, url, notes, nonce, blob, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, username, url, notes, nonce, blob, ts, ts))
    conn.commit()
    return cur.lastrowid

def update_entry(conn: sqlite3.Connection, entry_id: int, name: str, username: str, url: str, notes: str,
                 nonce: bytes, blob: bytes) -> None:
    ts = int(time.time())
    conn.execute("""
        UPDATE entries
        SET name=?, username=?, url=?, notes=?, nonce=?, blob=?, updated_at=?
        WHERE id=?
    """, (name, username, url, notes, nonce, blob, ts, entry_id))
    conn.commit()

def delete_entry(conn: sqlite3.Connection, entry_id: int) -> None:
    conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
    conn.commit()

def list_entries(conn: sqlite3.Connection) -> List[Tuple[Any, ...]]:
    cur = conn.execute("""
        SELECT id, name, username, url, notes, created_at, updated_at
        FROM entries
        ORDER BY name COLLATE NOCASE
    """)
    return cur.fetchall()

def get_entry_blob(conn: sqlite3.Connection, entry_id: int) -> Tuple[bytes, bytes]:
    cur = conn.execute("SELECT nonce, blob FROM entries WHERE id=?", (entry_id,))
    row = cur.fetchone()
    if not row:
        raise KeyError("Entry not found")
    return row[0], row[1]
