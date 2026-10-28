"""Original persistent state for local RF protocol experiments.

Accounts are created explicitly through the local CLI, never from a captured
session. This module knows nothing about official game accounts or servers.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import secrets
import sqlite3
import time
import uuid

PASSWORD_ROUNDS = 600_000


@dataclass(frozen=True)
class Account:
    account_id: int
    login: str
    display_name: str
    experience: int
    carats: int
    cash: int
    medals: int
    guid: str
    country: str
    region: str


def bounded_ascii(value: str, maximum: int, label: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"{label} must contain ASCII characters") from None
    if not encoded or len(encoded) > maximum or any(c < 32 or c > 126 for c in encoded):
        raise ValueError(f"{label} must contain 1 through {maximum} printable characters")
    return encoded


class AccountStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id INTEGER PRIMARY KEY,
                    login TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL UNIQUE,
                    password_salt BLOB NOT NULL,
                    password_digest BLOB NOT NULL,
                    password_rounds INTEGER NOT NULL,
                    experience INTEGER NOT NULL DEFAULT 0,
                    carats INTEGER NOT NULL DEFAULT 0,
                    cash INTEGER NOT NULL DEFAULT 0,
                    medals INTEGER NOT NULL DEFAULT 0,
                    guid TEXT NOT NULL,
                    country TEXT NOT NULL DEFAULT 'US',
                    region TEXT NOT NULL DEFAULT 'NA',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS avatars (
                    avatar_id INTEGER PRIMARY KEY,
                    account_id INTEGER NOT NULL UNIQUE
                        REFERENCES accounts(account_id) ON DELETE CASCADE
                );
                INSERT OR IGNORE INTO metadata VALUES ('schema_version', '1');
            """)
            version = db.execute("SELECT value FROM metadata WHERE name='schema_version'").fetchone()[0]
            if version != "1":
                raise ValueError("Unsupported local database schema")
            # Preserve early local accounts created before avatar rows existed.
            # Existing avatar identifiers remain unchanged on every reopen.
            db.execute("""
                INSERT INTO avatars (account_id)
                SELECT accounts.account_id FROM accounts
                WHERE NOT EXISTS (
                    SELECT 1 FROM avatars WHERE avatars.account_id = accounts.account_id
                ) ORDER BY accounts.account_id
            """)

    @contextlib.contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def account(row: sqlite3.Row | None) -> Account | None:
        if row is None:
            return None
        return Account(**{field: row[field] for field in Account.__dataclass_fields__})

    def create(self, login: str, password: str, display_name: str) -> Account:
        bounded_ascii(login, 62, "Local login")
        bounded_ascii(display_name, 23, "Character name")
        raw_password = bounded_ascii(password, 20, "Local password")
        if len(raw_password) < 8:
            raise ValueError("Choose a local password of at least eight characters")
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", raw_password, salt, PASSWORD_ROUNDS)
        with self.connection() as db, db:
            try:
                cursor = db.execute("""
                    INSERT INTO accounts
                    (login, display_name, password_salt, password_digest,
                     password_rounds, guid, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (login, display_name, salt, digest, PASSWORD_ROUNDS,
                      str(uuid.uuid4()), int(time.time())))
            except sqlite3.IntegrityError:
                raise ValueError("That local login or character name already exists") from None
            row = db.execute("SELECT * FROM accounts WHERE account_id=?", (cursor.lastrowid,)).fetchone()
            db.execute("INSERT INTO avatars (account_id) VALUES (?)", (cursor.lastrowid,))
        return self.account(row)

    def authenticate(self, login: str, password: str) -> Account | None:
        # Bound work and avoid recording failed passwords or identifiers.
        try:
            bounded_ascii(login, 62, "Local login")
            encoded = bounded_ascii(password, 20, "Local password")
        except ValueError:
            return None
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE login=?", (login,)).fetchone()
        if row is None:
            return None
        digest = hashlib.pbkdf2_hmac("sha256", encoded, row["password_salt"], row["password_rounds"])
        if not hmac.compare_digest(digest, row["password_digest"]):
            return None
        return self.account(row)

    def get(self, account_id: int) -> Account | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE account_id=?", (account_id,)).fetchone()
        return self.account(row)

    def count(self) -> int:
        with self.connection() as db:
            return db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]

    def avatar_for(self, account_id: int) -> int:
        with self.connection() as db:
            row = db.execute("SELECT avatar_id FROM avatars WHERE account_id=?", (account_id,)).fetchone()
        if row is None:
            raise ValueError("No local avatar record for this account")
        return row[0]
