import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional


DEFAULT_DB_PATH = os.getenv("CALLSIGN_DB_PATH", "/etc/callsign/callsign.db")

# Sentinel used to distinguish "field not provided" from an explicit None value.
_UNSET = object()
@dataclass
class UserRecord:
    id: int
    username: str
    token: str
    expires_at: Optional[int]
    is_admin: bool
    is_active: bool
    must_change: bool = False


class AuthStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT,
                        token TEXT UNIQUE NOT NULL,
                        expires_at INTEGER,
                        is_admin INTEGER NOT NULL DEFAULT 0,
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS admin_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        expires_at INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_token ON users(token)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_exp ON users(expires_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token)")

                existing_cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
                if "must_change_credentials" not in existing_cols:
                    conn.execute("ALTER TABLE users ADD COLUMN must_change_credentials INTEGER NOT NULL DEFAULT 0")

                conn.commit()

    def ensure_initial_admin(self, seed_token: str = "") -> Optional[dict[str, str]]:
        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1").fetchone()
                if row:
                    return None

                username = "admin"
                password = secrets.token_urlsafe(12)
                token = seed_token.strip() or secrets.token_urlsafe(32)
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, token, expires_at, is_admin, is_active, must_change_credentials, created_at, updated_at)
                    VALUES (?, ?, ?, NULL, 1, 1, 1, ?, ?)
                    """,
                    (username, _hash_password(password), token, now, now),
                )
                conn.commit()
                return {"username": username, "password": password, "token": token}

    def verify_user_token(self, token: str) -> Optional[UserRecord]:
        if not token:
            return None

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, username, token, expires_at, is_admin, is_active
                    FROM users
                    WHERE token = ?
                    LIMIT 1
                    """,
                    (token,),
                ).fetchone()
                if row is None:
                    return None

                if int(row["is_active"]) != 1:
                    return None

                expires_at = row["expires_at"]
                if expires_at is not None and now > int(expires_at):
                    conn.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return None

                return UserRecord(
                    id=int(row["id"]),
                    username=str(row["username"]),
                    token=str(row["token"]),
                    expires_at=int(expires_at) if expires_at is not None else None,
                    is_admin=int(row["is_admin"]) == 1,
                    is_active=int(row["is_active"]) == 1,
                )

    def verify_credentials(self, username: str, password: str) -> Optional[UserRecord]:
        """Verify username/password for ANY active user (admin or regular).

        Runs the password hash exactly once on every call (against the real
        hash when the user exists, otherwise against a fixed dummy hash) so the
        response time does not reveal whether a username exists.
        """
        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, username, password_hash, token, expires_at, is_admin, is_active, must_change_credentials
                    FROM users
                    WHERE username = ?
                    LIMIT 1
                    """,
                    (username,),
                ).fetchone()

                stored_hash = str(row["password_hash"] or "") if row is not None else ""
                password_ok = _verify_password(password, stored_hash or _DUMMY_PASSWORD_HASH)

                if row is None:
                    return None
                if int(row["is_active"]) != 1:
                    return None

                expires_at = row["expires_at"]
                if expires_at is not None and now > int(expires_at):
                    conn.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return None

                if not stored_hash or not password_ok:
                    return None

                return UserRecord(
                    id=int(row["id"]),
                    username=str(row["username"]),
                    token=str(row["token"]),
                    expires_at=int(expires_at) if expires_at is not None else None,
                    is_admin=int(row["is_admin"]) == 1,
                    is_active=True,
                    must_change=int(row["must_change_credentials"]) == 1,
                )

    def validate_session(self, session_token: str) -> Optional[UserRecord]:
        """Resolve a session token to ANY active user (admin or regular)."""
        if not session_token:
            return None

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT s.id AS sid, s.expires_at AS sess_exp,
                           u.id, u.username, u.token, u.expires_at, u.is_admin, u.is_active, u.must_change_credentials
                    FROM admin_sessions s
                    JOIN users u ON u.id = s.user_id
                    WHERE s.session_token = ?
                    LIMIT 1
                    """,
                    (session_token,),
                ).fetchone()
                if row is None:
                    return None

                if now > int(row["sess_exp"]):
                    conn.execute("DELETE FROM admin_sessions WHERE id = ?", (row["sid"],))
                    conn.commit()
                    return None

                if int(row["is_active"]) != 1:
                    return None

                exp = row["expires_at"]
                if exp is not None and now > int(exp):
                    conn.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return None

                return UserRecord(
                    id=int(row["id"]),
                    username=str(row["username"]),
                    token=str(row["token"]),
                    expires_at=int(exp) if exp is not None else None,
                    is_admin=int(row["is_admin"]) == 1,
                    is_active=True,
                    must_change=int(row["must_change_credentials"]) == 1,
                )

    def change_password(self, user_id: int, new_password: str) -> None:
        """Set a new password for a user and clear the must-change flag."""
        if len(new_password) < 8:
            raise ValueError("new password must be at least 8 characters")

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE users SET password_hash = ?, must_change_credentials = 0, updated_at = ? WHERE id = ?",
                    (_hash_password(new_password), now, user_id),
                )
                if cur.rowcount == 0:
                    raise ValueError("user not found")
                conn.commit()

    def admin_reset_password(self, username: str, new_password: str = "") -> dict[str, Any]:
        """Admin-initiated password reset for a regular user.

        Sets a new password (generated when not supplied), forces the user to
        change it on next login, and revokes their existing sessions.
        Returns the plaintext password so it can be shared once.
        """
        safe_username = username.strip()
        plain_password = new_password.strip() or secrets.token_urlsafe(9)
        if len(plain_password) < 8:
            raise ValueError("password must be at least 8 characters")

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT id, is_admin FROM users WHERE username = ?", (safe_username,)
                ).fetchone()
                if row is None:
                    raise ValueError("user not found")
                if int(row["is_admin"]) == 1:
                    raise ValueError("cannot reset an admin password here")
                conn.execute(
                    "UPDATE users SET password_hash = ?, must_change_credentials = 1, updated_at = ? WHERE id = ?",
                    (_hash_password(plain_password), now, row["id"]),
                )
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (row["id"],))
                conn.commit()

        return {"username": safe_username, "password": plain_password}

    def get_user_by_id(self, user_id: int) -> Optional[dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT username, token, expires_at, is_admin, is_active, created_at, updated_at
                    FROM users WHERE id = ? LIMIT 1
                    """,
                    (user_id,),
                ).fetchone()
        if row is None:
            return None
        return {
            "username": str(row["username"]),
            "token": str(row["token"]),
            "expires_at": int(row["expires_at"]) if row["expires_at"] is not None else None,
            "permanent": row["expires_at"] is None,
            "is_admin": int(row["is_admin"]) == 1,
            "is_active": int(row["is_active"]) == 1,
            "created_at": int(row["created_at"]),
            "updated_at": int(row["updated_at"]),
        }

    def verify_admin_credentials(self, username: str, password: str) -> Optional[UserRecord]:
        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, username, password_hash, token, expires_at, is_admin, is_active, must_change_credentials
                    FROM users
                    WHERE username = ?
                    LIMIT 1
                    """,
                    (username,),
                ).fetchone()
                if row is None:
                    return None
                if int(row["is_admin"]) != 1 or int(row["is_active"]) != 1:
                    return None

                expires_at = row["expires_at"]
                if expires_at is not None and now > int(expires_at):
                    conn.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return None

                if not _verify_password(password, str(row["password_hash"] or "")):
                    return None

                return UserRecord(
                    id=int(row["id"]),
                    username=str(row["username"]),
                    token=str(row["token"]),
                    expires_at=int(expires_at) if expires_at is not None else None,
                    is_admin=True,
                    is_active=True,
                    must_change=int(row["must_change_credentials"]) == 1,
                )

    def complete_admin_setup(self, current_admin_id: int, new_username: str, new_password: str) -> dict[str, Any]:
        new_username = new_username.strip()
        if not new_username:
            raise ValueError("new username is required")
        if new_username.lower() == "admin":
            raise ValueError("please choose a username other than 'admin'")
        if len(new_password) < 8:
            raise ValueError("new password must be at least 8 characters")

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                current = conn.execute(
                    "SELECT id, username, is_admin FROM users WHERE id = ? LIMIT 1",
                    (current_admin_id,),
                ).fetchone()
                if current is None or int(current["is_admin"]) != 1:
                    raise ValueError("current admin not found")

                clash = conn.execute(
                    "SELECT id FROM users WHERE username = ? AND id != ? LIMIT 1",
                    (new_username, current_admin_id),
                ).fetchone()
                if clash is not None:
                    raise ValueError("username already exists")

                new_token = secrets.token_urlsafe(32)
                cur = conn.execute(
                    """
                    INSERT INTO users (username, password_hash, token, expires_at, is_admin, is_active, must_change_credentials, created_at, updated_at)
                    VALUES (?, ?, ?, NULL, 1, 1, 0, ?, ?)
                    """,
                    (new_username, _hash_password(new_password), new_token, now, now),
                )
                new_id = int(cur.lastrowid or 0)

                # Disable the seeded admin account and revoke its sessions.
                conn.execute(
                    "UPDATE users SET is_active = 0, must_change_credentials = 0, updated_at = ? WHERE id = ?",
                    (now, current_admin_id),
                )
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (current_admin_id,))
                conn.commit()

        return {
            "id": new_id,
            "username": new_username,
            "token": new_token,
            "disabled_username": str(current["username"]),
        }

    def create_admin_session(self, user_id: int, ttl_seconds: int = 8 * 3600) -> str:
        now = int(time.time())
        token = secrets.token_urlsafe(40)
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO admin_sessions (user_id, session_token, expires_at, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, token, now + ttl_seconds, now),
                )
                conn.commit()
        return token

    def validate_admin_session(self, session_token: str) -> Optional[UserRecord]:
        if not session_token:
            return None

        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT s.id AS sid, s.expires_at AS sess_exp,
                           u.id, u.username, u.token, u.expires_at, u.is_admin, u.is_active, u.must_change_credentials
                    FROM admin_sessions s
                    JOIN users u ON u.id = s.user_id
                    WHERE s.session_token = ?
                    LIMIT 1
                    """,
                    (session_token,),
                ).fetchone()
                if row is None:
                    return None

                if now > int(row["sess_exp"]):
                    conn.execute("DELETE FROM admin_sessions WHERE id = ?", (row["sid"],))
                    conn.commit()
                    return None

                if int(row["is_admin"]) != 1 or int(row["is_active"]) != 1:
                    return None

                exp = row["expires_at"]
                if exp is not None and now > int(exp):
                    conn.execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (now, row["id"]))
                    conn.commit()
                    return None

                return UserRecord(
                    id=int(row["id"]),
                    username=str(row["username"]),
                    token=str(row["token"]),
                    expires_at=int(exp) if exp is not None else None,
                    is_admin=True,
                    is_active=True,
                    must_change=int(row["must_change_credentials"]) == 1,
                )

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT username, token, expires_at, is_admin, is_active, created_at, updated_at
                    FROM users
                    ORDER BY username ASC
                    """
                ).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "username": str(row["username"]),
                    "token": str(row["token"]),
                    "expires_at": int(row["expires_at"]) if row["expires_at"] is not None else None,
                    "permanent": row["expires_at"] is None,
                    "is_admin": int(row["is_admin"]) == 1,
                    "is_active": int(row["is_active"]) == 1,
                    "created_at": int(row["created_at"]),
                    "updated_at": int(row["updated_at"]),
                }
            )
        return result

    def create_user(self, username: str, expires_at: Optional[int], token: str = "", password: str = "", is_admin: bool = False) -> dict[str, Any]:
        now = int(time.time())
        safe_username = username.strip()
        if not safe_username:
            raise ValueError("username is required")
        if safe_username.lower() == "admin":
            raise ValueError("username 'admin' is reserved")

        safe_token = token.strip() or secrets.token_urlsafe(32)
        plain_password = password.strip() or secrets.token_urlsafe(9)
        if len(plain_password) < 8:
            raise ValueError("password must be at least 8 characters")

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, token, expires_at, is_admin, is_active, must_change_credentials, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)
                    """,
                    (safe_username, _hash_password(plain_password), safe_token, expires_at, 1 if is_admin else 0, now, now),
                )
                conn.commit()

        return {
            "username": safe_username,
            "token": safe_token,
            "password": plain_password,
            "expires_at": expires_at,
            "permanent": expires_at is None,
            "is_admin": is_admin,
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }

    def update_user(self, username: str, expires_at: Any = _UNSET, token: Any = _UNSET, is_active: Any = _UNSET) -> None:
        now = int(time.time())
        updates: list[str] = ["updated_at = ?"]
        params: list[Any] = [now]

        if expires_at is not _UNSET:
            updates.append("expires_at = ?")
            params.append(expires_at)

        if token is not _UNSET and token is not None:
            updates.append("token = ?")
            params.append(str(token).strip() or secrets.token_urlsafe(32))

        if is_active is not _UNSET and is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)

        params.append(username)

        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE username = ?", params)
                if cur.rowcount == 0:
                    raise ValueError("user not found")
                conn.commit()

    def delete_user(self, username: str) -> None:
        with self._lock:
            with self._connect() as conn:
                row = conn.execute("SELECT id, is_admin FROM users WHERE username = ?", (username,)).fetchone()
                if row is None:
                    raise ValueError("user not found")
                if int(row["is_admin"]) == 1:
                    raise ValueError("cannot delete admin user")

                conn.execute("DELETE FROM users WHERE id = ?", (row["id"],))
                conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (row["id"],))
                conn.commit()

    def deactivate_expired_users(self) -> int:
        now = int(time.time())
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET is_active = 0, updated_at = ?
                    WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at < ?
                    """,
                    (now, now),
                )
                conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
                conn.commit()
                return int(cur.rowcount)


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256$120000${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode())
        expected = base64.b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


# Fixed dummy hash used to equalize login timing when a username does not exist.
# Computed once at import; the plaintext is random and unknown so it never matches.
_DUMMY_PASSWORD_HASH = _hash_password(secrets.token_urlsafe(16))
