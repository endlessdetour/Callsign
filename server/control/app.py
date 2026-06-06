import hashlib
import hmac
import os
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from flask import Flask, Response, g, jsonify, request

SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from auth_store import AuthStore


app = Flask(__name__)


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


def _load_seed_token() -> str:
    token = _env("CALLSIGN_ACCESS_TOKEN")
    if token:
        return token

    token_file = _env("CALLSIGN_ACCESS_TOKEN_FILE", default="/etc/callsign/access_token")
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


SEED_ACCESS_TOKEN = _load_seed_token()
SESSION_TTL_SECONDS = int(_env("CALLSIGN_SESSION_TTL", default="3600"))
ADMIN_SESSION_TTL_SECONDS = int(_env("CALLSIGN_ADMIN_SESSION_TTL", default="28800"))
TUNNEL_PUBLIC_URL = _env("CALLSIGN_TUNNEL_PUBLIC_URL")
TUNNEL_PATH = _env("CALLSIGN_TUNNEL_PATH", default="/tunnel") or "/tunnel"
INITIAL_ADMIN_FILE = _env("CALLSIGN_INITIAL_ADMIN_FILE", default="/etc/callsign/initial_admin_credentials.txt")

AUTH_STORE = AuthStore(_env("CALLSIGN_DB_PATH", default="/etc/callsign/callsign.db"))
AUTH_STORE.initialize()
_initial_admin = AUTH_STORE.ensure_initial_admin(seed_token=SEED_ACCESS_TOKEN)
if _initial_admin:
    line = (
        f"username={_initial_admin['username']} password={_initial_admin['password']} token={_initial_admin['token']}"
    )
    print(f"[callsign][admin-init] {line}")
    try:
        os.makedirs(os.path.dirname(INITIAL_ADMIN_FILE), exist_ok=True)
        with open(INITIAL_ADMIN_FILE, "w", encoding="utf-8") as f:
            f.write(line + "\n")
        os.chmod(INITIAL_ADMIN_FILE, 0o600)
    except OSError as exc:
        print(f"[callsign][admin-init] failed to write credentials file: {exc}")


@dataclass
class Session:
    device_id: str
    assigned_ip: str
    owner_username: str
    owner_token: str
    created_at: int
    expires_at: int


SESSIONS: Dict[str, Session] = {}
SESSIONS_LOCK = threading.Lock()


def _sign(value: str) -> str:
    secret = SEED_ACCESS_TOKEN or "callsign-session-secret"
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _assigned_ip_for_device(device_id: str) -> str:
    digest = hashlib.sha256(device_id.encode("utf-8")).digest()
    suffix = digest[0] % 250 + 2
    return f"10.99.0.{suffix}"


def _deny_444() -> tuple[str, int]:
    return "", 444


def _parse_expiry_to_epoch(raw_value: str, permanent: bool) -> Optional[int]:
    if permanent:
        return None

    value = (raw_value or "").strip()
    if not value or value.lower() in {"permanent", "forever", "never"}:
        return None

    if value.isdigit():
        return int(value)

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = datetime.strptime(value, "%Y-%m-%d")
            dt = datetime(d.year, d.month, d.day, 23, 59, 59)
        except ValueError as exc:
            raise ValueError("invalid expires_at format; use YYYY-MM-DD or ISO datetime") from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return int(dt.timestamp())


def _is_client_api(path: str) -> bool:
    return path.startswith("/api/v1/") and not path.startswith("/api/v1/manage/")


def _admin_user_from_request():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    session_token = auth.split(" ", 1)[1].strip()
    return AUTH_STORE.validate_admin_session(session_token)


@app.before_request
def _require_user_token_for_client_apis():
    if request.path == "/login":
        return None
    if request.path.startswith("/api/v1/manage/"):
        return None
    if request.path != "/healthz" and not _is_client_api(request.path):
        return _deny_444()

    access_token = request.headers.get("X-Access-Token", "").strip()
    user = AUTH_STORE.verify_user_token(access_token)
    if user is None:
        return _deny_444()

    g.auth_user = user
    return None


@app.errorhandler(404)
def _not_found(_err):
    return _deny_444()


def issue_session_token(device_id: str, assigned_ip: str, owner_username: str, owner_token: str) -> str:
    now = int(time.time())
    expires_at = now + SESSION_TTL_SECONDS
    payload = f"{device_id}:{now}:{expires_at}"
    sig = _sign(payload)
    token = f"{payload}:{sig}"
    with SESSIONS_LOCK:
        SESSIONS[token] = Session(
            device_id=device_id,
            assigned_ip=assigned_ip,
            owner_username=owner_username,
            owner_token=owner_token,
            created_at=now,
            expires_at=expires_at,
        )
    return token


def validate_session_token(token: str, requester_token: str) -> Session:
    parts = token.split(":")
    if len(parts) != 4:
        raise ValueError("malformed token")

    device_id, created_at, expires_at, signature = parts
    payload = f"{device_id}:{created_at}:{expires_at}"
    expected = _sign(payload)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid signature")

    with SESSIONS_LOCK:
        session = SESSIONS.get(token)
    if session is None:
        raise ValueError("unknown session")

    if not hmac.compare_digest(requester_token, session.owner_token):
        raise ValueError("token mismatch")

    active_user = AUTH_STORE.verify_user_token(session.owner_token)
    if active_user is None:
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)
        raise ValueError("user inactive")

    now = int(time.time())
    if now > session.expires_at:
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)
        raise ValueError("expired")

    return session


def _cleanup_loop():
    while True:
        try:
            AUTH_STORE.deactivate_expired_users()
            now = int(time.time())
            with SESSIONS_LOCK:
                expired_tokens = [k for k, v in SESSIONS.items() if v.expires_at < now]
                for k in expired_tokens:
                    SESSIONS.pop(k, None)

                stale_tokens = [k for k, v in SESSIONS.items() if AUTH_STORE.verify_user_token(v.owner_token) is None]
                for k in stale_tokens:
                    SESSIONS.pop(k, None)
        except Exception as exc:
            print(f"[callsign][cleanup] warning: {exc}")
        time.sleep(60)


threading.Thread(target=_cleanup_loop, daemon=True).start()


@app.get("/healthz")
def healthz():
    return jsonify({"ok": True, "service": "control-plane"})


@app.post("/api/v1/bootstrap")
def bootstrap():
    data = request.get_json(silent=True) or {}
    device_id = (data.get("device_id") or "").strip()

    if not device_id:
        return _deny_444()

    assigned_ip = _assigned_ip_for_device(device_id)
    owner_token = request.headers.get("X-Access-Token", "").strip()
    owner_username = g.auth_user.username
    session_token = issue_session_token(device_id, assigned_ip, owner_username, owner_token)

    tunnel_url = TUNNEL_PUBLIC_URL
    if not tunnel_url:
        scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
        ws_scheme = "wss" if scheme == "https" else "ws"
        tunnel_url = f"{ws_scheme}://{request.host}{TUNNEL_PATH}"

    return jsonify(
        {
            "session_token": session_token,
            "assigned_ip": assigned_ip,
            "mtu": 1400,
            "routes": ["0.0.0.0/0"],
            "dns": ["1.1.1.1", "8.8.8.8"],
            "heartbeat_interval_sec": 20,
            "tunnel_url": tunnel_url,
        }
    )


@app.post("/api/v1/heartbeat")
def heartbeat():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return _deny_444()

    token = auth.split(" ", 1)[1].strip()
    access_token = request.headers.get("X-Access-Token", "").strip()
    try:
        session = validate_session_token(token, access_token)
    except ValueError:
        return _deny_444()

    return jsonify({"ok": True, "device_id": session.device_id, "ts": int(time.time())})


@app.post("/api/v1/validate")
def validate():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return _deny_444()

    token = auth.split(" ", 1)[1].strip()
    access_token = request.headers.get("X-Access-Token", "").strip()
    try:
        session = validate_session_token(token, access_token)
    except ValueError:
        return _deny_444()

    return jsonify({"ok": True, "device_id": session.device_id, "assigned_ip": session.assigned_ip})


@app.post("/api/v1/manage/login")
def admin_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))

    user = AUTH_STORE.verify_admin_credentials(username, password)
    if user is None:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401

    session_token = AUTH_STORE.create_admin_session(user.id, ttl_seconds=ADMIN_SESSION_TTL_SECONDS)
    return jsonify({"ok": True, "admin_session_token": session_token, "username": user.username})


@app.get("/api/v1/manage/users")
def admin_list_users():
    if _admin_user_from_request() is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "users": AUTH_STORE.list_users()})


@app.post("/api/v1/manage/users")
def admin_create_user():
    if _admin_user_from_request() is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    token = str(payload.get("token", "")).strip()
    permanent = bool(payload.get("permanent", False))
    expires_raw = str(payload.get("expires_at", "")).strip()

    try:
        expires_at = _parse_expiry_to_epoch(expires_raw, permanent=permanent)
        user = AUTH_STORE.create_user(username=username, expires_at=expires_at, token=token)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"create failed: {exc}"}), 400

    return jsonify({"ok": True, "user": user})


@app.patch("/api/v1/manage/users/<username>")
def admin_update_user(username: str):
    if _admin_user_from_request() is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    token = payload.get("token")
    token_value = None if token is None else str(token).strip()
    is_active = payload.get("is_active")
    if is_active is not None:
        is_active = bool(is_active)

    permanent = bool(payload.get("permanent", False))
    expires_raw = str(payload.get("expires_at", "")).strip()
    try:
        expires_at = _parse_expiry_to_epoch(expires_raw, permanent=permanent)
        AUTH_STORE.update_user(username=username, expires_at=expires_at, token=token_value, is_active=is_active)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"update failed: {exc}"}), 400

    return jsonify({"ok": True})


@app.delete("/api/v1/manage/users/<username>")
def admin_delete_user(username: str):
    if _admin_user_from_request() is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    try:
        AUTH_STORE.delete_user(username)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True})


def _render_admin_page():
    html = """
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>Callsign User Admin</title>
  <style>
    body { font-family: Segoe UI, sans-serif; margin: 24px; max-width: 1100px; }
    input, button { padding: 8px; margin: 4px; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    .row { margin: 8px 0; }
    .mono { font-family: Consolas, monospace; font-size: 12px; }
  </style>
</head>
<body>
  <h2>Callsign User Admin</h2>
  <div class=\"row\">Username <input id=\"u\" value=\"admin\" /> Password <input id=\"p\" type=\"password\" /></div>
  <div class=\"row\"><button onclick=\"login()\">Login</button> <span id=\"status\"></span></div>

  <h3>Create User</h3>
  <div class=\"row\">
    Username <input id=\"newU\" />
    Token(optional) <input id=\"newT\" class=\"mono\" size=\"48\" />
    Expire (YYYY-MM-DD or blank) <input id=\"newE\" />
    Permanent <input id=\"newP\" type=\"checkbox\" checked />
    <button onclick=\"createUser()\">Create</button>
  </div>

  <h3>Users</h3>
  <button onclick=\"loadUsers()\">Refresh</button>
  <table id=\"tbl\"><thead><tr><th>username</th><th>token</th><th>expires_at</th><th>permanent</th><th>active</th><th>admin</th><th>action</th></tr></thead><tbody></tbody></table>

<script>
let adminToken = "";

function authHeaders() {
  return {"Authorization": "Bearer " + adminToken, "Content-Type": "application/json"};
}

async function login() {
    const resp = await fetch('/api/v1/manage/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: document.getElementById('u').value, password: document.getElementById('p').value})
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) {
    document.getElementById('status').innerText = 'login failed';
    return;
  }
  adminToken = data.admin_session_token;
  document.getElementById('status').innerText = 'login ok';
  loadUsers();
}

async function loadUsers() {
  if (!adminToken) return;
    const resp = await fetch('/api/v1/manage/users', {headers: authHeaders()});
  const data = await resp.json();
  const tbody = document.querySelector('#tbl tbody');
  tbody.innerHTML = '';
  if (!resp.ok || !data.ok) return;
  for (const u of data.users) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${u.username}</td><td class=\"mono\">${u.token}</td><td>${u.expires_at ?? ''}</td><td>${u.permanent}</td><td>${u.is_active}</td><td>${u.is_admin}</td><td><button onclick=\"delUser('${u.username}')\">Delete</button></td>`;
    tbody.appendChild(tr);
  }
}

async function createUser() {
  if (!adminToken) return;
  const payload = {
    username: document.getElementById('newU').value,
    token: document.getElementById('newT').value,
    expires_at: document.getElementById('newE').value,
    permanent: document.getElementById('newP').checked,
  };
    const resp = await fetch('/api/v1/manage/users', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) alert(data.error || 'create failed');
  loadUsers();
}

async function delUser(name) {
  if (!adminToken) return;
    const resp = await fetch('/api/v1/manage/users/' + encodeURIComponent(name), {
    method: 'DELETE',
    headers: authHeaders(),
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) alert(data.error || 'delete failed');
  loadUsers();
}
</script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")


@app.get("/login")
def login_page():
    return _render_admin_page()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
