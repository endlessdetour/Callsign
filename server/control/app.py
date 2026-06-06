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
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Callsign Console</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #ffffff;
      --primary: #4f46e5;
      --primary-hover: #4338ca;
      --danger: #dc2626;
      --danger-hover: #b91c1c;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --ok: #16a34a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      color: var(--text);
      background: radial-gradient(1200px 600px at 10% -10%, #312e81 0%, transparent 50%),
                  radial-gradient(1000px 500px at 110% 10%, #0ea5e9 0%, transparent 45%),
                  var(--bg);
      padding: 40px 20px;
    }
    .wrap { max-width: 1080px; margin: 0 auto; }
    .brand { display: flex; align-items: center; gap: 12px; color: #e2e8f0; margin-bottom: 24px; }
    .brand .logo {
      width: 40px; height: 40px; border-radius: 12px;
      background: linear-gradient(135deg, #6366f1, #22d3ee);
      display: grid; place-items: center; font-weight: 700; color: #fff;
      box-shadow: 0 8px 24px rgba(79,70,229,.45);
    }
    .brand h1 { font-size: 20px; margin: 0; letter-spacing: .2px; }
    .brand p { margin: 2px 0 0; font-size: 12px; color: #94a3b8; }
    .card {
      background: var(--card);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 20px 50px rgba(2,6,23,.35);
      border: 1px solid rgba(255,255,255,.6);
    }
    .login-card { max-width: 420px; margin: 0 auto; }
    h2 { margin: 0 0 4px; font-size: 22px; }
    .sub { color: var(--muted); font-size: 13px; margin: 0 0 22px; }
    .field { margin-bottom: 16px; }
    label { display: block; font-size: 12px; font-weight: 600; color: var(--muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: .4px; }
    input[type=text], input[type=password], input.inp {
      width: 100%; padding: 11px 13px; border: 1px solid var(--border);
      border-radius: 10px; font-size: 14px; outline: none; transition: border .15s, box-shadow .15s;
      background: #f8fafc;
    }
    input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(79,70,229,.15); background: #fff; }
    .btn {
      border: none; border-radius: 10px; padding: 11px 18px; font-size: 14px; font-weight: 600;
      cursor: pointer; transition: transform .05s, background .15s; color: #fff; background: var(--primary);
    }
    .btn:hover { background: var(--primary-hover); }
    .btn:active { transform: translateY(1px); }
    .btn-block { width: 100%; }
    .btn-ghost { background: #eef2ff; color: var(--primary); }
    .btn-ghost:hover { background: #e0e7ff; }
    .btn-danger { background: var(--danger); padding: 7px 12px; font-size: 13px; }
    .btn-danger:hover { background: var(--danger-hover); }
    .hint { font-size: 13px; min-height: 18px; margin-top: 12px; }
    .hint.ok { color: var(--ok); }
    .hint.err { color: var(--danger); }
    .hidden { display: none; }
    .panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; flex-wrap: wrap; gap: 12px; }
    .panel-actions { display: flex; align-items: center; gap: 12px; }
    .who { font-size: 13px; color: var(--muted); }
    .grid {
      display: grid; grid-template-columns: 1fr 1fr 1fr auto auto; gap: 12px; align-items: end;
      background: #f8fafc; border: 1px solid var(--border); border-radius: 14px; padding: 18px; margin-bottom: 22px;
    }
    .check { display: flex; align-items: center; gap: 8px; height: 42px; }
    .check input { width: 18px; height: 18px; accent-color: var(--primary); }
    .check label { margin: 0; text-transform: none; letter-spacing: 0; font-size: 13px; color: var(--text); }
    table { border-collapse: separate; border-spacing: 0; width: 100%; font-size: 13px; }
    thead th {
      text-align: left; padding: 12px 14px; color: var(--muted); font-size: 11px; text-transform: uppercase;
      letter-spacing: .5px; border-bottom: 2px solid var(--border);
    }
    tbody td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tbody tr:hover { background: #f8fafc; }
    .mono { font-family: 'Consolas', ui-monospace, monospace; font-size: 12px; }
    .token-cell { display: flex; align-items: center; gap: 8px; }
    .token-text { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
    .pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .pill.yes { background: #dcfce7; color: #166534; }
    .pill.no { background: #fee2e2; color: #991b1b; }
    .pill.muted { background: #e2e8f0; color: #475569; }
    .copy { cursor: pointer; border: 1px solid var(--border); background: #fff; border-radius: 8px; padding: 4px 8px; font-size: 11px; color: var(--muted); }
    .copy:hover { color: var(--primary); border-color: var(--primary); }
    .empty { text-align: center; color: var(--muted); padding: 26px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='brand'>
      <div class='logo'>C</div>
      <div>
        <h1>Callsign</h1>
        <p>User Management Console</p>
      </div>
    </div>

    <div id='loginView' class='card login-card'>
      <h2>Sign in</h2>
      <p class='sub'>Enter your administrator credentials to continue.</p>
      <div class='field'>
        <label for='u'>Username</label>
        <input id='u' type='text' autocomplete='off' placeholder='Enter username' />
      </div>
      <div class='field'>
        <label for='p'>Password</label>
        <input id='p' type='password' autocomplete='current-password' placeholder='Enter password' />
      </div>
      <button class='btn btn-block' onclick='login()'>Login</button>
      <div id='status' class='hint'></div>
    </div>

    <div id='panelView' class='card hidden'>
      <div class='panel-head'>
        <h2>Users</h2>
        <div class='panel-actions'>
          <span id='who' class='who'></span>
          <button class='btn btn-ghost' onclick='loadUsers()'>Refresh</button>
          <button class='btn btn-ghost' onclick='logout()'>Sign out</button>
        </div>
      </div>

      <div class='grid'>
        <div>
          <label for='newU'>Username</label>
          <input id='newU' class='inp' placeholder='new user' />
        </div>
        <div>
          <label for='newT'>Token (optional)</label>
          <input id='newT' class='inp mono' placeholder='auto if blank' />
        </div>
        <div>
          <label for='newE'>Expire (YYYY-MM-DD)</label>
          <input id='newE' class='inp' placeholder='blank = none' />
        </div>
        <div class='check'>
          <input id='newP' type='checkbox' checked />
          <label for='newP'>Permanent</label>
        </div>
        <button class='btn' onclick='createUser()'>Create</button>
      </div>

      <table>
        <thead>
          <tr><th>Username</th><th>Token</th><th>Expires</th><th>Permanent</th><th>Active</th><th>Admin</th><th>Action</th></tr>
        </thead>
        <tbody id='tbody'></tbody>
      </table>
    </div>
  </div>

<script>
let adminToken = "";

function authHeaders() {
  return {"Authorization": "Bearer " + adminToken, "Content-Type": "application/json"};
}

function setStatus(msg, ok) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = 'hint ' + (ok ? 'ok' : 'err');
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function showPanel(username) {
  document.getElementById('loginView').classList.add('hidden');
  document.getElementById('panelView').classList.remove('hidden');
  document.getElementById('who').textContent = 'Signed in as ' + username;
}

function logout() {
  adminToken = "";
  document.getElementById('p').value = "";
  document.getElementById('panelView').classList.add('hidden');
  document.getElementById('loginView').classList.remove('hidden');
  setStatus('', true);
}

async function login() {
  const username = document.getElementById('u').value.trim();
  const password = document.getElementById('p').value;
  if (!username || !password) { setStatus('Username and password are required.', false); return; }
  try {
    const resp = await fetch('/api/v1/manage/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) { setStatus('Login failed. Check your credentials.', false); return; }
    adminToken = data.admin_session_token;
    showPanel(data.username || username);
    loadUsers();
  } catch (e) {
    setStatus('Network error, please retry.', false);
  }
}

function copyToken(t) {
  if (navigator.clipboard) navigator.clipboard.writeText(t);
}

async function loadUsers() {
  if (!adminToken) return;
  const resp = await fetch('/api/v1/manage/users', {headers: authHeaders()});
  const data = await resp.json();
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  if (!resp.ok || !data.ok) { if (resp.status === 401) logout(); return; }
  if (!data.users.length) {
    tbody.innerHTML = "<tr><td colspan='7' class='empty'>No users yet. Create one above.</td></tr>";
    return;
  }
  for (const u of data.users) {
    const tr = document.createElement('tr');
    const exp = u.expires_at ? new Date(u.expires_at * 1000).toISOString().slice(0, 10) : '\u2014';
    const active = u.is_active ? "<span class='pill yes'>active</span>" : "<span class='pill no'>inactive</span>";
    const admin = u.is_admin ? "<span class='pill muted'>admin</span>" : '';
    const perm = u.permanent ? "<span class='pill yes'>yes</span>" : "<span class='pill no'>no</span>";
    const del = u.is_admin ? '' : "<button class='btn btn-danger' data-del='" + esc(u.username) + "'>Delete</button>";
    tr.innerHTML =
      "<td>" + esc(u.username) + "</td>" +
      "<td><div class='token-cell'><span class='token-text mono' title='" + esc(u.token) + "'>" + esc(u.token) + "</span>" +
      "<button class='copy' data-copy='" + esc(u.token) + "'>copy</button></div></td>" +
      "<td>" + exp + "</td>" +
      "<td>" + perm + "</td>" +
      "<td>" + active + "</td>" +
      "<td>" + admin + "</td>" +
      "<td>" + del + "</td>";
    tbody.appendChild(tr);
  }
}

async function createUser() {
  if (!adminToken) return;
  const payload = {
    username: document.getElementById('newU').value.trim(),
    token: document.getElementById('newT').value.trim(),
    expires_at: document.getElementById('newE').value.trim(),
    permanent: document.getElementById('newP').checked,
  };
  if (!payload.username) { alert('Username is required.'); return; }
  const resp = await fetch('/api/v1/manage/users', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { alert(data.error || 'create failed'); return; }
  document.getElementById('newU').value = '';
  document.getElementById('newT').value = '';
  document.getElementById('newE').value = '';
  loadUsers();
}

async function delUser(name) {
  if (!adminToken) return;
  if (!confirm('Delete user ' + name + '?')) return;
  const resp = await fetch('/api/v1/manage/users/' + encodeURIComponent(name), {
    method: 'DELETE',
    headers: authHeaders(),
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { alert(data.error || 'delete failed'); return; }
  loadUsers();
}

document.getElementById('tbody').addEventListener('click', e => {
  const d = e.target.getAttribute('data-del');
  if (d) { delUser(d); return; }
  const c = e.target.getAttribute('data-copy');
  if (c) { copyToken(c); }
});

document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !document.getElementById('loginView').classList.contains('hidden')) login();
});
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
