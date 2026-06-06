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


def _read_cpu_times():
    """Return (idle, total) jiffies from /proc/stat, or None if unavailable."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for raw in f:
                if raw.startswith("cpu "):
                    parts = [int(x) for x in raw.split()[1:]]
                    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
                    return idle, sum(parts)
    except (OSError, ValueError):
        return None
    return None


def _cpu_percent():
    first = _read_cpu_times()
    if first is None:
        return None
    time.sleep(0.12)
    second = _read_cpu_times()
    if second is None:
        return None
    idle_delta = second[0] - first[0]
    total_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return round((1.0 - idle_delta / total_delta) * 100.0, 1)


def _meminfo():
    info = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for raw in f:
                key, _, rest = raw.partition(":")
                info[key.strip()] = int(rest.strip().split()[0]) * 1024  # kB -> bytes
    except (OSError, ValueError, IndexError):
        return None
    total = info.get("MemTotal")
    available = info.get("MemAvailable")
    if total is None or available is None or total <= 0:
        return None
    used = total - available
    mem = {
        "total": total,
        "available": available,
        "used": used,
        "percent": round(used / total * 100.0, 1),
    }
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    if swap_total > 0:
        swap_used = swap_total - swap_free
        mem["swap_total"] = swap_total
        mem["swap_used"] = swap_used
        mem["swap_percent"] = round(swap_used / swap_total * 100.0, 1)
    return mem


def _disk_usage(path: str = "/"):
    try:
        st = os.statvfs(path)
    except (OSError, AttributeError):
        return None
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    if total <= 0:
        return None
    used = total - (st.f_bfree * st.f_frsize)
    return {
        "total": total,
        "used": used,
        "free": free,
        "percent": round(used / total * 100.0, 1),
    }


def _uptime_seconds():
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def _collect_system_metrics() -> dict:
    cpu_count = os.cpu_count() or 1
    load = None
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except (OSError, AttributeError):
        load = None

    metrics = {
        "now": int(time.time()),
        "cpu_count": cpu_count,
        "cpu_percent": _cpu_percent(),
        "load": load,
        "memory": _meminfo(),
        "disk": _disk_usage("/"),
        "uptime_seconds": _uptime_seconds(),
    }
    if load is not None and cpu_count:
        metrics["load_per_core"] = round(load[0] / cpu_count, 2)
    return metrics


def _is_client_api(path: str) -> bool:
    return path.startswith("/api/v1/") and not path.startswith("/api/v1/manage/")


def _session_user_from_request():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    session_token = auth.split(" ", 1)[1].strip()
    return AUTH_STORE.validate_session(session_token)


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

    user = AUTH_STORE.verify_credentials(username, password)
    if user is None:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401

    session_token = AUTH_STORE.create_admin_session(user.id, ttl_seconds=ADMIN_SESSION_TTL_SECONDS)
    return jsonify({
        "ok": True,
        "admin_session_token": session_token,
        "username": user.username,
        "is_admin": user.is_admin,
        "must_change": user.must_change,
    })


def _require_admin():
    """Return (user, None) for an authenticated admin, or (None, response) otherwise."""
    user = _session_user_from_request()
    if user is None:
        return None, (jsonify({"ok": False, "error": "unauthorized"}), 401)
    if user.must_change:
        return None, (jsonify({"ok": False, "error": "setup required", "must_change": True}), 403)
    if not user.is_admin:
        return None, (jsonify({"ok": False, "error": "forbidden"}), 403)
    return user, None


@app.get("/api/v1/manage/me")
def manage_me():
    user = _session_user_from_request()
    if user is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    info = AUTH_STORE.get_user_by_id(user.id)
    if info is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    info["must_change"] = user.must_change
    return jsonify({"ok": True, "user": info})


@app.post("/api/v1/manage/password")
def manage_change_password():
    user = _session_user_from_request()
    if user is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    new_password = str(payload.get("new_password", ""))
    try:
        AUTH_STORE.change_password(user.id, new_password)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"change failed: {exc}"}), 400

    return jsonify({"ok": True})


@app.post("/api/v1/manage/setup")
def admin_setup():
    user = _session_user_from_request()
    if user is None:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if not user.is_admin:
        return jsonify({"ok": False, "error": "forbidden"}), 403
    if not user.must_change:
        return jsonify({"ok": False, "error": "setup already completed"}), 400

    payload = request.get_json(silent=True) or {}
    new_username = str(payload.get("new_username", "")).strip()
    new_password = str(payload.get("new_password", ""))

    try:
        result = AUTH_STORE.complete_admin_setup(user.id, new_username, new_password)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"setup failed: {exc}"}), 400

    return jsonify({"ok": True, "username": result["username"]})


@app.get("/api/v1/manage/users")
def admin_list_users():
    _user, err = _require_admin()
    if err is not None:
        return err
    return jsonify({"ok": True, "users": AUTH_STORE.list_users()})


@app.get("/api/v1/manage/system")
def admin_system_status():
    _user, err = _require_admin()
    if err is not None:
        return err
    try:
        metrics = _collect_system_metrics()
    except Exception as exc:
        return jsonify({"ok": False, "error": f"metrics unavailable: {exc}"}), 500
    return jsonify({"ok": True, "system": metrics})


@app.post("/api/v1/manage/users")
def admin_create_user():
    _user, err = _require_admin()
    if err is not None:
        return err

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    token = str(payload.get("token", "")).strip()
    password = str(payload.get("password", "")).strip()
    permanent = bool(payload.get("permanent", False))
    expires_raw = str(payload.get("expires_at", "")).strip()

    try:
        expires_at = _parse_expiry_to_epoch(expires_raw, permanent=permanent)
        created = AUTH_STORE.create_user(username=username, expires_at=expires_at, token=token, password=password)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"create failed: {exc}"}), 400

    return jsonify({"ok": True, "user": created})


@app.patch("/api/v1/manage/users/<username>")
def admin_update_user(username: str):
    _user, err = _require_admin()
    if err is not None:
        return err

    payload = request.get_json(silent=True) or {}
    kwargs = {}

    if "token" in payload:
        token = payload.get("token")
        kwargs["token"] = None if token is None else str(token).strip()

    if "is_active" in payload:
        is_active = payload.get("is_active")
        kwargs["is_active"] = None if is_active is None else bool(is_active)

    if "expires_at" in payload or "permanent" in payload:
        permanent = bool(payload.get("permanent", False))
        expires_raw = str(payload.get("expires_at", "")).strip()
        try:
            kwargs["expires_at"] = _parse_expiry_to_epoch(expires_raw, permanent=permanent)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

    try:
        AUTH_STORE.update_user(username=username, **kwargs)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"update failed: {exc}"}), 400

    return jsonify({"ok": True})


@app.post("/api/v1/manage/users/<username>/password")
def admin_reset_user_password(username: str):
    _user, err = _require_admin()
    if err is not None:
        return err

    payload = request.get_json(silent=True) or {}
    new_password = str(payload.get("password", "")).strip()
    try:
        result = AUTH_STORE.admin_reset_password(username, new_password)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"reset failed: {exc}"}), 400

    return jsonify({"ok": True, "user": result})


@app.delete("/api/v1/manage/users/<username>")
def admin_delete_user(username: str):
    _user, err = _require_admin()
    if err is not None:
        return err

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
    .btn-sm { padding: 6px 10px; font-size: 12px; }
    .actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .hint { font-size: 13px; min-height: 18px; margin-top: 12px; }
    .hint.ok { color: var(--ok); }
    .hint.err { color: var(--danger); }
    .hidden { display: none; }
    .panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; flex-wrap: wrap; gap: 12px; }
    .panel-actions { display: flex; align-items: center; gap: 12px; }
    .who { font-size: 13px; color: var(--muted); }
    .grid {
      display: grid; grid-template-columns: 1fr 1fr 1fr 1fr auto auto; gap: 12px; align-items: end;
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
    .sysbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
    .stat { display: flex; align-items: center; gap: 8px; background: #f8fafc; border: 1px solid var(--border); border-radius: 12px; padding: 10px 14px; font-size: 13px; }
    .stat b { font-size: 15px; }
    .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
    .dot.up { background: var(--ok); box-shadow: 0 0 0 3px rgba(22,163,74,.18); }
    .dot.down { background: var(--danger); box-shadow: 0 0 0 3px rgba(220,38,38,.18); }
    .sys-head { display: flex; align-items: center; justify-content: space-between; margin: 4px 0 12px; }
    .sys-head h3 { margin: 0; font-size: 16px; }
    .sys-meta { font-size: 12px; color: var(--muted); }
    .sys-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .metric { background: #f8fafc; border: 1px solid var(--border); border-radius: 14px; padding: 14px 16px; }
    .metric-top { display: flex; align-items: baseline; justify-content: space-between; }
    .metric-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); font-weight: 600; }
    .metric-val { font-size: 22px; font-weight: 700; }
    .metric-val small { font-size: 12px; font-weight: 500; color: var(--muted); }
    .metric-sub { font-size: 12px; color: var(--muted); margin-top: 6px; }
    .bar { height: 8px; border-radius: 999px; background: #e2e8f0; overflow: hidden; margin-top: 10px; }
    .bar > span { display: block; height: 100%; border-radius: 999px; transition: width .4s ease; }
    .bar > span.ok { background: linear-gradient(90deg,#22c55e,#16a34a); }
    .bar > span.warn { background: linear-gradient(90deg,#f59e0b,#d97706); }
    .bar > span.crit { background: linear-gradient(90deg,#ef4444,#dc2626); }
    .self-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 26px; }
    .self-item { display: flex; flex-direction: column; gap: 6px; background: #f8fafc; border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
    .self-item.self-token { grid-column: 1 / -1; }
    .self-label { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); font-weight: 600; }
    .self-value { font-size: 15px; }
    .self-h3 { margin: 0 0 14px; font-size: 16px; }
    .self-pw { max-width: 420px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } .self-grid { grid-template-columns: 1fr; } }
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

    <div id='setupView' class='card login-card hidden'>
      <h2>Secure your account</h2>
      <p class='sub'>First login detected. Set a new administrator username and password. The default <strong>admin</strong> account will be disabled.</p>
      <div class='field'>
        <label for='setU'>New username</label>
        <input id='setU' type='text' autocomplete='off' placeholder='Choose a username' />
      </div>
      <div class='field'>
        <label for='setP'>New password</label>
        <input id='setP' type='password' autocomplete='new-password' placeholder='At least 8 characters' />
      </div>
      <div class='field'>
        <label for='setP2'>Confirm password</label>
        <input id='setP2' type='password' autocomplete='new-password' placeholder='Re-enter password' />
      </div>
      <button class='btn btn-block' onclick='completeSetup()'>Save and continue</button>
      <div id='setupStatus' class='hint'></div>
    </div>

    <div id='pwChangeView' class='card login-card hidden'>
      <h2>Change your password</h2>
      <p class='sub'>For security, please set a new password before continuing.</p>
      <div class='field'>
        <label for='pwNew'>New password</label>
        <input id='pwNew' type='password' autocomplete='new-password' placeholder='At least 8 characters' />
      </div>
      <div class='field'>
        <label for='pwNew2'>Confirm password</label>
        <input id='pwNew2' type='password' autocomplete='new-password' placeholder='Re-enter password' />
      </div>
      <button class='btn btn-block' onclick='changeOwnPassword(true)'>Save and continue</button>
      <div id='pwChangeStatus' class='hint'></div>
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

      <div id='sysStatus' class='sysbar'></div>

      <div class='sys-head'>
        <h3>System health</h3>
        <span id='sysMeta' class='sys-meta'></span>
      </div>
      <div id='sysMetrics' class='sys-grid'></div>

      <div class='grid'>
        <div>
          <label for='newU'>Username</label>
          <input id='newU' class='inp' placeholder='new user' />
        </div>
        <div>
          <label for='newPw'>Password</label>
          <input id='newPw' class='inp' placeholder='auto if blank' />
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

    <div id='selfView' class='card hidden'>
      <div class='panel-head'>
        <h2>My account</h2>
        <div class='panel-actions'>
          <span id='selfWho' class='who'></span>
          <button class='btn btn-ghost' onclick='logout()'>Sign out</button>
        </div>
      </div>

      <div class='self-grid'>
        <div class='self-item'><span class='self-label'>Username</span><span id='selfUsername' class='self-value'></span></div>
        <div class='self-item'><span class='self-label'>Status</span><span id='selfStatus' class='self-value'></span></div>
        <div class='self-item'><span class='self-label'>Expires</span><span id='selfExpires' class='self-value'></span></div>
        <div class='self-item self-token'>
          <span class='self-label'>Access token</span>
          <div class='token-cell'>
            <span id='selfToken' class='token-text mono'></span>
            <button class='copy' id='selfCopy'>copy</button>
          </div>
        </div>
      </div>

      <h3 class='self-h3'>Change password</h3>
      <div class='self-pw'>
        <div class='field'>
          <label for='selfPwNew'>New password</label>
          <input id='selfPwNew' type='password' autocomplete='new-password' placeholder='At least 8 characters' />
        </div>
        <div class='field'>
          <label for='selfPwNew2'>Confirm password</label>
          <input id='selfPwNew2' type='password' autocomplete='new-password' placeholder='Re-enter password' />
        </div>
        <button class='btn' onclick='changeOwnPassword(false)'>Update password</button>
        <div id='selfPwStatus' class='hint'></div>
      </div>
    </div>
  </div>

<script>
let adminToken = "";
let currentUser = {username: "", is_admin: false, must_change: false};

function authHeaders() {
  return {"Authorization": "Bearer " + adminToken, "Content-Type": "application/json"};
}

function setStatus(msg, ok) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = 'hint ' + (ok ? 'ok' : 'err');
}

function setHint(id, msg, ok) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'hint ' + (ok ? 'ok' : 'err');
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function fmtDate(epoch) {
  return epoch ? new Date(epoch * 1000).toISOString().slice(0, 10) : '\u2014';
}

const ALL_VIEWS = ['loginView', 'setupView', 'pwChangeView', 'panelView', 'selfView'];
function showView(id) {
  for (const v of ALL_VIEWS) {
    document.getElementById(v).classList.toggle('hidden', v !== id);
  }
}

function logout() {
  adminToken = "";
  currentUser = {username: "", is_admin: false, must_change: false};
  document.getElementById('p').value = "";
  stopSystemPolling();
  showView('loginView');
  setStatus('', true);
}

function copyToken(t) {
  if (navigator.clipboard) navigator.clipboard.writeText(t);
}

function routeAfterAuth() {
  if (currentUser.must_change) {
    showView(currentUser.is_admin ? 'setupView' : 'pwChangeView');
    return;
  }
  if (currentUser.is_admin) {
    document.getElementById('who').textContent = 'Signed in as ' + currentUser.username + ' (admin)';
    showView('panelView');
    loadUsers();
    startSystemPolling();
  } else {
    showView('selfView');
    loadMe();
  }
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
    currentUser = {username: data.username || username, is_admin: !!data.is_admin, must_change: !!data.must_change};
    setStatus('', true);
    routeAfterAuth();
  } catch (e) {
    setStatus('Network error, please retry.', false);
  }
}

async function completeSetup() {
  const nu = document.getElementById('setU').value.trim();
  const np = document.getElementById('setP').value;
  const np2 = document.getElementById('setP2').value;
  if (!nu) { setHint('setupStatus', 'New username is required.', false); return; }
  if (np.length < 8) { setHint('setupStatus', 'Password must be at least 8 characters.', false); return; }
  if (np !== np2) { setHint('setupStatus', 'Passwords do not match.', false); return; }
  const resp = await fetch('/api/v1/manage/setup', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({new_username: nu, new_password: np})
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { setHint('setupStatus', data.error || 'setup failed', false); return; }
  adminToken = "";
  showView('loginView');
  document.getElementById('u').value = nu;
  document.getElementById('p').value = "";
  setStatus('Account secured. Please sign in with your new credentials.', true);
}

async function changeOwnPassword(forced) {
  const ids = forced
    ? {n: 'pwNew', c: 'pwNew2', s: 'pwChangeStatus'}
    : {n: 'selfPwNew', c: 'selfPwNew2', s: 'selfPwStatus'};
  const np = document.getElementById(ids.n).value;
  const np2 = document.getElementById(ids.c).value;
  if (np.length < 8) { setHint(ids.s, 'Password must be at least 8 characters.', false); return; }
  if (np !== np2) { setHint(ids.s, 'Passwords do not match.', false); return; }
  const resp = await fetch('/api/v1/manage/password', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({new_password: np})
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { setHint(ids.s, data.error || 'change failed', false); return; }
  document.getElementById(ids.n).value = "";
  document.getElementById(ids.c).value = "";
  currentUser.must_change = false;
  if (forced) {
    setHint(ids.s, 'Password updated.', true);
    routeAfterAuth();
  } else {
    setHint(ids.s, 'Password updated successfully.', true);
  }
}

async function loadMe() {
  if (!adminToken) return;
  const resp = await fetch('/api/v1/manage/me', {headers: authHeaders()});
  const data = await resp.json();
  if (!resp.ok || !data.ok) { if (resp.status === 401) logout(); return; }
  const u = data.user;
  currentUser.username = u.username;
  document.getElementById('selfWho').textContent = 'Signed in as ' + u.username;
  document.getElementById('selfUsername').textContent = u.username;
  document.getElementById('selfStatus').innerHTML = u.is_active
    ? "<span class='pill yes'>active</span>" : "<span class='pill no'>inactive</span>";
  document.getElementById('selfExpires').textContent = u.permanent ? 'Permanent' : fmtDate(u.expires_at);
  document.getElementById('selfToken').textContent = u.token;
  document.getElementById('selfToken').setAttribute('title', u.token);
  document.getElementById('selfCopy').onclick = () => copyToken(u.token);
}

function renderStatus(users) {
  const total = users.length;
  const active = users.filter(u => u.is_active).length;
  const admins = users.filter(u => u.is_admin).length;
  document.getElementById('sysStatus').innerHTML =
    "<div class='stat'><span class='dot up'></span> Service online</div>" +
    "<div class='stat'>Total users <b>" + total + "</b></div>" +
    "<div class='stat'>Active <b>" + active + "</b></div>" +
    "<div class='stat'>Admins <b>" + admins + "</b></div>";
}

function fmtBytes(n) {
  if (n === null || n === undefined) return '\u2014';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
}

function fmtUptime(s) {
  if (s === null || s === undefined) return '\u2014';
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

function barClass(pct) {
  if (pct === null || pct === undefined) return 'ok';
  if (pct >= 90) return 'crit';
  if (pct >= 75) return 'warn';
  return 'ok';
}

function metricCard(label, valueHtml, pct, subHtml) {
  let bar = '';
  if (pct !== null && pct !== undefined) {
    const w = Math.max(0, Math.min(100, pct));
    bar = "<div class='bar'><span class='" + barClass(pct) + "' style='width:" + w + "%'></span></div>";
  }
  return "<div class='metric'>" +
    "<div class='metric-top'><span class='metric-label'>" + label + "</span></div>" +
    "<div class='metric-val'>" + valueHtml + "</div>" +
    bar +
    (subHtml ? "<div class='metric-sub'>" + subHtml + "</div>" : '') +
    "</div>";
}

function renderSystem(sys) {
  const cards = [];

  const cpu = sys.cpu_percent;
  const cpuVal = (cpu === null || cpu === undefined) ? '\u2014' : cpu + "<small>%</small>";
  cards.push(metricCard('CPU', cpuVal, cpu, sys.cpu_count + ' vCPU'));

  if (sys.memory) {
    const m = sys.memory;
    let memSub = fmtBytes(m.used) + ' / ' + fmtBytes(m.total);
    if (m.swap_total) { memSub += ' &middot; swap ' + m.swap_percent + '%'; }
    cards.push(metricCard('Memory', m.percent + "<small>%</small>", m.percent, memSub));
  } else {
    cards.push(metricCard('Memory', '\u2014', null, 'unavailable'));
  }

  if (sys.disk) {
    const d = sys.disk;
    cards.push(metricCard('Disk (/)', d.percent + "<small>%</small>", d.percent,
      fmtBytes(d.used) + ' used &middot; ' + fmtBytes(d.free) + ' free'));
  } else {
    cards.push(metricCard('Disk (/)', '\u2014', null, 'unavailable'));
  }

  if (sys.load) {
    const loadPct = (sys.load_per_core !== null && sys.load_per_core !== undefined)
      ? Math.round(sys.load_per_core * 100) : null;
    const perCore = (sys.load_per_core !== null && sys.load_per_core !== undefined) ? sys.load_per_core : '\u2014';
    cards.push(metricCard('Load avg',
      sys.load[0] + "<small> / " + sys.load[1] + ' / ' + sys.load[2] + "</small>",
      loadPct, 'per core ' + perCore));
  }

  cards.push(metricCard('Uptime', "<span style='font-size:18px'>" + fmtUptime(sys.uptime_seconds) + "</span>", null, ''));

  document.getElementById('sysMetrics').innerHTML = cards.join('');
  const t = new Date((sys.now || Date.now() / 1000) * 1000);
  document.getElementById('sysMeta').textContent = 'Updated ' + t.toLocaleTimeString();
}

async function loadSystem() {
  if (!adminToken) return;
  try {
    const resp = await fetch('/api/v1/manage/system', {headers: authHeaders()});
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      if (resp.status === 401) { logout(); return; }
      document.getElementById('sysMeta').textContent = 'metrics unavailable';
      return;
    }
    renderSystem(data.system);
  } catch (e) {
    document.getElementById('sysMeta').textContent = 'metrics unavailable';
  }
}

let sysTimer = null;
function startSystemPolling() {
  loadSystem();
  if (sysTimer) clearInterval(sysTimer);
  sysTimer = setInterval(loadSystem, 5000);
}
function stopSystemPolling() {
  if (sysTimer) { clearInterval(sysTimer); sysTimer = null; }
}

async function loadUsers() {
  if (!adminToken) return;
  const resp = await fetch('/api/v1/manage/users', {headers: authHeaders()});
  const data = await resp.json();
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = '';
  if (!resp.ok || !data.ok) { if (resp.status === 401) logout(); return; }
  renderStatus(data.users);
  if (!data.users.length) {
    tbody.innerHTML = "<tr><td colspan='7' class='empty'>No users yet. Create one above.</td></tr>";
    return;
  }
  for (const u of data.users) {
    const tr = document.createElement('tr');
    const exp = fmtDate(u.expires_at);
    const active = u.is_active ? "<span class='pill yes'>active</span>" : "<span class='pill no'>inactive</span>";
    const admin = u.is_admin ? "<span class='pill muted'>admin</span>" : '';
    const perm = u.permanent ? "<span class='pill yes'>yes</span>" : "<span class='pill no'>no</span>";
    let actions = '';
    if (!u.is_admin) {
      const un = esc(u.username);
      const toggleLabel = u.is_active ? 'Disable' : 'Enable';
      actions =
        "<div class='actions'>" +
        "<button class='btn btn-ghost btn-sm' data-exp='" + un + "'>Set expiry</button>" +
        "<button class='btn btn-ghost btn-sm' data-reset='" + un + "'>Reset password</button>" +
        "<button class='btn btn-ghost btn-sm' data-toggle='" + un + "' data-active='" + (u.is_active ? '1' : '0') + "'>" + toggleLabel + "</button>" +
        "<button class='btn btn-danger btn-sm' data-del='" + un + "'>Delete</button>" +
        "</div>";
    }
    tr.innerHTML =
      "<td>" + esc(u.username) + "</td>" +
      "<td><div class='token-cell'><span class='token-text mono' title='" + esc(u.token) + "'>" + esc(u.token) + "</span>" +
      "<button class='copy' data-copy='" + esc(u.token) + "'>copy</button></div></td>" +
      "<td>" + exp + "</td>" +
      "<td>" + perm + "</td>" +
      "<td>" + active + "</td>" +
      "<td>" + admin + "</td>" +
      "<td>" + actions + "</td>";
    tbody.appendChild(tr);
  }
}

async function createUser() {
  if (!adminToken) return;
  const payload = {
    username: document.getElementById('newU').value.trim(),
    password: document.getElementById('newPw').value.trim(),
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
  const u = data.user || {};
  alert('User created.\\n\\nUsername: ' + u.username + '\\nPassword: ' + (u.password || '(set)') +
        '\\nToken: ' + u.token + '\\n\\nShare these now. The password is shown only once.');
  document.getElementById('newU').value = '';
  document.getElementById('newPw').value = '';
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

async function patchUser(name, payload) {
  const resp = await fetch('/api/v1/manage/users/' + encodeURIComponent(name), {
    method: 'PATCH',
    headers: authHeaders(),
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { alert(data.error || 'update failed'); return false; }
  loadUsers();
  return true;
}

async function setExpiry(name) {
  if (!adminToken) return;
  const input = prompt('Set expiry for ' + name + '\\nEnter a date (YYYY-MM-DD), or leave blank for permanent:', '');
  if (input === null) return;
  const value = input.trim();
  if (value && !/^\\d{4}-\\d{2}-\\d{2}$/.test(value)) {
    alert('Please use the format YYYY-MM-DD, or leave blank for permanent.');
    return;
  }
  await patchUser(name, value ? {permanent: false, expires_at: value} : {permanent: true, expires_at: ''});
}

async function toggleActive(name, isActive) {
  if (!adminToken) return;
  const next = !isActive;
  if (!confirm((next ? 'Enable' : 'Disable') + ' user ' + name + '?')) return;
  await patchUser(name, {is_active: next});
}

async function resetPassword(name) {
  if (!adminToken) return;
  const input = prompt('Reset password for ' + name + '\\nEnter a new password (min 8 chars), or leave blank to auto-generate:', '');
  if (input === null) return;
  const value = input.trim();
  if (value && value.length < 8) { alert('Password must be at least 8 characters.'); return; }
  const resp = await fetch('/api/v1/manage/users/' + encodeURIComponent(name) + '/password', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({password: value})
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) { alert(data.error || 'reset failed'); return; }
  const u = data.user || {};
  alert('Password reset.\\n\\nUsername: ' + u.username + '\\nNew password: ' + u.password +
        '\\n\\nShare this now. The user must change it at next login. The password is shown only once.');
}

document.getElementById('tbody').addEventListener('click', e => {
  const d = e.target.getAttribute('data-del');
  if (d) { delUser(d); return; }
  const ex = e.target.getAttribute('data-exp');
  if (ex) { setExpiry(ex); return; }
  const tg = e.target.getAttribute('data-toggle');
  if (tg) { toggleActive(tg, e.target.getAttribute('data-active') === '1'); return; }
  const rs = e.target.getAttribute('data-reset');
  if (rs) { resetPassword(rs); return; }
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
