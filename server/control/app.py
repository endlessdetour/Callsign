import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Dict

from flask import Flask, jsonify, request


app = Flask(__name__)

def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


def _load_access_token() -> str:
    token = _env("CALLSIGN_ACCESS_TOKEN")
    if token:
        return token

    token_file = _env("CALLSIGN_ACCESS_TOKEN_FILE", default="/etc/callsign/access_token")
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


ACCESS_TOKEN = _load_access_token()
SESSION_TTL_SECONDS = int(_env("CALLSIGN_SESSION_TTL", default="3600"))
TUNNEL_PUBLIC_URL = _env("CALLSIGN_TUNNEL_PUBLIC_URL")
TUNNEL_PATH = _env("CALLSIGN_TUNNEL_PATH", default="/tunnel") or "/tunnel"

if not ACCESS_TOKEN:
    raise RuntimeError("CALLSIGN_ACCESS_TOKEN is required")


@dataclass
class Session:
    device_id: str
    assigned_ip: str
    created_at: int
    expires_at: int


SESSIONS: Dict[str, Session] = {}


def _sign(value: str) -> str:
    # Session tokens are signed with the single configured access token.
    return hmac.new(ACCESS_TOKEN.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _assigned_ip_for_device(device_id: str) -> str:
    # Keep this stable across restarts/processes.
    digest = hashlib.sha256(device_id.encode("utf-8")).digest()
    suffix = digest[0] % 250 + 2
    return f"10.99.0.{suffix}"


def _deny_444():
    return "", 444


@app.before_request
def _require_access_token():
    token = request.headers.get("X-Access-Token", "")
    if not hmac.compare_digest(token, ACCESS_TOKEN):
        return _deny_444()


@app.errorhandler(404)
def _not_found(_err):
    return _deny_444()


def issue_session_token(device_id: str, assigned_ip: str) -> str:
    now = int(time.time())
    expires_at = now + SESSION_TTL_SECONDS
    payload = f"{device_id}:{now}:{expires_at}"
    sig = _sign(payload)
    token = f"{payload}:{sig}"
    SESSIONS[token] = Session(device_id=device_id, assigned_ip=assigned_ip, created_at=now, expires_at=expires_at)
    return token


def validate_session_token(token: str) -> Session:
    parts = token.split(":")
    if len(parts) != 4:
        raise ValueError("malformed token")

    device_id, created_at, expires_at, signature = parts
    payload = f"{device_id}:{created_at}:{expires_at}"
    expected = _sign(payload)
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid signature")

    session = SESSIONS.get(token)
    if session is None:
        raise ValueError("unknown session")

    now = int(time.time())
    if now > session.expires_at:
        SESSIONS.pop(token, None)
        raise ValueError("expired")

    return session


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
    session_token = issue_session_token(device_id, assigned_ip)

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
    try:
        session = validate_session_token(token)
    except ValueError:
        return _deny_444()

    return jsonify({"ok": True, "device_id": session.device_id, "ts": int(time.time())})


@app.post("/api/v1/validate")
def validate():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return _deny_444()

    token = auth.split(" ", 1)[1].strip()
    try:
        session = validate_session_token(token)
    except ValueError:
        return _deny_444()

    return jsonify({"ok": True, "device_id": session.device_id, "assigned_ip": session.assigned_ip})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
