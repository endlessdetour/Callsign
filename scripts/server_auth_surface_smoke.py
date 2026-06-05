import importlib
import os
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def run_control_checks():
    os.environ["CALLSIGN_ACCESS_TOKEN"] = "acc"
    os.environ["CALLSIGN_TUNNEL_PATH"] = "/connect-ws"

    control_app = importlib.import_module("server.control.app")
    control_app = importlib.reload(control_app)

    client = control_app.app.test_client()
    r = client.get("/healthz")
    assert_true(r.status_code == 444, "control healthz without access token should return 444")

    r = client.get("/healthz", headers={"X-Access-Token": "acc"})
    assert_true(r.status_code == 200, "control healthz should accept valid token")

    r = client.get("/non-existent", headers={"X-Access-Token": "acc"})
    assert_true(r.status_code == 444, "control unknown path should return 444")


def run_tunnel_checks():
    os.environ["CALLSIGN_ACCESS_TOKEN"] = "acc"
    os.environ["CALLSIGN_TUNNEL_PATH"] = "/connect-ws"

    if "fcntl" not in sys.modules:
        sys.modules["fcntl"] = types.SimpleNamespace(ioctl=lambda *_args, **_kwargs: None)

    tunnel_app = importlib.import_module("server.tunnel.app")
    tunnel_app = importlib.reload(tunnel_app)

    status, _headers, body = tunnel_app.asyncio.run(tunnel_app.process_request("/healthz", {}))
    assert_true(status == 401, "tunnel healthz without access token should return 401")
    assert_true(body == b"", "tunnel deny responses should have empty body")

    status, _headers, body = tunnel_app.asyncio.run(
        tunnel_app.process_request("/connect-ws", {"X-Access-Token": "acc"})
    )
    assert_true(status == 401, "tunnel path without bearer token should return 401")
    assert_true(body == b"", "unexpected path deny should have empty body")


def main():
    run_control_checks()
    run_tunnel_checks()
    print("server-auth-surface-smoke: PASS")


if __name__ == "__main__":
    main()
