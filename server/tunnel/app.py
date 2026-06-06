import asyncio
import contextlib
import hmac
import ipaddress
import json
import os
import subprocess
import struct
from http import HTTPStatus
from typing import Dict, Optional, Tuple

import requests
import websockets
from websockets.exceptions import ConnectionClosed

try:
    import fcntl  # Linux-only; required only for tun mode.
except ImportError:
    fcntl = None


def _env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


CONTROL_VALIDATE_URL = os.getenv("CONTROL_VALIDATE_URL", "http://127.0.0.1:5000/api/v1/validate")
TUNNEL_HOST = os.getenv("TUNNEL_HOST", "0.0.0.0")
TUNNEL_PORT = int(os.getenv("TUNNEL_PORT", "8443"))
SEED_ACCESS_TOKEN = _env("CALLSIGN_ACCESS_TOKEN")
CALLSIGN_TUNNEL_PATH = _env("CALLSIGN_TUNNEL_PATH", default="/tunnel") or "/tunnel"
CALLSIGN_TUN_MODE = _env("CALLSIGN_TUN_MODE", default="echo").lower()
TUN_INTERFACE = _env("CALLSIGN_TUN_INTERFACE", default="tun0")
TUN_LOCAL_CIDR = _env("CALLSIGN_TUN_LOCAL_CIDR", default="10.99.0.1/24")
REVALIDATE_INTERVAL_SECONDS = int(_env("CALLSIGN_REVALIDATE_INTERVAL_SECONDS", default="30"))

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class LinuxTunDevice:
    def __init__(self, if_name: str):
        self.if_name = if_name
        self.fd: Optional[int] = None

    def open(self):
        if self.fd is not None:
            return

        if os.name != "posix" or fcntl is None:
            raise RuntimeError("tun mode requires Linux with fcntl support")

        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr = struct.pack("16sH", self.if_name.encode("utf-8"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)

    def close(self):
        if self.fd is None:
            return
        os.close(self.fd)
        self.fd = None

    async def read_packet(self) -> bytes:
        if self.fd is None:
            raise RuntimeError("tun device is not open")
        return await asyncio.to_thread(os.read, self.fd, 65535)

    async def write_packet(self, data: bytes):
        if self.fd is None:
            raise RuntimeError("tun device is not open")
        await asyncio.to_thread(os.write, self.fd, data)


def extract_ipv4_dst(packet: bytes) -> Optional[str]:
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    if version != 4:
        return None
    return str(ipaddress.IPv4Address(packet[16:20]))


def extract_ipv4_src(packet: bytes) -> Optional[str]:
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    if version != 4:
        return None
    return str(ipaddress.IPv4Address(packet[12:16]))


class TunnelHub:
    def __init__(self):
        self.mode = CALLSIGN_TUN_MODE
        self.tun: Optional[LinuxTunDevice] = None
        self.client_by_ip: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.client_auth_by_ip: Dict[str, Tuple[str, str]] = {}
        self.lock = asyncio.Lock()
        self.tun_reader_task = None
        self.revalidate_task = None

    async def initialize(self):
        if self.mode != "tun":
            print("[tunnel] running in echo mode")
            return

        try:
            self.tun = LinuxTunDevice(TUN_INTERFACE)
            self.tun.open()
            self._configure_tun_interface()
            print(f"[tunnel] running in tun mode on {TUN_INTERFACE}; ensure routes/NAT configured externally")
            self.tun_reader_task = asyncio.create_task(self._tun_to_clients_loop())
            self.revalidate_task = asyncio.create_task(self._revalidate_clients_loop())
        except Exception as exc:
            print(f"[tunnel] tun mode unavailable ({exc}); falling back to echo mode")
            self.mode = "echo"
            self.tun = None
            self.revalidate_task = asyncio.create_task(self._revalidate_clients_loop())

    def _configure_tun_interface(self):
        # Ensure tun interface is up and has the expected gateway address.
        interface = ipaddress.IPv4Interface(TUN_LOCAL_CIDR)
        subprocess.run(["ip", "addr", "replace", str(interface), "dev", TUN_INTERFACE], check=True)
        subprocess.run(["ip", "link", "set", "dev", TUN_INTERFACE, "up"], check=True)

    async def shutdown(self):
        if self.tun_reader_task is not None:
            self.tun_reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.tun_reader_task
        if self.revalidate_task is not None:
            self.revalidate_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.revalidate_task
        if self.tun is not None:
            self.tun.close()

    async def register(self, assigned_ip: str, websocket, session_token: str, access_token: str):
        async with self.lock:
            self.client_by_ip[assigned_ip] = websocket
            self.client_auth_by_ip[assigned_ip] = (session_token, access_token)

    async def unregister(self, assigned_ip: str):
        async with self.lock:
            self.client_by_ip.pop(assigned_ip, None)
            self.client_auth_by_ip.pop(assigned_ip, None)

    async def on_client_frame(self, assigned_ip: str, websocket, msg: bytes):
        if self.mode == "echo":
            await websocket.send(msg)
            return
        if self.tun is None:
            return
        # Anti-spoofing: only forward packets whose source address matches the
        # IP this client was leased. Drops forged source IPs (and non-IPv4),
        # preventing a client from impersonating another tenant on the overlay.
        if extract_ipv4_src(msg) != assigned_ip:
            return
        await self.tun.write_packet(msg)

    async def _tun_to_clients_loop(self):
        while True:
            if self.tun is None:
                return
            packet = await self.tun.read_packet()
            dst_ip = extract_ipv4_dst(packet)
            if not dst_ip:
                continue
            async with self.lock:
                ws = self.client_by_ip.get(dst_ip)
            if ws is None:
                continue
            try:
                await ws.send(packet)
            except Exception:
                continue

    async def _revalidate_clients_loop(self):
        while True:
            await asyncio.sleep(REVALIDATE_INTERVAL_SECONDS)
            async with self.lock:
                snapshot = [
                    (ip, ws, self.client_auth_by_ip.get(ip))
                    for ip, ws in self.client_by_ip.items()
                ]

            for assigned_ip, ws, auth_info in snapshot:
                if auth_info is None:
                    continue
                session_token, access_token = auth_info
                is_valid = await asyncio.to_thread(_validate_token_sync, session_token, access_token)
                if is_valid:
                    continue
                with contextlib.suppress(Exception):
                    await ws.close(code=1008, reason="session expired")
                await self.unregister(assigned_ip)


HUB = TunnelHub()


def _validate_token_sync(token: str, access_token: str) -> Optional[Tuple[str, str]]:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Access-Token": access_token,
    }
    try:
        resp = requests.post(CONTROL_VALIDATE_URL, headers=headers, timeout=5)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None
    device_id = data.get("device_id")
    assigned_ip = data.get("assigned_ip")
    if not device_id or not assigned_ip:
        return None
    return str(device_id), str(assigned_ip)

async def process_request(path, request_headers):
    access_token = request_headers.get("X-Access-Token", "").strip()
    if not access_token:
        return (HTTPStatus.UNAUTHORIZED, [("Content-Type", "text/plain"), ("Content-Length", "0")], b"")

    if path == "/healthz":
        # Health endpoint requires the configured seed access token (operators /
        # monitoring know it); a non-empty but wrong token must not pass.
        if SEED_ACCESS_TOKEN and not hmac.compare_digest(access_token, SEED_ACCESS_TOKEN):
            return (HTTPStatus.UNAUTHORIZED, [("Content-Type", "text/plain"), ("Content-Length", "0")], b"")
        body = b'{"ok": true, "service": "tunnel"}'
        return (
            HTTPStatus.OK,
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
            body,
        )

    if path != CALLSIGN_TUNNEL_PATH:
        return (HTTPStatus.NOT_FOUND, [("Content-Type", "text/plain"), ("Content-Length", "0")], b"")

    auth = request_headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return (HTTPStatus.UNAUTHORIZED, [("Content-Type", "text/plain"), ("Content-Length", "0")], b"")

    token = auth.split(" ", 1)[1].strip()
    auth_info = await asyncio.to_thread(_validate_token_sync, token, access_token)
    if not auth_info:
        return (HTTPStatus.UNAUTHORIZED, [("Content-Type", "text/plain"), ("Content-Length", "0")], b"")
    return None


async def tunnel_ws(websocket, path):
    access_token = websocket.request_headers.get("X-Access-Token", "").strip()
    if not access_token:
        await websocket.close(code=1008, reason="unauthorized")
        return

    if path != CALLSIGN_TUNNEL_PATH:
        await websocket.close(code=1008, reason="invalid path")
        return

    auth = websocket.request_headers.get("Authorization", "")
    token = auth.split(" ", 1)[1].strip() if auth.startswith("Bearer ") else ""
    auth_info = await asyncio.to_thread(_validate_token_sync, token, access_token)
    if not auth_info:
        await websocket.close(code=1008, reason="unauthorized")
        return
    device_id, assigned_ip = auth_info

    await HUB.register(assigned_ip, websocket, token, access_token)

    frame_count = 0
    try:
        async for msg in websocket:
            if isinstance(msg, bytes):
                frame_count += 1
                await HUB.on_client_frame(assigned_ip, websocket, msg)
            else:
                payload = msg.strip().lower()
                if payload == "ping":
                    await websocket.send("pong")
                elif payload == "stats":
                    await websocket.send(
                        json.dumps({"device_id": device_id, "assigned_ip": assigned_ip, "frames": frame_count})
                    )
                else:
                    await websocket.send("unknown")
    except ConnectionClosed:
        pass
    finally:
        await HUB.unregister(assigned_ip)


async def main():
    await HUB.initialize()
    try:
        async with websockets.serve(
            tunnel_ws,
            TUNNEL_HOST,
            TUNNEL_PORT,
            process_request=process_request,
            ping_interval=30,
            ping_timeout=30,
            max_size=2 * 1024 * 1024,
        ):
            print(f"tunnel server listening on {TUNNEL_HOST}:{TUNNEL_PORT}")
            await asyncio.Future()
    finally:
        await HUB.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
