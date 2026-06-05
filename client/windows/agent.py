import argparse
import asyncio
import atexit
import os
import platform
import secrets
import socket
import subprocess
import sys
import time
import ctypes
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Optional
from ipaddress import ip_address

import requests
import websockets
from websockets.exceptions import ConnectionClosed

try:
    from client.windows.route_manager import WindowsRouteManager
    from client.windows.wintun_adapter import WintunAdapter
except ModuleNotFoundError:
    # Script mode: agent.py launched directly from client/windows.
    from route_manager import WindowsRouteManager
    from wintun_adapter import WintunAdapter


_LOG_FILE_HANDLE = None


def _configure_log_file(path: str) -> None:
    global _LOG_FILE_HANDLE
    value = (path or "").strip()
    if not value:
        return

    log_path = os.path.abspath(value)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    _LOG_FILE_HANDLE = open(log_path, "a", encoding="utf-8", buffering=1)


def _close_log_file() -> None:
    global _LOG_FILE_HANDLE
    if _LOG_FILE_HANDLE is None:
        return
    try:
        _LOG_FILE_HANDLE.close()
    finally:
        _LOG_FILE_HANDLE = None


atexit.register(_close_log_file)


def log(message: str) -> None:
    print(message, flush=True)
    if _LOG_FILE_HANDLE is not None:
        _LOG_FILE_HANDLE.write(message + "\n")
        _LOG_FILE_HANDLE.flush()


@dataclass
class BootstrapConfig:
    session_token: str
    assigned_ip: str
    mtu: int
    heartbeat_interval_sec: int
    tunnel_url: Optional[str]
    routes: List[str]
    dns: List[str]


class MockTunAdapter:
    """Prototype adapter used before integrating Wintun."""

    def __init__(self, mtu: int):
        self.mtu = mtu

    async def read_packet(self) -> bytes:
        await asyncio.sleep(1)
        payload = f"pkt:{int(time.time())}".encode("utf-8")
        return payload

    async def write_packet(self, data: bytes) -> None:
        # In real TUN mode this writes to virtual NIC RX queue.
        log(f"[adapter] recv {len(data)} bytes")


class ControlClient:
    def __init__(self, control_url: str, access_token: str, device_id: str):
        self.control_url = control_url.rstrip("/")
        self.access_token = access_token
        self.device_id = device_id

    def bootstrap(self) -> BootstrapConfig:
        url = f"{self.control_url}/api/v1/bootstrap"
        try:
            resp = requests.post(
                url,
                json={"device_id": self.device_id},
                headers={
                    "X-Access-Token": self.access_token,
                },
                timeout=8,
            )
        except requests.Timeout as exc:
            raise RuntimeError(f"bootstrap timed out: {url}") from exc
        except requests.ConnectionError as exc:
            raise RuntimeError(f"bootstrap connection failed: {url}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"bootstrap request failed: {exc}") from exc

        if resp.status_code != 200:
            message = resp.text.strip()
            try:
                payload = resp.json()
                message = payload.get("error") or message
            except ValueError:
                pass
            if resp.status_code == 401:
                raise RuntimeError(f"bootstrap unauthorized (401): {message}. Check access token.")
            raise RuntimeError(f"bootstrap failed ({resp.status_code}): {message}")

        data = resp.json()
        return BootstrapConfig(
            session_token=data["session_token"],
            assigned_ip=data["assigned_ip"],
            mtu=int(data["mtu"]),
            heartbeat_interval_sec=int(data["heartbeat_interval_sec"]),
            tunnel_url=(data.get("tunnel_url") or "").strip() or None,
            routes=[str(item) for item in data.get("routes", [])],
            dns=[str(item) for item in data.get("dns", [])],
        )

    async def heartbeat_loop(self, token: str, interval_sec: int):
        url = f"{self.control_url}/api/v1/heartbeat"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Access-Token": self.access_token,
        }
        while True:
            try:
                resp = requests.post(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    log("[control] heartbeat ok")
                else:
                    log(f"[control] heartbeat failed: {resp.status_code} {resp.text}")
            except Exception as exc:
                log(f"[control] heartbeat exception: {exc}")
            await asyncio.sleep(interval_sec)


class TunnelClient:
    def __init__(self, tunnel_url: str, session_token: str, access_token: str, adapter):
        self.tunnel_url = tunnel_url
        self.session_token = session_token
        self.access_token = access_token
        self.adapter = adapter

    async def _send_loop(self, ws):
        while True:
            pkt = await self.adapter.read_packet()
            await ws.send(pkt)

    async def _recv_loop(self, ws):
        async for message in ws:
            if isinstance(message, bytes):
                await self.adapter.write_packet(message)
            else:
                log(f"[tunnel] text: {message}")

    async def run(self):
        headers = {
            "Authorization": f"Bearer {self.session_token}",
            "X-Access-Token": self.access_token,
        }
        while True:
            try:
                async with websockets.connect(
                    self.tunnel_url,
                    extra_headers=headers,
                    ping_interval=20,
                    ping_timeout=20,
                    family=socket.AF_INET,
                ) as ws:
                    log("[tunnel] connected")
                    await ws.send("ping")
                    sender = asyncio.create_task(self._send_loop(ws))
                    receiver = asyncio.create_task(self._recv_loop(ws))
                    done, pending = await asyncio.wait(
                        [sender, receiver], return_when=asyncio.FIRST_EXCEPTION
                    )
                    for task in pending:
                        task.cancel()
                    for task in done:
                        if task.exception() is not None:
                            raise task.exception()
            except ConnectionClosed as exc:
                log(f"[tunnel] disconnected: code={exc.code} reason={exc.reason!r}, retry in 3s")
                await asyncio.sleep(3)
            except Exception as exc:
                log(f"[tunnel] disconnected: {type(exc).__name__}: {exc!r}, retry in 3s")
                await asyncio.sleep(3)


def default_device_id() -> str:
    host = socket.gethostname()
    return f"{platform.system().lower()}-{host}-{secrets.token_hex(4)}"


def _validate_url(url: str, name: str, secure_scheme: str, insecure_scheme: str, allow_insecure: bool) -> None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"invalid {name}: {url}")

    if parsed.scheme == secure_scheme:
        return

    if parsed.scheme == insecure_scheme and allow_insecure:
        return

    if parsed.scheme == insecure_scheme:
        raise RuntimeError(
            f"{name} must use {secure_scheme.upper()} by default. Received {url}. "
            f"Use --allow-insecure for local development only."
        )

    raise RuntimeError(f"unsupported {name} scheme: {parsed.scheme}")


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _resolve_ipv4_targets(control_url: str, tunnel_url: str, dns_servers: List[str]) -> List[str]:
    targets: List[str] = []

    for server in dns_servers:
        value = (server or "").strip()
        if not value:
            continue
        try:
            ip = ip_address(value)
            if ip.version == 4:
                targets.append(str(ip))
        except ValueError:
            continue

    for raw_url in [control_url, tunnel_url]:
        host = (urlparse(raw_url).hostname or "").strip()
        if not host:
            continue
        try:
            ip = ip_address(host)
            if ip.version == 4:
                targets.append(str(ip))
                continue
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr:
                    targets.append(addr)
        except OSError as exc:
            log(f"[client] warning: failed resolving {host}: {exc}")

    deduped: List[str] = []
    seen = set()
    for item in targets:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def _system_dns_servers() -> List[str]:
    if os.name != "nt":
        return []

    cmd = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 "
        "| Select-Object -ExpandProperty ServerAddresses "
        "| Where-Object { $_ -and $_ -ne '0.0.0.0' }"
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return []
    if completed.returncode != 0:
        return []

    values: List[str] = []
    seen = set()
    for line in completed.stdout.splitlines():
        item = line.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        values.append(item)
    return values



async def main():
    parser = argparse.ArgumentParser(description="Callsign Windows tunnel client")
    parser.add_argument("--control-url", required=True)
    parser.add_argument("--tunnel-url", default="")
    parser.add_argument("--device-id", default=default_device_id())
    parser.add_argument("--allow-insecure", action="store_true")
    parser.add_argument("--use-wintun", action="store_true")
    parser.add_argument("--apply-routes", action="store_true")
    parser.add_argument("--log-file", default="")
    args = parser.parse_args()

    _configure_log_file(args.log_file)

    access_token = os.getenv("CALLSIGN_ACCESS_TOKEN", "").strip()
    if not access_token:
        raise RuntimeError("CALLSIGN_ACCESS_TOKEN is required")
    _validate_url(args.control_url, "control-url", "https", "http", args.allow_insecure)

    control = ControlClient(args.control_url, access_token, args.device_id)
    bootstrap = control.bootstrap()
    tunnel_url = args.tunnel_url.strip() or (bootstrap.tunnel_url or "")
    if not tunnel_url:
        raise RuntimeError("tunnel-url is missing: set --tunnel-url or have server return tunnel_url in bootstrap")
    _validate_url(tunnel_url, "tunnel-url", "wss", "ws", args.allow_insecure)

    log(f"[control] bootstrap ok: device_id={args.device_id} assigned_ip={bootstrap.assigned_ip} mtu={bootstrap.mtu}")
    log(f"[control] tunnel endpoint: {tunnel_url}")

    route_manager = None
    if args.use_wintun:
        if not _is_admin():
            raise RuntimeError("Wintun mode requires running as Administrator")
        adapter = WintunAdapter()
        log("[client] using Wintun adapter")
        if args.apply_routes:
            route_manager = WindowsRouteManager("CallsignTunnel")
            local_dns = _system_dns_servers()
            resolver_targets = local_dns or (bootstrap.dns or ["1.1.1.1"])
            preserve_ips = _resolve_ipv4_targets(args.control_url, tunnel_url, resolver_targets)
            log(f"[client] preserving routes for: {', '.join(preserve_ips) if preserve_ips else 'none'}")
            route_manager.apply(
                assigned_ip=bootstrap.assigned_ip,
                gateway_ip="10.99.0.1",
                # Keep current resolver settings to avoid breaking networks where public DNS is blocked.
                dns_servers=[],
                preserve_ips=preserve_ips,
            )
            log("[client] default route applied through Wintun")
    else:
        adapter = MockTunAdapter(mtu=bootstrap.mtu)
        log("[client] using mock adapter")

    tunnel = TunnelClient(tunnel_url, bootstrap.session_token, access_token, adapter)

    try:
        await asyncio.gather(
            control.heartbeat_loop(bootstrap.session_token, bootstrap.heartbeat_interval_sec),
            tunnel.run(),
        )
    finally:
        if route_manager is not None:
            route_manager.rollback(gateway_ip="10.99.0.1")
            log("[client] route rollback completed")
        if hasattr(adapter, "close"):
            adapter.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("[client] stopped")
    except Exception as exc:
        log(f"[fatal] {exc}")
        sys.exit(1)
