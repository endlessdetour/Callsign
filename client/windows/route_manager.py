import subprocess
import json
import os
from pathlib import Path
from typing import List


def _run(cmd: List[str]) -> None:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"command timed out: {' '.join(cmd)}") from exc
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{completed.stdout}\n{completed.stderr}")


def _cleanup_persistent_default_route(gateway_ip: str) -> None:
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore "
                "-DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue "
                f"| Where-Object {{$_.NextHop -eq '{gateway_ip}'}} "
                "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


def _remove_host_routes(prefix_ip: str) -> None:
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-NetRoute -AddressFamily IPv4 "
                f"-DestinationPrefix '{prefix_ip}/32' -ErrorAction SilentlyContinue "
                "| Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


def _state_file_path() -> Path:
    local_appdata = os.getenv("LOCALAPPDATA", "").strip()
    if local_appdata:
        return Path(local_appdata) / "CallsignTunnel" / "route_state.json"
    return Path.cwd() / "route_state.json"


class WindowsRouteManager:
    def __init__(self, adapter_name: str):
        self.adapter_name = adapter_name
        self._if_index = None
        self._default_route_set = False
        self._preserve_routes: List[str] = []
        self._state_file = _state_file_path()

    def _load_state(self) -> dict:
        if not self._state_file.exists():
            return {}
        try:
            return json.loads(self._state_file.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_state(self, gateway_ip: str) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "gateway_ip": gateway_ip,
            "preserve_routes": list(self._preserve_routes),
            "adapter_name": self.adapter_name,
        }
        self._state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _clear_state(self) -> None:
        try:
            if self._state_file.exists():
                self._state_file.unlink()
        except Exception:
            pass

    def cleanup_orphaned(self) -> None:
        state = self._load_state()
        gateway_ip = str(state.get("gateway_ip", "")).strip()
        preserve_routes = state.get("preserve_routes", [])

        if gateway_ip:
            subprocess.run(
                ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", gateway_ip],
                capture_output=True,
                text=True,
                timeout=20,
            )
            _cleanup_persistent_default_route(gateway_ip)

        if isinstance(preserve_routes, list):
            for ip in preserve_routes:
                value = str(ip).strip()
                if not value:
                    continue
                _remove_host_routes(value)

        self._clear_state()

    def _get_primary_default_route(self):
        completed = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"failed to inspect routing table: {completed.stderr or completed.stdout}")

        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            if parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                # route print format: dest mask gateway iface metric
                return parts[2]

        raise RuntimeError("no default IPv4 route found")

    def _get_if_index(self) -> int:
        if self._if_index is not None:
            return self._if_index

        ps = (
            f"(Get-NetAdapter -Name '{self.adapter_name}' -ErrorAction Stop).ifIndex"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"failed to resolve adapter index: {completed.stderr or completed.stdout}")

        self._if_index = int(completed.stdout.strip())
        return self._if_index

    def apply(self, assigned_ip: str, gateway_ip: str, dns_servers: List[str], preserve_ips: List[str] | None = None) -> None:
        # Recover from previous abnormal termination before applying new routes.
        self.cleanup_orphaned()

        if_index = self._get_if_index()
        current_gateway = self._get_primary_default_route()

        # Clean stale defaults to this gateway first (active/persistent) before adding a fresh one.
        subprocess.run(
            ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", gateway_ip],
            capture_output=True,
            text=True,
            timeout=20,
        )
        _cleanup_persistent_default_route(gateway_ip)

        unique_preserve: List[str] = []
        seen = set()
        for ip in preserve_ips or []:
            value = (ip or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            unique_preserve.append(value)

        self._preserve_routes = []
        for ip in unique_preserve:
            if ip == gateway_ip:
                continue
            _remove_host_routes(ip)
            _run(
                [
                    "route",
                    "add",
                    ip,
                    "mask",
                    "255.255.255.255",
                    current_gateway,
                    "metric",
                    "1",
                ]
            )
            self._preserve_routes.append(ip)

        _run([
            "netsh",
            "interface",
            "ip",
            "set",
            "address",
            f"name={self.adapter_name}",
            "static",
            assigned_ip,
            "255.255.255.0",
            gateway_ip,
            "1",
        ])

        if dns_servers:
            _run([
                "netsh",
                "interface",
                "ip",
                "set",
                "dns",
                f"name={self.adapter_name}",
                "static",
                dns_servers[0],
                "primary",
            ])
            for idx, server in enumerate(dns_servers[1:], start=2):
                _run([
                    "netsh",
                    "interface",
                    "ip",
                    "add",
                    "dns",
                    f"name={self.adapter_name}",
                    server,
                    f"index={idx}",
                ])

        subprocess.run(
            [
                "route",
                "delete",
                "0.0.0.0",
                "mask",
                "0.0.0.0",
                gateway_ip,
                "if",
                str(if_index),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )

        try:
            _run([
                "route",
                "add",
                "0.0.0.0",
                "mask",
                "0.0.0.0",
                gateway_ip,
                "if",
                str(if_index),
                "metric",
                "3",
            ])
            self._default_route_set = True
            self._save_state(gateway_ip)
        except Exception:
            self.rollback(gateway_ip=gateway_ip)
            raise

    def rollback(self, gateway_ip: str) -> None:
        try:
            if self._default_route_set:
                if_index = self._get_if_index()
                subprocess.run(
                    [
                        "route",
                        "delete",
                        "0.0.0.0",
                        "mask",
                        "0.0.0.0",
                        gateway_ip,
                        "if",
                        str(if_index),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )

                # Also remove any stale default route entries to this gateway regardless of bound interface.
                subprocess.run(
                    ["route", "delete", "0.0.0.0", "mask", "0.0.0.0", gateway_ip],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                _cleanup_persistent_default_route(gateway_ip)

            if self._preserve_routes:
                for ip in self._preserve_routes:
                    _remove_host_routes(ip)
        finally:
            self._default_route_set = False
            self._preserve_routes = []
            self._clear_state()
