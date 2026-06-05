# Callsign

English (default) | [简体中文](README.zh-CN.md)

Callsign is a lightweight overlay networking prototype with a split control plane and data plane.

It focuses on fast protocol validation, strict token-based access control, and practical deployment behind a reverse proxy.

## Features

- Split architecture: Flask control plane + WebSocket tunnel plane + Windows client
- Token-gated control and tunnel endpoints (`X-Access-Token` required)
- Session bootstrap, heartbeat, and server-side validation flow
- Echo mode for transport validation and tun mode for routed traffic
- Windows GUI with tray controls, profile management, and single-instance guard
- NAT persistence via systemd (`callsign-nat.service`) for Linux server boot recovery

## Architecture

1. Control plane (`server/control`)
- Bootstrap
- Session issuance
- Heartbeat and token validation

2. Tunnel plane (`server/tunnel`)
- Authenticated WebSocket endpoint
- Packet transport (echo / tun)
- Control-plane-backed bearer validation

3. Client plane (`client/windows`)
- Bootstrap and heartbeat loops
- Tunnel connection lifecycle
- Adapter abstraction (mock / Wintun)

Detailed design: [docs/architecture.md](docs/architecture.md)

## Quick Start

### 1) Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2) Minimal config

```powershell
Copy-Item .env.example .env
```

Set at least:

```text
CALLSIGN_ACCESS_TOKEN=<strong-random-token>
```

### 3) Start services

Control:

```powershell
./scripts/start-control.ps1
```

Tunnel:

```powershell
./scripts/start-tunnel.ps1
```

Client:

```powershell
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

For local plaintext testing only:

```powershell
./scripts/start-client.ps1 -ControlUrl http://127.0.0.1:5000 -TunnelUrl ws://127.0.0.1:8443/connect-ws -AllowInsecure
```

## Build

```powershell
./scripts/build-exe.ps1
```

Output:

- `dist/callsign/callsign.exe`
- `dist/callsign-windows-arm64.zip`

This is an onedir package. Distribute the zip or full folder, not a single exe.

## Configuration

Core variables:

- `CALLSIGN_ACCESS_TOKEN`: direct token value
- `CALLSIGN_ACCESS_TOKEN_FILE`: token file path (default `/etc/callsign/access_token`)
- `CALLSIGN_TUNNEL_PATH`: WebSocket path (must match control/tunnel/proxy)

Control-plane variables:

- `CALLSIGN_SESSION_TTL` (default `3600`)
- `CALLSIGN_TUNNEL_PUBLIC_URL`

Tunnel-plane variables:

- `CONTROL_VALIDATE_URL` (default `http://127.0.0.1:5000/api/v1/validate`)
- `CALLSIGN_TUN_MODE` (`echo` or `tun`)
- `CALLSIGN_TUN_INTERFACE` (default `tun0`)
- `CALLSIGN_TUN_LOCAL_CIDR` (default `10.99.0.1/24`)

## Server Deployment Notes

- Baseline proxy config: `deploy/nginx.conf.example`
- NAT persistence assets:
  - `deploy/systemd/callsign-nat.service`
  - `deploy/systemd/callsign-nat-setup.sh`

Recommended token initialization on Linux:

```bash
sudo install -d -m 700 /etc/callsign
sudo sh -c 'umask 077; [ -s /etc/callsign/access_token ] || python3 - <<"PY" > /etc/callsign/access_token
import secrets
print(secrets.token_urlsafe(32))
PY'
sudo chmod 600 /etc/callsign/access_token
```

Set in `/etc/proxy-server.env`:

```bash
CALLSIGN_ACCESS_TOKEN_FILE=/etc/callsign/access_token
```

## Testing

Run full regression set:

```powershell
.\.venv\Scripts\python.exe scripts/server_auth_surface_smoke.py
.\.venv\Scripts\python.exe scripts/gui_full_regression_test.py
.\.venv\Scripts\python.exe scripts/gui_startup_elevation_test.py
.\.venv\Scripts\python.exe scripts/gui_single_instance_smoke.py
.\.venv\Scripts\python.exe scripts/gui_tray_smoke_test.py
.\.venv\Scripts\python.exe scripts/gui_tray_runtime_smoke.py
```

## Security Checklist (Before Git Push)

- Keep real tokens out of git history
- Keep `.env`, `.env.*`, and `deploy/proxy-server.env` local only
- Keep `client_profiles.json`, `*.log`, and `*.ppk` out of version control
- Rotate any credential once it appeared in shell history, logs, or screenshots

## Repository Layout

- `server/control`: control service
- `server/tunnel`: tunnel service
- `client/windows`: Windows GUI and agent
- `scripts`: build, run, deploy, and test scripts
- `deploy`: nginx and systemd deployment assets
- `third_party/wintun`: Wintun binaries and license

## Project Status

Callsign is a prototype focused on behavior validation and incremental hardening.

Not yet in scope:

- Production-grade policy engine
- End-to-end mTLS identity
- Full observability and SRE operations stack
