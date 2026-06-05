# Callsign

Callsign: A lightweight HTTP/3 overlay network.

Callsign is an open-source overlay networking prototype with a split control plane and data plane.

It is designed for:
- Fast protocol and routing validation
- 443-only external exposure through reverse proxy
- Incremental hardening for real-world deployment

Current implementation includes a Windows GUI client, a control service (Flask), and a tunnel service (WebSocket).

## 1) Project Positioning

Callsign is positioned as a general-purpose overlay networking project, closer to infrastructure networking tools and private connectivity platforms.

## 2) What This Project Provides

- Windows GUI client with profile management
- Start and stop connection from main window and system tray
- Single-instance guard (prevents opening multiple app windows)
- Auto-admin relaunch path for operations requiring administrator privileges
- Wintun-based adapter path and route programming option
- Control-plane bootstrap, heartbeat, and token validation
- Tunnel-plane authenticated WebSocket transport
- Security hardening baseline:
  - Mandatory access token on control and tunnel services
  - Unauthorized or invalid requests are denied with HTTP 444

## 3) Current Scope and Non-goals

This is still a prototype. It validates control and transport behavior, but is not yet a full production network platform.

Not completed yet:
- Full production-grade packet forwarding policy engine
- Certificate-based identity (mTLS) end-to-end
- Complete observability and SRE-grade operations tooling

## 4) High-level Architecture

1. Control plane (Flask)
- Device bootstrap
- Session issuance
- Heartbeat and token validation

2. Data plane (WebSocket)
- Authenticated tunnel endpoint
- Binary frame transport
- Echo-mode transport validation and tun-mode support path

3. Client plane (Windows)
- Bootstrap and heartbeat loops
- Tunnel connection and frame exchange
- Adapter abstraction (Mock and Wintun)

See also: docs/architecture.md

## 5) Repository Layout

- server/control: Flask control-plane service
- server/tunnel: WebSocket tunnel service
- client/windows: Windows GUI and agent
- scripts: run/build/test scripts
- deploy: reverse proxy and deployment examples
- third_party/wintun: Wintun runtime files and license

## 6) Security Model (Important)

Callsign now uses a mandatory access token model.

Required controls:
- Access token is mandatory on both control and tunnel services
  - Service reads `CALLSIGN_ACCESS_TOKEN` first
  - If unset, service reads `CALLSIGN_ACCESS_TOKEN_FILE` (default: `/etc/callsign/access_token`)
- Clients must provide X-Access-Token on control and tunnel requests
- Control-plane unauthorized/invalid access is denied as 444; tunnel handshake rejections use standard HTTP codes for WebSocket compatibility

Operational implication:
- If token source is missing or mismatched anywhere in the chain, requests will be rejected

## 7) Prerequisites

- Windows 11 for client development and GUI packaging
- Python 3.14.x (same major/minor as your runtime)
- PowerShell
- Optional for packaging: PyInstaller (installed in venv)

## 8) Quick Start (Local Prototype)

### 8.1 Create environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 8.2 Prepare config file

```powershell
Copy-Item .env.example .env
```

Edit `.env` and set real values for at least:
- `CALLSIGN_ACCESS_TOKEN`

### 8.3 Set required environment variables (optional override)

Set these in every terminal that runs control, tunnel, or client:

```powershell
$env:CALLSIGN_ACCESS_TOKEN="replace-with-strong-random-token"
$env:CALLSIGN_TUNNEL_PATH="/connect-ws"
$env:CALLSIGN_TUNNEL_PUBLIC_URL="wss://overlay.example.com/connect-ws"
```

### 8.4 Start services

Terminal A (control):

```powershell
./scripts/start-control.ps1
```

Terminal B (tunnel):

```powershell
./scripts/start-tunnel.ps1
```

Terminal C (client agent):

```powershell
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

Optional local plaintext testing only:

```powershell
./scripts/start-client.ps1 -ControlUrl http://127.0.0.1:5000 -TunnelUrl ws://127.0.0.1:8443/connect-ws -AllowInsecure
```

## 9) Windows GUI Client

Run from source:

```powershell
./scripts/start-client-gui.ps1
```

Key UX behavior:
- Close button minimizes to tray
- Tray menu supports connect/disconnect/show/exit
- Main window includes an explicit Exit button
- Re-launch when already running shows a tray reminder instead of opening another instance

## 10) Build Windows Executable

```powershell
./scripts/build-exe.ps1
```

Output:
- dist/callsign/callsign.exe
- dist/callsign-windows-arm64.zip

Notes:
- callsign.exe is the user entrypoint
- agent.exe is a helper backend process packaged alongside the GUI bundle
- This is an onedir package. Do not distribute only callsign.exe or agent.exe.
- Share dist/callsign-windows-arm64.zip (or the full dist/callsign folder).

## 11) Configuration Reference

### Shared core variables

Use CALLSIGN_* names only.

- CALLSIGN_ACCESS_TOKEN
  - Purpose: direct access token value for control/tunnel requests
  - Required: no (if `CALLSIGN_ACCESS_TOKEN_FILE` is set and valid)

- CALLSIGN_ACCESS_TOKEN_FILE
  - Purpose: file path containing access token used by control/tunnel services
  - Required: recommended for server deployment
  - Default: /etc/callsign/access_token

- CALLSIGN_TUNNEL_PATH
  - Purpose: tunnel WebSocket path (must match control, tunnel, and proxy)
  - Required: recommended
  - Example: /connect-ws

### Control service

- CALLSIGN_SESSION_TTL
  - Purpose: session token TTL in seconds
  - Default: 3600

- CALLSIGN_TUNNEL_PUBLIC_URL
  - Purpose: public WSS URL returned to clients during bootstrap
  - Example: wss://overlay.example.com/connect-ws

### Tunnel service

- CONTROL_VALIDATE_URL
  - Purpose: control endpoint for bearer validation
  - Default: http://127.0.0.1:5000/api/v1/validate

- CALLSIGN_TUN_MODE
  - Purpose: echo or tun
  - Default: echo

- CALLSIGN_TUN_INTERFACE
  - Purpose: tun interface name used by tunnel service
  - Default: tun0

- CALLSIGN_TUN_LOCAL_CIDR
  - Purpose: tun gateway CIDR used for routing/NAT
  - Default: 10.99.0.1/24

## 12) NAT Persistence (Linux Server)

- Deployment installs and enables callsign-nat.service automatically.
- callsign-nat.service runs /usr/local/bin/callsign-nat-setup.sh on boot.
- It enforces ip_forward, MASQUERADE, and FORWARD rules for tun traffic.

## 13) Reverse Proxy and Exposure

Use deploy/nginx.conf.example as the baseline.

Hardening recommendations:
- Expose only 443 publicly
- Keep app processes on localhost/private network
- Keep tunnel path non-default and consistent end-to-end
- Add source allowlists (for example trusted edge/CDN ranges)
- Add rate limits and connection caps

## 14) Tests

GUI and behavior regression scripts:
- scripts/gui_startup_elevation_test.py
- scripts/gui_full_regression_test.py
- scripts/gui_tray_smoke_test.py
- scripts/gui_tray_runtime_smoke.py
- scripts/gui_single_instance_smoke.py

Server auth-surface smoke test:
- scripts/server_auth_surface_smoke.py

Example run:

```powershell
.\.venv\Scripts\python.exe scripts/server_auth_surface_smoke.py
.\.venv\Scripts\python.exe scripts/gui_full_regression_test.py
```

## 15) Troubleshooting

### GUI starts but no connection

- Check CALLSIGN_ACCESS_TOKEN is set in client terminal
- Verify control URL and tunnel public URL/path are consistent
- Check reverse proxy upgrade headers for WebSocket

### Requests always denied

- Confirm X-Access-Token is correctly configured end-to-end
- Confirm control/tunnel both run with the same CALLSIGN_ACCESS_TOKEN

### Wintun or route takeover issues

- Run GUI as administrator
- Verify Wintun DLL placement and licensing files
- Test echo mode first, then tun mode

### Icon not updating in Windows Explorer

- Rebuild completed binary and reopen Explorer window
- If needed, refresh icon cache

## 16) Open-source and Licensing Notes

- Review third_party/wintun license terms before redistribution
- Keep third-party notices in release artifacts
- Validate dependency licenses before commercial distribution

## 17) Pre-publish Security Checklist

Before pushing to GitHub, verify:
- No real keys/tokens are committed
  - `CALLSIGN_ACCESS_TOKEN` must stay as placeholder in examples
  - `CALLSIGN_ACCESS_TOKEN_FILE` should point to server-local paths only (for example `/etc/callsign/access_token`)
- No private deployment env files are committed
  - Keep `.env`, `.env.*`, and `deploy/proxy-server.env` local only
- No local profile or runtime logs are committed
  - Keep `client_profiles.json` and `*.log` out of version control
- No private key artifacts are committed
  - Keep `*.ppk` and other SSH private key files outside the repository
- Rotate any credential that was ever used in a local script, shell history, or screenshot
- Re-run regression tests before release
  - `scripts/gui_full_regression_test.py`
  - `scripts/server_auth_surface_smoke.py`

Git upload risk notes:
- Git history is immutable by default; once a real token is pushed, treat it as leaked and rotate immediately.
- Run a staged diff check before each commit and confirm no secret-bearing files are included.
- If a secret was committed, rewrite history and force-push, then rotate the secret regardless.

## 18) Server Token Initialization (Recommended)

For Linux server deployment, initialize and persist token as a root-only file:

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

You may also set `CALLSIGN_ACCESS_TOKEN` directly for local dev, but file-based loading is preferred on servers.

## 19) Roadmap

- mTLS device identity and short-lived signed credentials
- More resilient NAT/forwarding data plane behavior
- Better diagnostics, metrics, and production deployment templates
- Installer and update channel for desktop release
