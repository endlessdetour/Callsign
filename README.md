# Callsign

English (default) | [简体中文](README.zh-CN.md)

Callsign is a lightweight overlay networking prototype with a built-in admin
console for user and access management.

## Features

- **Overlay tunnel** — WebSocket-based control/tunnel planes with per-device
  session tokens and a Linux `tun` data path.
- **Admin console** (`/login`) — role-based web UI for managing users, tokens,
  and access. Forced first-login credential change for the seeded admin.
- **User management** — create users (auto-generated or custom password and
  token), set/clear expiry, enable/disable, delete, and reset a user's password
  (which forces a change on their next login and revokes their sessions).
- **Self-service** — regular users can view their own access details and change
  their own password.
- **Live system health** — admin panel shows CPU, memory, disk, load, and
  uptime, polled every few seconds (read from `/proc`, no extra dependencies).
- **Hardened by default** — see [Security](#security).

## Security

- Passwords hashed with pbkdf2_sha256 (120k rounds) + per-user salt; constant
  time comparison; login timing equalized to prevent username enumeration.
- Server-stored session tokens (`secrets.token_urlsafe`).
- Control plane runs under gunicorn behind nginx; security headers (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy) are set on every
  response and the `Server` header is stripped.
- Optional Cloudflare-only origin gate (nginx `geo` on the real peer address),
  default nginx welcome page closed, and `server_tokens off`.
- Per-device overlay IP leases (no address collisions) and tunnel source-IP
  anti-spoofing.
- Windows client encrypts its access token at rest with DPAPI.

## Server Install (One Command)

```bash
wget -qO- https://raw.githubusercontent.com/endlessdetour/Callsign/fast_iteration/deploy/install-server.sh | sudo CALLSIGN_BRANCH=fast_iteration bash
```

This installs/updates server components, asks/uses your domain, automatically requests a Let's Encrypt certificate (falls back to self-signed only if issuance fails), enables certificate auto-renewal, renders nginx config, creates token, writes systemd units, and starts services.

Optional flags:

- `CALLSIGN_BRANCH=fast_iteration` to install a specific branch
- `CALLSIGN_TRUST_CLOUDFLARE=1` to keep Cloudflare-only source gating in nginx
- `CALLSIGN_REQUEST_SSL_CERT=0` to skip Let's Encrypt request and force self-signed cert

Default behavior:

- Interactive shell: installer asks for domain and whether to enable Cloudflare geo gate (default is `No`)
- Interactive shell: installer asks whether to request Let's Encrypt SSL cert (default is `Yes`)
- Non-interactive shell: Cloudflare geo gate is disabled unless `CALLSIGN_TRUST_CLOUDFLARE=1` is explicitly set
- Non-interactive shell: Let's Encrypt request is enabled unless `CALLSIGN_REQUEST_SSL_CERT=0` is explicitly set

## Admin Console

After install, open `https://<your-domain>/login`. The installer prints the
seeded admin credentials in its summary and writes them to
`/etc/callsign/initial_admin_credentials.txt` (mode `0600`, root only).

On first login you are required to set a new administrator username and
password; the seeded `admin` account is then disabled. Use the console to create
and manage users, set token expiry, reset passwords, and watch live system
health.

## Client Downloads

- Windows ARM64: [Download from Releases](https://github.com/endlessdetour/Callsign/releases) (`callsign-windows-arm64.zip`)
- Windows x64: [Download from Releases](https://github.com/endlessdetour/Callsign/releases) (`callsign-windows-amd64.zip`)
- macOS: support pending

Notes:
- The build automatically bundles the matching Wintun driver for the host architecture (arm64 / x64), so all Windows packages share the same build path and are published under the `callsign-windows-<arch>.zip` naming pattern.
- A macOS client is not available yet; only the Windows client is shipped today.

## Quick Local Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
./scripts/start-control.ps1
./scripts/start-tunnel.ps1
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

## Docs

- Architecture: [docs/architecture.md](docs/architecture.md)
- Nginx example: [deploy/nginx.conf.example](deploy/nginx.conf.example)
- Systemd units: [deploy/systemd](deploy/systemd)
- Server installer: [deploy/install-server.sh](deploy/install-server.sh)
