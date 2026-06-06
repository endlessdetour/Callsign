# Callsign

English (default) | [简体中文](README.zh-CN.md)

Callsign is a lightweight overlay networking prototype.

## Server Install (One Command)

```bash
wget -qO- https://raw.githubusercontent.com/endlessdetour/Callsign/main/deploy/install-server.sh | sudo CALLSIGN_DOMAIN=cloud.example.com bash
```

This installs/updates server components, asks/uses your domain, automatically requests a Let's Encrypt certificate (falls back to self-signed only if issuance fails), enables certificate auto-renewal, renders nginx config, creates token, writes systemd units, and starts services.

Optional flags:

- `CALLSIGN_BRANCH=fast_iteration` to install a specific branch
- `CALLSIGN_TRUST_CLOUDFLARE=1` to keep Cloudflare-only source gating in nginx

Default behavior:

- Interactive shell: installer asks for domain and whether to enable Cloudflare geo gate (default is `No`)
- Non-interactive shell: Cloudflare geo gate is disabled unless `CALLSIGN_TRUST_CLOUDFLARE=1` is explicitly set

## Client Downloads

- Windows ARM64: [Click to Download](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-arm64.zip)
- Windows x64: [Click to Download](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-x64.zip)
- Windows x86: [Click to Download](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-x86.zip)

Notes:
- ARM64 link is current target.
- Other builds can be published later with the same link pattern.

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
