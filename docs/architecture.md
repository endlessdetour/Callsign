# Architecture (Prototype)

## Goal

- Expose only HTTPS on port 443 externally.
- Use a driver-oriented client path later (Wintun integration).
- Validate transport and control flow first.

## Planes

1. Control plane (Flask)
- Bootstrap device.
- Issue session token.
- Heartbeat and token validation.

2. Data plane (websockets over HTTPS/WSS)
- Accept authenticated tunnel connection.
- Carry binary frames over TLS (via reverse proxy).
- Echo in prototype stage to validate duplex transport.

3. Client plane (Windows agent)
- Perform bootstrap.
- Keep heartbeat loop.
- Connect tunnel and exchange frames.
- Adapter abstraction so MockTunAdapter can be replaced by WintunAdapter.

## Production direction

- Put Nginx/Caddy in front for TLS and 443-only exposure.
- Keep single CALLSIGN_ACCESS_TOKEN in prototype; move to mTLS + signed short-lived tokens for production.
- Replace mock adapter with Wintun and route management.
- Replace echo tunnel with real packet forwarding/NAT service.
