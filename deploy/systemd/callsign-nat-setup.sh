#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/proxy-server.env"
TUN_INTERFACE="${CALLSIGN_TUN_INTERFACE:-tun0}"
TUN_LOCAL_CIDR="${CALLSIGN_TUN_LOCAL_CIDR:-10.99.0.1/24}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  TUN_INTERFACE="${CALLSIGN_TUN_INTERFACE:-$TUN_INTERFACE}"
  TUN_LOCAL_CIDR="${CALLSIGN_TUN_LOCAL_CIDR:-$TUN_LOCAL_CIDR}"
fi

TUN_NETWORK="$(TUN_LOCAL_CIDR="$TUN_LOCAL_CIDR" python3 - <<'PY'
import ipaddress
import os
print(ipaddress.ip_network(os.environ.get("TUN_LOCAL_CIDR", "10.99.0.1/24"), strict=False))
PY
)"

EGRESS_IFACE="$(ip -4 route show default 0.0.0.0/0 | awk '{print $5}' | head -n 1)"
if [[ -z "$EGRESS_IFACE" ]]; then
  echo "[callsign-nat] failed to detect default egress interface" >&2
  exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -s "$TUN_NETWORK" -o "$EGRESS_IFACE" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$TUN_NETWORK" -o "$EGRESS_IFACE" -j MASQUERADE

iptables -C FORWARD -i "$TUN_INTERFACE" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "$TUN_INTERFACE" -j ACCEPT

iptables -C FORWARD -o "$TUN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -o "$TUN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "[callsign-nat] configured: tun=$TUN_INTERFACE network=$TUN_NETWORK egress=$EGRESS_IFACE"