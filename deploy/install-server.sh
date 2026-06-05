#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (or via sudo)."
  exit 1
fi

INSTALL_DIR="${CALLSIGN_INSTALL_DIR:-/opt/callsign}"
REPO_URL="${CALLSIGN_REPO_URL:-https://github.com/endlessdetour/Callsign.git}"
BRANCH="${CALLSIGN_BRANCH:-main}"
DOMAIN="${CALLSIGN_DOMAIN:-}"
TRUST_CLOUDFLARE="${CALLSIGN_TRUST_CLOUDFLARE:-0}"
ENV_FILE="/etc/proxy-server.env"
TOKEN_FILE="/etc/callsign/access_token"
NGINX_SITE_AVAILABLE="/etc/nginx/sites-available/proxy-server.conf"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/proxy-server.conf"

echo "[callsign] install dir: ${INSTALL_DIR}"
echo "[callsign] repo: ${REPO_URL} (${BRANCH})"

if [[ -z "${DOMAIN}" ]]; then
  if [[ -t 0 ]]; then
    read -r -p "[callsign] domain (example: cloud.example.com): " DOMAIN
  fi
fi

if [[ -z "${DOMAIN}" ]]; then
  echo "[callsign] CALLSIGN_DOMAIN is required (example: cloud.example.com)." >&2
  echo "[callsign] Usage: wget -qO- <url> | sudo CALLSIGN_DOMAIN=cloud.example.com bash" >&2
  exit 1
fi

echo "[callsign] domain: ${DOMAIN}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip iptables nginx openssl

TLS_CERT_PATH="${CALLSIGN_TLS_CERT:-/etc/letsencrypt/live/${DOMAIN}/fullchain.pem}"
TLS_KEY_PATH="${CALLSIGN_TLS_KEY:-/etc/letsencrypt/live/${DOMAIN}/privkey.pem}"

if [[ ! -s "${TLS_CERT_PATH}" || ! -s "${TLS_KEY_PATH}" ]]; then
  echo "[callsign] TLS cert not found for ${DOMAIN}, generating self-signed cert."
  install -d -m 700 /etc/nginx/certs
  TLS_CERT_PATH="/etc/nginx/certs/${DOMAIN}.crt"
  TLS_KEY_PATH="/etc/nginx/certs/${DOMAIN}.key"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${TLS_KEY_PATH}" \
    -out "${TLS_CERT_PATH}" \
    -days 365 \
    -subj "/CN=${DOMAIN}" >/dev/null 2>&1
  chmod 600 "${TLS_KEY_PATH}"
fi

if [[ "${TRUST_CLOUDFLARE}" == "1" && ! -f /etc/nginx/conf.d/cloudflare-geo.conf ]]; then
  echo "[callsign] cloudflare-geo.conf not found; disabling Cloudflare-only gate."
  TRUST_CLOUDFLARE=0
fi

upsert_env() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "${ENV_FILE}"; then
    sed -i "s#^${key}=.*#${key}=${value}#" "${ENV_FILE}"
  else
    echo "${key}=${value}" >> "${ENV_FILE}"
  fi
}

mkdir -p "${INSTALL_DIR}"
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  git -C "${INSTALL_DIR}" fetch --all --prune
  if git -C "${INSTALL_DIR}" show-ref --verify --quiet "refs/remotes/origin/${BRANCH}"; then
    git -C "${INSTALL_DIR}" checkout -B "${BRANCH}" "origin/${BRANCH}"
  else
    echo "[callsign] branch not found on origin: ${BRANCH}" >&2
    exit 1
  fi
  git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
else
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
fi

python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/python" -m pip install --upgrade pip
"${INSTALL_DIR}/.venv/bin/python" -m pip install -r "${INSTALL_DIR}/requirements.txt"

install -d -m 700 /etc/callsign
if [[ ! -s "${TOKEN_FILE}" ]]; then
  python3 - <<'PY' > "${TOKEN_FILE}"
import secrets
print(secrets.token_urlsafe(32))
PY
fi
chmod 600 "${TOKEN_FILE}"

if [[ ! -f "${ENV_FILE}" ]]; then
  install -m 600 /dev/null "${ENV_FILE}"
fi

upsert_env "CALLSIGN_ACCESS_TOKEN_FILE" "${TOKEN_FILE}"
upsert_env "CALLSIGN_ACCESS_TOKEN" "$(cat "${TOKEN_FILE}")"
upsert_env "CONTROL_VALIDATE_URL" "http://127.0.0.1:5000/api/v1/validate"
upsert_env "CALLSIGN_TUNNEL_PATH" "/connect-ws"
upsert_env "CALLSIGN_TUN_MODE" "tun"
upsert_env "CALLSIGN_TUN_INTERFACE" "tun0"
upsert_env "CALLSIGN_TUN_LOCAL_CIDR" "10.99.0.1/24"
upsert_env "CALLSIGN_TUNNEL_PUBLIC_URL" "wss://${DOMAIN}/connect-ws"

python3 - <<PY
from pathlib import Path
import re

src = Path("${INSTALL_DIR}/deploy/nginx.conf.example")
dst = Path("${NGINX_SITE_AVAILABLE}")
domain = "${DOMAIN}"
cert = "${TLS_CERT_PATH}"
key = "${TLS_KEY_PATH}"
trust_cf = "${TRUST_CLOUDFLARE}" == "1"

text = src.read_text(encoding="utf-8")
text = text.replace("overlay.example.com", domain)
text = text.replace("# ssl_certificate     /etc/nginx/certs/fullchain.pem;", f"ssl_certificate     {cert};")
text = text.replace("# ssl_certificate_key /etc/nginx/certs/privkey.pem;", f"ssl_certificate_key {key};")
text = text.replace("ssl_certificate     /etc/nginx/certs/fullchain.pem;", f"ssl_certificate     {cert};")
text = text.replace("ssl_certificate_key /etc/nginx/certs/privkey.pem;", f"ssl_certificate_key {key};")

if not trust_cf:
    text = re.sub(r"\n\s*# Optional: only trust Cloudflare origin traffic\.\n\s*# Requires /etc/nginx/conf\.d/cloudflare-geo\.conf from deploy/nginx\.cloudflare-geo\.conf\.example\.\n", "\n", text)
    text = re.sub(r"\n\s*if \(\$from_cloudflare = 0\) \{\n\s*return 444;\n\s*\}\n", "\n", text)

dst.write_text(text, encoding="utf-8")
PY

ln -sfn "${NGINX_SITE_AVAILABLE}" "${NGINX_SITE_ENABLED}"
rm -f /etc/nginx/sites-enabled/default

install -m 644 "${INSTALL_DIR}/deploy/systemd/callsign-nat.service" /etc/systemd/system/callsign-nat.service
install -m 755 "${INSTALL_DIR}/deploy/systemd/callsign-nat-setup.sh" /usr/local/bin/callsign-nat-setup.sh
install -m 644 "${INSTALL_DIR}/deploy/systemd/proxy-control.service" /etc/systemd/system/proxy-control.service
install -m 644 "${INSTALL_DIR}/deploy/systemd/proxy-tunnel.service" /etc/systemd/system/proxy-tunnel.service

systemctl daemon-reload
nginx -t
systemctl enable nginx
systemctl restart nginx
systemctl enable callsign-nat.service proxy-control.service proxy-tunnel.service
systemctl restart callsign-nat.service
systemctl restart proxy-control.service
systemctl restart proxy-tunnel.service

TOKEN_VALUE="$(cat "${TOKEN_FILE}")"
echo "[callsign] install complete"
echo "[callsign] domain: ${DOMAIN}"
echo "[callsign] tls cert: ${TLS_CERT_PATH}"
echo "[callsign] token file: ${TOKEN_FILE}"
echo "[callsign] token: ${TOKEN_VALUE}"
echo "[callsign] health: $(curl -s -o /dev/null -w '%{http_code}' -H "X-Access-Token: ${TOKEN_VALUE}" http://127.0.0.1:5000/healthz)"