#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (or via sudo)."
  exit 1
fi

INSTALL_DIR="${CALLSIGN_INSTALL_DIR:-/opt/callsign}"
REPO_URL="${CALLSIGN_REPO_URL:-https://github.com/endlessdetour/Callsign.git}"
BRANCH="${CALLSIGN_BRANCH:-main}"
ENV_FILE="/etc/proxy-server.env"
TOKEN_FILE="/etc/callsign/access_token"

echo "[callsign] install dir: ${INSTALL_DIR}"
echo "[callsign] repo: ${REPO_URL} (${BRANCH})"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip iptables nginx

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

grep -q '^CALLSIGN_ACCESS_TOKEN_FILE=' "${ENV_FILE}" || echo "CALLSIGN_ACCESS_TOKEN_FILE=${TOKEN_FILE}" >> "${ENV_FILE}"
grep -q '^CALLSIGN_ACCESS_TOKEN=' "${ENV_FILE}" || echo "CALLSIGN_ACCESS_TOKEN=$(cat "${TOKEN_FILE}")" >> "${ENV_FILE}"
grep -q '^CONTROL_VALIDATE_URL=' "${ENV_FILE}" || echo "CONTROL_VALIDATE_URL=http://127.0.0.1:5000/api/v1/validate" >> "${ENV_FILE}"
grep -q '^CALLSIGN_TUNNEL_PATH=' "${ENV_FILE}" || echo "CALLSIGN_TUNNEL_PATH=/connect-ws" >> "${ENV_FILE}"
grep -q '^CALLSIGN_TUN_MODE=' "${ENV_FILE}" || echo "CALLSIGN_TUN_MODE=tun" >> "${ENV_FILE}"
grep -q '^CALLSIGN_TUN_INTERFACE=' "${ENV_FILE}" || echo "CALLSIGN_TUN_INTERFACE=tun0" >> "${ENV_FILE}"
grep -q '^CALLSIGN_TUN_LOCAL_CIDR=' "${ENV_FILE}" || echo "CALLSIGN_TUN_LOCAL_CIDR=10.99.0.1/24" >> "${ENV_FILE}"

install -m 644 "${INSTALL_DIR}/deploy/systemd/callsign-nat.service" /etc/systemd/system/callsign-nat.service
install -m 755 "${INSTALL_DIR}/deploy/systemd/callsign-nat-setup.sh" /usr/local/bin/callsign-nat-setup.sh
install -m 644 "${INSTALL_DIR}/deploy/systemd/proxy-control.service" /etc/systemd/system/proxy-control.service
install -m 644 "${INSTALL_DIR}/deploy/systemd/proxy-tunnel.service" /etc/systemd/system/proxy-tunnel.service

systemctl daemon-reload
systemctl enable nginx
systemctl restart nginx
systemctl enable callsign-nat.service proxy-control.service proxy-tunnel.service
systemctl restart callsign-nat.service
systemctl restart proxy-control.service
systemctl restart proxy-tunnel.service

TOKEN_VALUE="$(cat "${TOKEN_FILE}")"
echo "[callsign] install complete"
echo "[callsign] token file: ${TOKEN_FILE}"
echo "[callsign] token: ${TOKEN_VALUE}"
echo "[callsign] health: $(curl -s -o /dev/null -w '%{http_code}' -H "X-Access-Token: ${TOKEN_VALUE}" http://127.0.0.1:5000/healthz)"