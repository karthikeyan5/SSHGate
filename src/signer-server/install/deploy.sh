#!/usr/bin/env bash
# deploy.sh — VPS-side install script for sshgate-signer-server (v2 scaffold).
#
# Idempotent. Run as a user with sudo on a fresh-ish Linux box:
#
#   git clone <sshgate repo>
#   cd sshgate/src/signer-server
#   sudo ./install/deploy.sh
#
# What it does (in order):
#   1. Verifies Go toolchain is present (the daemon is built from source —
#      no pre-built binary is committed; this mirrors v1's plugin install).
#   2. Creates a dedicated `sshgate-signer-server` system user (no shell, no
#      home directory).
#   3. Creates /var/lib/sshgate-signer-server (owned by the user) for the
#      SQLite DB.
#   4. Creates /etc/sshgate-signer-server with a 0700 keys/ subdir for the
#      bearer-token file. If api-key.txt doesn't already exist, generates
#      one with `openssl rand -base64 32`.
#   5. Builds the binary with `go build` and installs it at
#      /usr/local/bin/sshgate-signer-server.
#   6. Renders the systemd unit (with placeholder substitution from the
#      template) at /etc/systemd/system/sshgate-signer-server.service.
#   7. Enables + starts the service.
#   8. Prints the API key path + a quick smoke test (curl /healthz).
#
# What it does NOT do (v2.1 work):
#   - Provision TLS. The server listens on 127.0.0.1:8443 (plain HTTP);
#     operators need a reverse proxy (Caddy/nginx) for public traffic.
#   - Register users for the web UI. v2.0 has no human-approval UI yet.
#   - Configure log shipping or metrics.
#
# Re-running this script is safe: existing user/dir/file/unit are
# detected and left alone (or upgraded in place for the binary + unit).

set -euo pipefail

# ----- Configurable knobs (override via env) -----
SERVICE_USER="${SIGNER_SERVER_USER:-sshgate-signer-server}"
INSTALL_DIR="${SIGNER_SERVER_INSTALL_DIR:-/usr/local/bin}"
STATE_DIR="${SIGNER_SERVER_STATE_DIR:-/var/lib/sshgate-signer-server}"
CONFIG_DIR="${SIGNER_SERVER_CONFIG_DIR:-/etc/sshgate-signer-server}"
KEYS_DIR="${SIGNER_SERVER_KEYS_DIR:-${CONFIG_DIR}/keys}"
API_KEY_FILE="${SIGNER_SERVER_API_KEY_FILE:-${KEYS_DIR}/api-key.txt}"
DB_PATH="${SIGNER_SERVER_DB:-${STATE_DIR}/state.db}"
LISTEN_ADDR="${SIGNER_SERVER_ADDR:-127.0.0.1:8443}"
UNIT_PATH="/etc/systemd/system/sshgate-signer-server.service"

# ----- Helpers -----
log() { printf '[deploy] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }
need_sudo() { [[ $EUID -eq 0 ]] || fail "run as root (or via sudo)"; }

# Discover the repo root: this script lives at <repo>/src/signer-server/install/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PKG_DIR}/../.." && pwd)"

# ----- Pre-flight -----
need_sudo
command -v go >/dev/null 2>&1 || fail "go toolchain not found; install Go 1.22+ first"
command -v systemctl >/dev/null 2>&1 || fail "systemctl not found; this script targets systemd hosts"
command -v openssl >/dev/null 2>&1 || fail "openssl not found; needed for API key generation"

# ----- 1. user -----
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  log "creating system user '${SERVICE_USER}'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
  log "user '${SERVICE_USER}' already exists"
fi

# ----- 2. directories -----
log "ensuring state dir ${STATE_DIR} (owned by ${SERVICE_USER})"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"

log "ensuring config dirs ${CONFIG_DIR} + ${KEYS_DIR}"
install -d -m 0755 "${CONFIG_DIR}"
install -d -m 0700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${KEYS_DIR}"

# ----- 3. API key (single bearer token for v2.0) -----
if [[ ! -s "${API_KEY_FILE}" ]]; then
  log "generating bearer API key at ${API_KEY_FILE}"
  umask 077
  openssl rand -base64 32 > "${API_KEY_FILE}"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${API_KEY_FILE}"
  chmod 0600 "${API_KEY_FILE}"
else
  log "API key already present at ${API_KEY_FILE}; leaving it alone"
fi

# ----- 4. build the binary -----
log "building sshgate-signer-server from ${REPO_ROOT}"
(
  cd "${REPO_ROOT}"
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' \
    -o "${INSTALL_DIR}/sshgate-signer-server" \
    ./src/signer-server/cmd/sshgate-signer-server
)
chmod 0755 "${INSTALL_DIR}/sshgate-signer-server"
log "installed binary at ${INSTALL_DIR}/sshgate-signer-server"

# ----- 5. systemd unit -----
log "rendering systemd unit at ${UNIT_PATH}"
TEMPLATE="${SCRIPT_DIR}/sshgate-signer-server.service"
[[ -f "${TEMPLATE}" ]] || fail "systemd unit template missing at ${TEMPLATE}"

# Simple sed substitution; the template uses __FOO__ placeholders that
# don't appear in any legitimate systemd directive.
sed \
  -e "s#__BIN__#${INSTALL_DIR}/sshgate-signer-server#g" \
  -e "s#__USER__#${SERVICE_USER}#g" \
  -e "s#__API_KEY_FILE__#${API_KEY_FILE}#g" \
  -e "s#__DB_PATH__#${DB_PATH}#g" \
  -e "s#__LISTEN_ADDR__#${LISTEN_ADDR}#g" \
  -e "s#__STATE_DIR__#${STATE_DIR}#g" \
  -e "s#__INSTALL_DIR__#${PKG_DIR}#g" \
  "${TEMPLATE}" > "${UNIT_PATH}"

systemctl daemon-reload
systemctl enable sshgate-signer-server.service >/dev/null
systemctl restart sshgate-signer-server.service
log "service enabled + (re)started"

# ----- 6. smoke test -----
sleep 1
if command -v curl >/dev/null 2>&1; then
  log "smoke test: GET ${LISTEN_ADDR}/healthz"
  if curl -fsS "http://${LISTEN_ADDR}/healthz"; then
    log "smoke test passed"
  else
    log "smoke test FAILED — check 'journalctl -u sshgate-signer-server -n 50'"
    exit 1
  fi
fi

log "done."
log ""
log "API key (give this to laptop clients):"
log "  ${API_KEY_FILE}"
log ""
log "Next: stand up a reverse proxy (Caddy/nginx) terminating TLS on 443"
log "      and forwarding to ${LISTEN_ADDR}. v2.0 server speaks plain HTTP;"
log "      it expects TLS to be handled upstream."
