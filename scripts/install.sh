#!/usr/bin/env bash
# install.sh — copy SSHGate binaries to /usr/local and install the
# hardened velsigner systemd unit.
#
# Run from the SSHGate source tree root (the directory containing
# `bin/velsigner` and `bin/velgate-linux-amd64`):
#
#     sudo ./scripts/install.sh
#
# Idempotent. Re-running upgrades the binaries in place and restarts
# the daemon. The systemd unit is overwritten every run so any drift
# from a hand-edit is reset to the canonical hardened version.
#
# Prerequisites:
#   - scripts/create-velsigner-user.sh has already been run (velsigner
#     user exists; /var/lib/velsigner skeleton in place)
#   - bin/velsigner and bin/velgate-linux-amd64 exist (build first)
#
# Exit codes (per cli.md §2):
#   0  success
#   1  generic runtime failure
#   66 input file missing  (EX_NOINPUT)
#   77 not root            (EX_NOPERM)
#   78 misconfigured       (EX_CONFIG)
set -euo pipefail

log() { printf '[install] %s\n' "$*" >&2; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf '[install] ERROR: must run as root (try: sudo %s)\n' "$0" >&2
    exit 77
fi

if ! getent passwd velsigner >/dev/null 2>&1; then
    printf '[install] ERROR: velsigner user does not exist; run scripts/create-velsigner-user.sh first\n' >&2
    exit 78
fi

# Resolve repo root from this script's location so the operator can
# invoke install.sh from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VELSIGNER_BIN="$REPO_ROOT/bin/velsigner"
VELGATE_BIN="$REPO_ROOT/bin/velgate-linux-amd64"

if [ ! -x "$VELSIGNER_BIN" ]; then
    printf '[install] ERROR: %s not found or not executable; run go build first\n' "$VELSIGNER_BIN" >&2
    exit 66
fi
if [ ! -f "$VELGATE_BIN" ]; then
    printf '[install] ERROR: %s not found; run make velgate-linux first\n' "$VELGATE_BIN" >&2
    exit 66
fi

# Step 1: install binaries.
log "installing velsigner -> /usr/local/bin/velsigner"
install -m 0755 -o root -g root "$VELSIGNER_BIN" /usr/local/bin/velsigner

log "installing velgate-linux-amd64 -> /usr/local/share/sshgate/velgate-linux-amd64"
mkdir -p /usr/local/share/sshgate
install -m 0755 -o root -g root "$VELGATE_BIN" /usr/local/share/sshgate/velgate-linux-amd64

# Step 2: write the systemd unit. Always overwrite — the unit is the
# source of truth, not whatever a previous install or hand-edit left.
UNIT_PATH=/etc/systemd/system/velsigner.service
log "writing systemd unit -> $UNIT_PATH"
cat >"$UNIT_PATH" <<'UNIT'
[Unit]
Description=SSHGate signing daemon (velsigner)
After=network.target

[Service]
Type=simple
User=velsigner
Group=velsigner
ExecStart=/usr/local/bin/velsigner --config /var/lib/velsigner/config/config.toml
Restart=on-failure
RestartSec=10
RuntimeDirectory=velsigner
RuntimeDirectoryMode=0750
# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/velsigner /run/velsigner
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_PATH"

# Step 3: reload + (re)start.
log "systemctl daemon-reload"
systemctl daemon-reload

log "systemctl enable velsigner"
systemctl enable velsigner

log "systemctl restart velsigner"
systemctl restart velsigner

# Give the unit a beat to either come up or fail visibly.
sleep 1
if ! systemctl is-active --quiet velsigner; then
    printf '[install] ERROR: velsigner failed to start; check: journalctl -u velsigner -n 50\n' >&2
    exit 1
fi

log "velsigner is active"
log "done"
