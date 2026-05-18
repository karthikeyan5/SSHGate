#!/usr/bin/env bash
# create-velsigner-user.sh — one-time provisioning of the velsigner system user.
#
# Creates:
#   - `velsigner` system user (no shell, no login)
#   - /var/lib/velsigner/{keys,tokens,config,log,bin} skeleton
#   - /run/velsigner (volatile; systemd's RuntimeDirectory will recreate on boot)
#
# Adds $SUDO_USER to the `velsigner` group so unprivileged tooling
# (audit-log readers, status probes) can stat the daemon's runtime dir
# without sudo.
#
# Idempotent: re-running on a host that already has the velsigner user
# skips the useradd step but still re-applies the directory permissions
# (cheap, and means a half-broken state can be repaired by re-running).
#
# Exit codes (per cli.md §2):
#   0  success
#   1  generic runtime failure
#   77 not root  (EX_NOPERM)
set -euo pipefail

log() { printf '[create-velsigner-user] %s\n' "$*" >&2; }
die() { printf '[create-velsigner-user] ERROR: %s\n' "$*" >&2; exit 1; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf '[create-velsigner-user] ERROR: must run as root (try: sudo %s)\n' "$0" >&2
    exit 77
fi

VELSIGNER_HOME="/var/lib/velsigner"
VELSIGNER_RUN="/run/velsigner"

# Step 1: create the system user (idempotent).
if getent passwd velsigner >/dev/null 2>&1; then
    log "user velsigner exists; skipping useradd"
else
    log "creating system user velsigner"
    useradd \
        --system \
        --shell /usr/sbin/nologin \
        --home-dir "$VELSIGNER_HOME" \
        --create-home \
        velsigner
fi

# Step 2: create the state-dir skeleton.
log "ensuring $VELSIGNER_HOME skeleton exists"
mkdir -p \
    "$VELSIGNER_HOME/keys" \
    "$VELSIGNER_HOME/tokens" \
    "$VELSIGNER_HOME/config" \
    "$VELSIGNER_HOME/log" \
    "$VELSIGNER_HOME/bin"

chown -R velsigner:velsigner "$VELSIGNER_HOME"
chmod 0750 "$VELSIGNER_HOME"
# Keys and tokens hold the signing material and bot token — tighter.
chmod 0750 "$VELSIGNER_HOME/keys" "$VELSIGNER_HOME/tokens"

# Step 3: runtime dir for the unix socket.
# Note: this is volatile (lost on reboot). The systemd unit declares
# RuntimeDirectory=velsigner so the dir is recreated with the correct
# owner/mode on every service start. We create it here too so the
# operator can run velsigner from the CLI before installing the unit.
log "ensuring $VELSIGNER_RUN exists"
mkdir -p "$VELSIGNER_RUN"
chown velsigner:velsigner "$VELSIGNER_RUN"
chmod 0750 "$VELSIGNER_RUN"

# Step 4: add the invoking user to the velsigner group so they can stat
# the runtime dir, read the audit log, etc. — without needing sudo.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    log "adding $SUDO_USER to velsigner group"
    usermod -aG velsigner "$SUDO_USER"
    log "you may need to log out and back in (or run 'newgrp velsigner') for group membership to take effect"
fi

log "done"
