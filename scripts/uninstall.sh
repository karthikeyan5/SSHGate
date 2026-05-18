#!/usr/bin/env bash
# uninstall.sh — remove SSHGate's installed components.
#
# Always removes (idempotent — missing files are not an error):
#   - the velsigner systemd unit (stopped + disabled first)
#   - /usr/local/bin/velsigner
#   - /usr/local/share/sshgate/
#
# Prompts before removing (destructive — holds the master signing key
# and the audit log):
#   - /var/lib/velsigner
#   - the velsigner system user
#
# Pass --purge to skip the prompts and wipe everything.
#
# Exit codes (per cli.md §2):
#   0  success (including "user said no to the destructive parts")
#   1  generic runtime failure
#   77 not root  (EX_NOPERM)
set -euo pipefail

log() { printf '[uninstall] %s\n' "$*" >&2; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf '[uninstall] ERROR: must run as root (try: sudo %s)\n' "$0" >&2
    exit 77
fi

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

# Step 1: stop + disable the unit.
if systemctl list-unit-files velsigner.service >/dev/null 2>&1; then
    if systemctl is-active --quiet velsigner; then
        log "stopping velsigner"
        systemctl stop velsigner || true
    fi
    if systemctl is-enabled --quiet velsigner 2>/dev/null; then
        log "disabling velsigner"
        systemctl disable velsigner || true
    fi
fi

# Step 2: remove the unit file.
UNIT_PATH=/etc/systemd/system/velsigner.service
if [ -f "$UNIT_PATH" ]; then
    log "removing $UNIT_PATH"
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
fi

# Step 3: remove the binaries.
if [ -e /usr/local/bin/velsigner ]; then
    log "removing /usr/local/bin/velsigner"
    rm -f /usr/local/bin/velsigner
fi
if [ -d /usr/local/share/sshgate ]; then
    log "removing /usr/local/share/sshgate"
    rm -rf /usr/local/share/sshgate
fi

# Step 4: confirm before nuking state.
if [ -d /var/lib/velsigner ]; then
    if [ "$PURGE" -eq 1 ]; then
        ANSWER="y"
    else
        printf '\n'
        printf '/var/lib/velsigner holds the master signing key, the bot token, and the audit log.\n'
        printf 'Removing it is DESTRUCTIVE — any servers configured against this signer will need re-keying.\n'
        printf '\n'
        printf 'Remove /var/lib/velsigner? [y/N] '
        read -r ANSWER
    fi
    case "${ANSWER:-N}" in
        y|Y|yes|YES)
            log "removing /var/lib/velsigner"
            rm -rf /var/lib/velsigner
            ;;
        *)
            log "keeping /var/lib/velsigner (no state removed)"
            ;;
    esac
fi

# Step 5: remove the velsigner user (only if state dir is gone — keeping
# the user around with no $HOME is a footgun).
if [ ! -d /var/lib/velsigner ] && getent passwd velsigner >/dev/null 2>&1; then
    if [ "$PURGE" -eq 1 ]; then
        ANSWER="y"
    else
        printf 'Remove velsigner system user? [y/N] '
        read -r ANSWER
    fi
    case "${ANSWER:-N}" in
        y|Y|yes|YES)
            log "removing velsigner user"
            userdel velsigner || true
            ;;
        *)
            log "keeping velsigner user"
            ;;
    esac
fi

# Step 6: clean the volatile runtime dir if still around (systemd usually
# tears this down when the unit is removed; belt-and-braces).
if [ -d /run/velsigner ]; then
    log "removing /run/velsigner"
    rm -rf /run/velsigner
fi

log "done"
