#!/usr/bin/env bash
# uninstall.sh — remove SSHGate's installed components.
#
# Always removes (idempotent — missing files are not an error):
#   - the sshgate-signer-telegram systemd unit (stopped + disabled first)
#   - /usr/local/bin/sshgate-signer-telegram
#   - /usr/local/share/sshgate/
#
# Prompts before removing (destructive — holds the master signing key
# and the audit log):
#   - /var/lib/sshgatesigner
#   - the sshgatesigner system user
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
if systemctl list-unit-files sshgate-signer-telegram.service >/dev/null 2>&1; then
    if systemctl is-active --quiet sshgate-signer-telegram; then
        log "stopping sshgate-signer-telegram"
        systemctl stop sshgate-signer-telegram || true
    fi
    if systemctl is-enabled --quiet sshgate-signer-telegram 2>/dev/null; then
        log "disabling sshgate-signer-telegram"
        systemctl disable sshgate-signer-telegram || true
    fi
fi

# Step 2: remove the unit file.
UNIT_PATH=/etc/systemd/system/sshgate-signer-telegram.service
if [ -f "$UNIT_PATH" ]; then
    log "removing $UNIT_PATH"
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
fi

# Step 3: remove the binaries.
if [ -e /usr/local/bin/sshgate-signer-telegram ]; then
    log "removing /usr/local/bin/sshgate-signer-telegram"
    rm -f /usr/local/bin/sshgate-signer-telegram
fi
if [ -d /usr/local/share/sshgate ]; then
    log "removing /usr/local/share/sshgate"
    rm -rf /usr/local/share/sshgate
fi

# Step 4: confirm before nuking state.
if [ -d /var/lib/sshgatesigner ]; then
    if [ "$PURGE" -eq 1 ]; then
        ANSWER="y"
    else
        printf '\n'
        printf '/var/lib/sshgatesigner holds the master signing key, the bot token, and the audit log.\n'
        printf 'Removing it is DESTRUCTIVE — any servers configured against this signer will need re-keying.\n'
        printf '\n'
        printf 'Remove /var/lib/sshgatesigner? [y/N] '
        read -r ANSWER
    fi
    case "${ANSWER:-N}" in
        y|Y|yes|YES)
            log "removing /var/lib/sshgatesigner"
            rm -rf /var/lib/sshgatesigner
            ;;
        *)
            log "keeping /var/lib/sshgatesigner (no state removed)"
            ;;
    esac
fi

# Step 5: remove the sshgatesigner user (only if state dir is gone — keeping
# the user around with no $HOME is a footgun).
if [ ! -d /var/lib/sshgatesigner ] && getent passwd sshgatesigner >/dev/null 2>&1; then
    if [ "$PURGE" -eq 1 ]; then
        ANSWER="y"
    else
        printf 'Remove sshgatesigner system user? [y/N] '
        read -r ANSWER
    fi
    case "${ANSWER:-N}" in
        y|Y|yes|YES)
            log "removing sshgatesigner user"
            userdel sshgatesigner || true
            ;;
        *)
            log "keeping sshgatesigner user"
            ;;
    esac
fi

# Step 6: clean the volatile runtime dir if still around (systemd usually
# tears this down when the unit is removed; belt-and-braces).
if [ -d /run/sshgatesigner ]; then
    log "removing /run/sshgatesigner"
    rm -rf /run/sshgatesigner
fi

log "done"
