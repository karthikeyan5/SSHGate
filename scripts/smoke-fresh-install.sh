#!/usr/bin/env bash
# smoke-fresh-install.sh — fresh-user regression smoke for SSHGate.
#
# Proves the MCP server STARTS on a machine with no config and no SSH key
# (the Tier-1 read-only first-run state) instead of hard-exiting and taking
# the whole tool surface down with it. This is the headless guard for the
# chicken-and-egg bug fixed in `fix(mcp): start server without SSH key ...`:
# Claude Code spawns sshgate-mcp at /reload-plugins, which runs BEFORE
# /sshgate:setup creates the key, so a server that refused to start keyless
# left a fresh read-only user with a dead tool surface.
#
# Run via `make smoke` or as part of `make e2e`. See docs/E2E-TEST-STRATEGY.md.
set -euo pipefail
cd "$(dirname "$0")/.."

bindir="$(mktemp -d)"
bin="$bindir/sshgate-mcp"
go build -o "$bin" ./src/mcp/cmd/sshgate-mcp

th="$(mktemp -d)"           # a pristine HOME: no ~/.config/sshgate, no key
err="$th/stderr.log"
cleanup() { rm -rf "$bindir" "$th"; }
trap cleanup EXIT

# Empty stdin -> immediate EOF -> the server should start, log "ready", and
# shut down cleanly (exit 0). Pre-fix it logged "ssh key: ... does not exist"
# and returned 1 WITHOUT ever reaching "ready".
if ! HOME="$th" SSHGATE_SIGNER_SOCK=/run/sshgatesigner/sock "$bin" </dev/null >/dev/null 2>"$err"; then
	echo "SMOKE FAIL: keyless sshgate-mcp exited non-zero (dead tool surface for fresh users)" >&2
	cat "$err" >&2
	exit 1
fi
if ! grep -q "ready" "$err"; then
	echo "SMOKE FAIL: keyless sshgate-mcp did not reach 'ready' — it would not serve tools on a fresh install" >&2
	cat "$err" >&2
	exit 1
fi

echo "smoke: keyless MCP startup OK (server reaches 'ready' with no key; tool surface stays alive)"
