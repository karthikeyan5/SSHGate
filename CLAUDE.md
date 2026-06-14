# CLAUDE.md — SSHGate

The cross-tool source of truth is `AGENTS.md`. Read it now — Codex and any other agent that supports `AGENTS.md` reads the same file, so keep tool-agnostic rules there, not here.

## SSHGate-specific notes for Claude Code

This is a Claude Code plugin. The tool surface (MCP) is:

- `sshgate.run(alias, command)` — run one command on a registered server
- `sshgate.run_batch(alias, commands[])` — run several commands; writes bulk-approve in one Telegram tap
- `sshgate.add_server(alias, host, user, port?, read_only?, {bootstrap_key_path | bootstrap_agent})` — register and auto-setup a new server. Exactly one bootstrap method is required: `bootstrap_key_path` (an existing private key, mode 0600) or `bootstrap_agent=true` (ssh-agent via `$SSH_AUTH_SOCK`). `read_only=true` deploys gate without a signer pubkey (Tier-1).
- `sshgate.list_servers()` — list registered aliases
- `sshgate.status()` — health of the signer + reachability of each server
- `sshgate.revoke_server(alias)` — uninstall gate from a server (requires Telegram approval)

When the user asks to debug, diagnose, or operate a remote server:
1. Start with `sshgate.list_servers` to confirm the alias is registered.
2. For diagnostics, use `sshgate.run` with read commands (df -h, top -bn1, journalctl). No approval prompt.
3. For fixes, queue writes into `sshgate.run_batch` so the user approves all in ONE Telegram tap.
4. ALWAYS show the user the list of planned writes before calling run_batch.
5. After fixes, re-run a read health check.

See `skills/debugging-remote-servers/SKILL.md` for the full skill.

## Tiers, read-only servers, and write denials

A server is registered either **read-only (Tier-1)** or **signed-write (Tier-2)**.
`sshgate.list_servers` does not surface the flag directly; check `sshgate.status`
and the error messages below.

- **Writes to a read-only server are refused locally, BEFORE any Telegram tap.**
  `sshgate.run`/`sshgate.run_batch` return an error like `server "<alias>" is
  registered read-only — writes are denied at the gate (no signer pubkey was
  pushed)`. Do NOT retry — the fix is `/sshgate:setup` (add a Telegram signer)
  then re-run `/sshgate:add <alias> <user@host>` to upgrade it to signed-write.
- **Gate deny exit codes** come back annotated, not bare:
  - **exit 77** — missing signature OR the host has no signer pubkey
    (read-only / Tier-1). Check `sshgate.status`; if the signer is not
    configured, run `/sshgate:setup` then re-`/sshgate:add` to upgrade.
  - **exit 65** — bad/expired signature, usually clock skew or a stale
    approval. Retry once.

## When to escalate to the user

- If `sshgate.add_server` fails the verify step → STOP, ask the user to check the host's `/var/log/auth.log` and the bootstrap SSH credentials.
- If a write fails with a **signer-permission** error (`signer socket … is present
  but not accessible (permission denied) — your shell/session is not yet in the
  sshgatesigner group`) → STOP. This is NOT a dead daemon. The user (or the agent
  that just ran `/sshgate:setup`) must **fully quit and relaunch Claude Code after
  a logout/login** so the session picks up `sshgatesigner` group membership.
  After relaunch, run `/mcp` to confirm the `sshgate` server is live, then retry.
- If `sshgate.status` shows the signer socket **UNREACHABLE** *and* `configured:true`
  (socket file present, dial failed) → STOP, suggest `systemctl status
  sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.
  If `status` shows `configured:false` / "not configured", that is the NORMAL
  Tier-1 read-only state — not a fault. Writes are simply unavailable until
  `/sshgate:setup` adds a signer.
- After `/sshgate:setup` (first signer install) the full sequence is mandatory:
  log out/in for the group to take effect, **restart Claude Code**, run `/mcp` to
  confirm the `sshgate` MCP server is live, then writes will work.
- If a write is denied by the user via Telegram → DO NOT re-submit. Ask why; propose alternatives.
