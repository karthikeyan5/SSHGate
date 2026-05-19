# CLAUDE.md — SSHGate

The cross-tool source of truth is `AGENTS.md`. Read it now — Codex and any other agent that supports `AGENTS.md` reads the same file, so keep tool-agnostic rules there, not here.

## SSHGate-specific notes for Claude Code

This is a Claude Code plugin. The tool surface (MCP) is:

- `sshgate.run(alias, command)` — run one command on a registered server
- `sshgate.run_batch(alias, commands[])` — run several commands; writes bulk-approve in one Telegram tap
- `sshgate.add_server(alias, user, host, port?, read_only?)` — register and auto-setup a new server
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

## When to escalate to the user

- If `sshgate.add_server` fails the verify step → STOP, ask the user to check the host's `/var/log/auth.log` and the bootstrap SSH credentials.
- If `sshgate.status` shows the signer socket unreachable → STOP, suggest `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`.
- If a write is denied by the user via Telegram → DO NOT re-submit. Ask why; propose alternatives.
