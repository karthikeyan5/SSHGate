---
description: Register a remote server with SSHGate and auto-install the gate binary on it
argument-hint: <alias> <user@host>[:port] [--read-only|--ro]
allowed-tools: Bash, Read
---

You are registering a new server with SSHGate. The user invoked `/sshgate:add <alias> <user@host>[:port] [--read-only|--ro]`.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`. Reject otherwise with a clear error.
- `user@host[:port]` — second positional. Split on `@` and optional `:`. Port defaults to 22.
- `--read-only` (or `--ro`) — optional flag. If present, register the server in read-only mode (gate is deployed but `gate.pub` is NOT pushed; writes are denied locally at the gate). Default is read-write (gate.pub is pushed, writes require Telegram approval).

If the required positional arguments are missing, print the argument-hint and stop. Do not prompt the user inline; this command is scriptable.

Then call the MCP tool `mcp__sshgate__add_server` with:
- `alias`: parsed alias
- `host`: parsed host
- `port`: parsed port (default 22)
- `user`: parsed user
- `read_only`: `true` if `--read-only`/`--ro` was passed, else `false`
- `bootstrap_agent`: true (use the user's ssh-agent if `SSH_AUTH_SOCK` is set)
- `bootstrap_key_path`: empty (let the tool fall back if no agent)

Surface the tool's output verbatim: the alias, fingerprint, binary path, and VerifiedOK status. If `VerifiedOK == false` or the tool returns an error, print the error clearly and tell the user that any partial state has been rolled back (the tool handles rollback internally).

On success, suggest a follow-up:

```
✓ Server '<alias>' registered.
  Fingerprint: <fp>
  Try: ask Claude to "run df -h on <alias>" or invoke sshgate.run directly.
```

Do not run the follow-up command yourself — that's the user's call.

If the user's SSH agent is not running and they have no key at a standard location (e.g. `~/.ssh/id_ed25519`), the bootstrap leg will fail with a clear error from the tool. Surface that error and suggest `ssh-add ~/.ssh/id_ed25519` to start the agent.
