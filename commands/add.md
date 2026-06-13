---
description: Register a remote server with SSHGate and auto-install the gate binary on it
argument-hint: <alias> <user@host>[:port] [--read-only|--ro]
allowed-tools: Bash, Read
---

You are registering a new server with SSHGate. The user invoked `/sshgate:add <alias> <user@host>[:port] [--read-only|--ro]`.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`. Reject otherwise with a clear error.
- `user@host[:port]` — second positional. Split on `@` and optional `:`. Port defaults to 22.
- `--read-only` (or `--ro`) — optional flag. If present, register the server in read-only mode (gate is deployed but `gate.pub` is NOT pushed; writes are denied locally at the gate).

If the required positional arguments are missing, print the argument-hint and stop. Do not prompt the user inline; this command is scriptable.

**Determine read_only.** Before calling the tool, decide whether this is a read-only deploy:

- If `--read-only`/`--ro` was passed → `read_only = true`.
- Otherwise, probe for a local signing pubkey:

```bash
test -f "${XDG_CONFIG_HOME:-$HOME/.config}/sshgate/pubkey-distrib/gate.pub" && echo "signer:yes" || echo "signer:no"
```

  - `signer:yes` → `read_only = false` (Tier-2 signed-write deploy).
  - `signer:no` → **auto-fall back to read-only.** Set `read_only = true` and tell the user verbatim:
    > "No local signer pubkey found (`~/.config/sshgate/pubkey-distrib/gate.pub` — or your $XDG_CONFIG_HOME equivalent — is absent), so '<alias>' is being deployed in read-only mode. Reads will work; writes are denied at the gate. Run /sshgate:setup to add a Telegram signer, then re-run /sshgate:add <alias> <user@host> to upgrade it to signed-write."

**Choose the bootstrap auth method.** The FIRST dial to the remote (to lay
down the gate) reuses your existing SSH access to the host. The tool requires
exactly one of `bootstrap_agent` or `bootstrap_key_path` and does NOT
auto-select between them, so this command picks the right one before calling:

```bash
if [ -n "$SSH_AUTH_SOCK" ] && ssh-add -l >/dev/null 2>&1; then
  echo "bootstrap:agent"
else
  for k in id_ed25519 id_ecdsa id_rsa; do
    [ -f "$HOME/.ssh/$k" ] && { echo "bootstrap:key:$HOME/.ssh/$k"; break; }
  done
fi
```

- `bootstrap:agent` → an ssh-agent with at least one key is loaded; pass
  `bootstrap_agent: true` and `bootstrap_key_path: ""`.
- `bootstrap:key:<path>` → no usable agent, but a default private key exists;
  pass `bootstrap_agent: false` and `bootstrap_key_path: <path>`.
- **No output at all** → no usable ssh-agent AND no default key in `~/.ssh/`.
  Do NOT call the tool. Tell the user verbatim, then stop:
  > "SSHGate needs your existing SSH access to '<host>' for the one-time gate
  > install, but found no loaded ssh-agent and no default key at
  > ~/.ssh/id_ed25519, ~/.ssh/id_ecdsa, or ~/.ssh/id_rsa. Either run
  > `ssh-add <your key>` to load the key you use to reach <host>, or place that
  > key at ~/.ssh/id_ed25519 — then re-run /sshgate:add. (SSHGate refuses key
  > files with permissions looser than 0600.)"

Then call the MCP tool `mcp__sshgate__add_server` with:
- `alias`: parsed alias
- `host`: parsed host
- `port`: parsed port (default 22)
- `user`: parsed user
- `read_only`: the value decided above
- the bootstrap method chosen above — `bootstrap_agent: true` XOR
  `bootstrap_key_path: <path>`, never both and never neither.

Surface the tool's output verbatim: the alias, fingerprint, binary path, and VerifiedOK status. If `VerifiedOK == false` or the tool returns an error, print the error clearly and tell the user that any partial state has been rolled back (the tool handles rollback internally).

On success, suggest a follow-up:

```
✓ Server '<alias>' registered.
  Fingerprint: <fp>
  Try: ask Claude to "run df -h on <alias>" or invoke sshgate.run directly.
```

Do not run the follow-up command yourself — that's the user's call.

If the bootstrap dial still fails after a method was chosen (for example the
discovered default key is not the one authorized on `<host>` — e.g. you select
a different `IdentityFile` for it in `~/.ssh/config`, or the key is
passphrase-protected and not loaded in the agent), surface the tool's error
verbatim and suggest the fix: `ssh-add <the key that reaches <host>>` to load
it into the agent, then re-run /sshgate:add. The agent path offers all your
loaded keys, so loading the correct one resolves a wrong-default-key mismatch.
