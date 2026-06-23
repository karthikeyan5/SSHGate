# AGENTS.md — SSHGate

Tool-agnostic playbook for this Claude Code plugin / MCP server.

## What this is

SSHGate is a Claude Code plugin that lets an agent SSH into Linux servers. Reads run freely. Writes need one Telegram-button approval from the operator.

## Architecture (one-liner)

A small Go binary (`gate`) sits between OpenSSH and shell exec on each remote server. A local daemon (`signer-telegram`, running as a separate Unix user) holds the master Ed25519 signing key and asks the operator to approve writes via Telegram. The MCP server (`sshgate-mcp`) exposes seven tools to Claude (`run`, `run_batch`, `list_servers`, `status`, `revoke_server`, `request_grant`, `revoke_grant`). Provisioning a server is a human-only `sshgate` CLI — deliberately off the agent surface so the agent can't expand its own reach.

## How to use this project as an agent

The setup walkthrough is in `commands/setup.md`. The main entry points:
- `/sshgate:setup` — install (one-time)
- `/sshgate:status` — check health
- `/sshgate:revoke <alias>` — clean removal

**Provisioning is a human-only CLI, not a slash command and not an agent tool.**
A human registers a server with the `sshgate` binary (installed to
`~/go/bin/sshgate` by `make install-local`):
- `sshgate pubkey` — print SSHGate's dedicated public-key line.
- The human pastes that line into the target's `~/.ssh/authorized_keys`.
- `sshgate add <alias> <user@host>[:port] [--read-only]` — install the gate and
  lock that key down to the forced command. `--read-only` registers Tier-1.

The agent has no way to add a server. If asked, point the user at these CLI steps.

For debugging workflows, the active skill is `skills/debugging-remote-servers/SKILL.md`. Read it before responding to "debug X on server Y" requests.

## Tiers (read-only vs signed-write)

A server is provisioned either **read-only (Tier-1)** — gate deployed, no signer
pubkey, every write denied locally at the gate — or **signed-write (Tier-2)** —
a Telegram signer approves writes. `sshgate add … --read-only` registers Tier-1;
`sshgate add` (no flag) registers Tier-2 (`gate.pub` present = signed-write,
absent = read-only). To change a server's tier today, a human runs
`/sshgate:revoke <alias>` (its Telegram approval is kept) and re-provisions with
`sshgate add` at the desired tier (`/sshgate:setup` first if no signer exists).
A smoother in-place upgrade is planned (roadmap #17).

- A write aimed at a read-only server is **refused before any Telegram tap**.
  Don't retry; surface the re-provision path above (the agent can't do it).
- Gate denials surface as annotated errors: **exit 77** = missing signature /
  read-only host; **exit 65** = bad/expired signature (clock skew, stale approval).

## Operator constraints

- Treat Telegram-denial as final; do NOT loop on denials.
- Show the user the planned writes BEFORE soliciting bulk approval.
- Never log MCP tool args containing user-supplied secrets to stdout.
- After the FIRST `/sshgate:setup` (signer install): the operator must log out/in
  for `sshgatesigner` group membership, then **restart Claude Code** and run `/mcp`
  to confirm the `sshgate` server is live before writes work. A "signer socket
  permission denied" error means this step was skipped — it is NOT a dead daemon.
