# AGENTS.md — SSHGate

Tool-agnostic playbook for this Claude Code plugin / MCP server.

## What this is

SSHGate is a Claude Code plugin that lets an agent SSH into Linux servers. Reads run freely. Writes need one Telegram-button approval from the operator.

## Architecture (one-liner)

A small Go binary (`gate`) sits between OpenSSH and shell exec on each remote server. A local daemon (`signer-telegram`, running as a separate Unix user) holds the master Ed25519 signing key and asks the operator to approve writes via Telegram. The MCP server (`sshgate-mcp`) exposes tools to Claude.

## How to use this project as an agent

The setup walkthrough is in `commands/setup.md`. The main entry points:
- `/sshgate:setup` — install (one-time)
- `/sshgate:add <alias> <user@host> [--read-only]` — register a server
- `/sshgate:status` — check health
- `/sshgate:revoke <alias>` — clean removal

For debugging workflows, the active skill is `skills/debugging-remote-servers/SKILL.md`. Read it before responding to "debug X on server Y" requests.

## Tiers (read-only vs signed-write)

A server is registered either **read-only (Tier-1)** — gate deployed, no signer
pubkey, every write denied locally at the gate — or **signed-write (Tier-2)** —
a Telegram signer approves writes. `/sshgate:add … --read-only` registers Tier-1;
`/sshgate:setup` then re-`/sshgate:add` upgrades it.

- A write aimed at a read-only server is **refused before any Telegram tap** with
  an actionable upgrade path. Don't retry; run `/sshgate:setup` first.
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
