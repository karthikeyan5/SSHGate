# SSHGate

A Claude Code plugin that lets the agent SSH into your Linux servers. Reads run freely. Writes need one tap on your phone.

---

## The problem

When an AI agent needs to diagnose a remote server, the workflow today is a relay. The human SSHes in, runs a command, pastes the output back into the chat. The agent reads it, asks for the next command. The human SSHes again. Twenty round-trips later, the agent has a guess at what's wrong. The agent could have done this in seconds on its own.

The reason it doesn't is that full SSH access for an agent is dangerous. `rm -rf` on the wrong path, an accidental `truncate`, a supply-chain compromise of the agent's runtime, a hallucinated `systemctl stop` — any of these on a production server is a bad day. The human stays in the loop not to be useful, but to be a gate.

The right shape is a gate that doesn't waste the human's time. Diagnostics flow through automatically. Anything that mutates state pauses for an explicit human "yes."

---

## SSHGate solves this

SSHGate puts a small binary on every remote server that classifies each incoming command and enforces the gate:

```
read command              → execute
write command + signature → verify → execute
write command, no sig     → deny
```

Three lines of logic. The signing key is held by a separate Unix user the agent cannot read from, and it only signs after you tap "approve" on Telegram. The agent never holds the key. The human never types another shell command.

---

## Three components

**gate** (`sshgate-gate`) — the remote-side Go binary. ~500 LOC. Lives at `~/.sshgate-gate/gate` on each server you register. OpenSSH calls it via `command="..."` forcing in `authorized_keys`, so every connection on the SSHGate key routes through it. gate classifies the command, verifies the `SSHGATE_SIG:` prefix if present, and runs or denies. The classifier is compiled in; gate stores no config.

**signer-telegram** (`sshgate-signer-telegram`) — the local approval daemon on your laptop. Runs as a separate Unix user (`sshgatesigner`) so Claude — running as you — cannot read its key file, ptrace its process, or read its Telegram bot token. When a write arrives, signer-telegram DMs you on a dedicated Telegram bot with the command list and Approve/Deny buttons; it signs only after your tap, and only if Telegram's `from.id` matches the allowlisted user.

**MCP server** (`sshgate-mcp`) — the Claude Code plugin half. Exposes `run`, `run_batch`, `add_server`, `list_servers`, `status`, and `revoke_server` as MCP tools. Reads SSH directly; writes go to signer-telegram first for approval, then SSH the signed command across.

---

## What you get

- Ask Claude to debug a server in plain English. Reads stream back instantly with no approval friction. "What's eating disk on prod-db" becomes one chat turn instead of fifteen.
- Restart services, install packages, edit configs with one tap on your phone. Your laptop and your phone are the two trust domains; the agent is neither.
- Bulk-approve a sequence of writes in one tap. Claude queues `apt update && apt install nginx && systemctl enable nginx && systemctl start nginx` as a single approval. Each command is still individually signed for audit; the "bulk" is purely the UI.
- Register a new server in one slash command: `/sshgate:add prod-db ubuntu@prod-db.example.com`. The plugin auto-installs gate, lays in the restricted `authorized_keys` entry, and verifies end-to-end with a probe.
- Your master signing key never sits in the same trust domain as the agent. The agent can request signatures; it cannot produce them.

---

## Three tiers of setup

`/sshgate:setup` is tiered and idempotent. Start with the lightest tier that meets your needs; you can upgrade later without tearing anything down.

**Tier 1 — Read-only.** gate is deployed to every remote, but no signing key is uploaded. Reads work; writes are denied at the gate. No Telegram bot, no signer daemon, no sudo. Fastest install. Recommended for the first run while you decide whether you want write access at all.

**Tier 2 — Local Telegram signer.** The full v1 install. Master keypair under the `sshgatesigner` system user, signer-telegram systemd unit, dedicated Telegram bot for approvals. Writes require a phone tap. This is the default for daily use.

**Tier 3 — Hosted server.** Not yet available. Reserved for the v2 architecture (hosted `sshgate-signer-server` with WebAuthn + TOTP web auth, multi-operator approval rules, central audit). The signer-telegram backend interface is the swap point; gate, the MCP, and the slash commands stay the same.

---

## Install

SSHGate is a Claude Code plugin. Anthropic-marketplace publication is on the v1.x roadmap; until then, install from a local clone.

> **Launch Claude Code normally with `claude`.** SSHGate does NOT require `--dangerously-load-development-channels`. That flag is for plugins (like c3) that push notifications INTO Claude's context. SSHGate only uses standard MCP tool calls; its approvals flow OUT to your phone via Telegram, not into the conversation.

**The 30-second install.** In any Claude Code session, paste:

```
follow https://github.com/karthikeyan5/SSHGate/blob/main/INSTALL.md to install sshgate
```

The agent clones the repo, registers it as a local marketplace, installs the plugin, and walks you through `/sshgate:setup`. You'll be asked for sudo (Tier 2 only) and a Telegram bot token (Tier 2 only). The whole flow is ~2 minutes for Tier 1, ~10 minutes for Tier 2.

**Manual install.** Clone the repo, then in Claude Code:

```
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
/reload-plugins
/sshgate:setup
```

`/sshgate:setup` walks you through Tier 1 first (read-only), and offers the Tier 2 upgrade in the same flow when you're ready. It probes on-disk state on every run, so re-running it is safe.

Full step-by-step (for users without Claude Code, or anyone who wants to read what `/sshgate:setup` does under the hood): [`docs/install-step-by-step.md`](docs/install-step-by-step.md).

Requirements: Linux with systemd, Go 1.22+, sudo (for Tier 2 only), a Telegram account (for Tier 2 only). Remote servers must be reachable over SSH and run Linux.

macOS: cross-compile only in v1.x; native install path is v1.2. See [the install guide](docs/install-step-by-step.md#macos-users) for status.

---

## Usage examples

**Read — no approval.**

> "What's eating disk on prod-db?"

Claude calls `sshgate.run("prod-db", "df -h")`, then `du -sh /var/log/*`, then `find /var -size +100M`. All three are reads. They stream back into chat with no Telegram pings. Claude surfaces the culprit.

**Single write — one tap.**

> "Restart nginx on prod-db."

Claude calls `sshgate.run("prod-db", "systemctl restart nginx")`. Your phone buzzes with:

```
SSHGate approval — prod-db
1. systemctl restart nginx

[Approve]   [Deny]
```

Tap approve. The command runs. Claude reports the result.

**Bulk write — one tap for four commands.**

> "Update the nginx config and restart it."

Claude calls `sshgate.run_batch("prod-db", [...])` with four commands. Your phone buzzes once:

```
SSHGate approval — prod-db
4 commands queued:
1. cat > /etc/nginx/sites-available/app.conf <<'EOF' ...
2. nginx -t
3. systemctl reload nginx
4. systemctl status nginx

[Approve all]   [Deny]
```

Tap approve. All four run in order. If any fails, the rest stop.

---

## What SSHGate is NOT

- Not a replacement for SSH. It sits on top of SSH.
- Not a configuration management tool (Ansible, Chef, Puppet). It runs the commands you (or the agent) write; it does not own desired state.
- Not a full access proxy (Teleport, StrongDM). No session recording, no MFA at the SSH layer, no SSO, no per-user RBAC.
- Not a secret manager. It gates commands, not credentials.
- Not a multi-operator approval system in v1. One operator, one phone, one Telegram DM. Multi-operator is a v2 feature.

---

## Status

v1 + v1.1 shipped. Three audit gates clean (code review, PII, security), plus a Docker-backed integration suite. All four phases of the v1 plan landed: cryptographic loop, real Telegram approval with bulk, auto-setup of new servers, the polish layer (list/status/revoke + skill + slash commands).

v2 scaffold is wired but not deployable. The hosted `sshgate-signer-server` exists as an HTTP service with SQLite state and a swap-point client backend; the signer daemon can already route through it via one config change. What's missing for v2 to be usable: WebAuthn passkey + TOTP auth on the web UI, a web UI at all, and multi-operator approval logic. Tracked in `src/signer-server/README.md`.

- Design spec: [`docs/specs/2026-05-19-sshgate-design.md`](docs/specs/2026-05-19-sshgate-design.md)
- Implementation plan: [`docs/plans/2026-05-19-sshgate-v1-implementation.md`](docs/plans/2026-05-19-sshgate-v1-implementation.md)
- Morning review / decision log: [`docs/decisions/MORNING-REVIEW-2026-05-19.md`](docs/decisions/MORNING-REVIEW-2026-05-19.md)

---

## Architecture

Full diagram, trust-domain breakdown, wire protocol, and threat model: [`docs/specs/2026-05-19-sshgate-design.md`](docs/specs/2026-05-19-sshgate-design.md).

Short version: three trust domains — your user (runs Claude + the MCP, holds the SSH client key), the `sshgatesigner` user (runs signer-telegram, holds the master signing key + bot token), and Telegram (authenticates your phone). Each remote server runs gate as the only thing the SSHGate SSH key can invoke, enforced by OpenSSH's `command=` forcing. Reads pass; writes need a fresh Ed25519 signature from signer-telegram, which signer-telegram only produces after a verified phone tap.

---

## License

MIT — see `LICENSE`.
