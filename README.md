# SSHGate

A Claude Code plugin that lets the agent SSH into your servers to
debug or do maintenance. Read commands run freely. Write commands
need a single button-tap on your phone (via a dedicated Telegram bot)
before they execute. The signing key is isolated from the agent at
the OS level, so the agent cannot bypass the gate.

## Status

v1 — feature complete.

- [x] Phase 0 — Repo scaffolding, Go module, plugin manifest, Docker test target
- [x] Phase 1 — Cryptographic loop end-to-end (reads work, writes stub-denied)
- [x] Phase 2 — Real Telegram approval + bulk approval (`run_batch`)
- [x] Phase 3 — Auto-setup flow (`/sshgate:add`)
- [x] Phase 4 — `list_servers`, `status`, `revoke_server`, slash commands, skill, docs

## What it does

SSHGate is the front door Claude uses to operate your Linux servers.
You register each server once (`/sshgate:add prod-db user@host`), and
from then on Claude can SSH in to read state (`df -h`, `journalctl`,
`systemctl status`) without bothering you. The classifier on the
remote side knows which commands mutate state and refuses to run them
unless the SSH command carries a fresh Ed25519 signature from the
local `velsigner` daemon.

When Claude wants to write — restart a service, edit a file, install
a package — it bundles the writes (one or many) into a single sign
request to `velsigner`. `velsigner` posts the command list to your
Telegram via a dedicated bot, with `[✓ Approve all] [✗ Deny]`
buttons. One tap and Claude proceeds; deny or ignore for 60 seconds
and the request fails closed.

The plugin is the Claude-side shape of an idea designed to be
hostable on a server (v2 — see the spec). The v1 build keeps
everything on your laptop: a local daemon, a personal Telegram bot,
your own remote servers.

## Security model

The agent runs as your normal Unix user; `velsigner` runs as a
separate Unix user that owns the master Ed25519 signing key
(`/var/lib/velsigner/keys/velgate.key`, mode `0600`). Claude cannot
read that file. It cannot ptrace `velsigner` (different uid; kernel
yama blocks it). It cannot impersonate you on Telegram (Telegram
authenticates `from.id` on its servers; your user id is in the bot's
allowlist; Claude has no Telegram session). On every remote server,
the `velgate` binary verifies each signed command against
`velgate.pub` before it executes — even if `velsigner` were
compromised, the remote-side gate enforces the policy independently.
Reads are still gated: the SSH key SSHGate uses has `command=` forced
to `~/.velgate/velgate` in `authorized_keys`, so every connection
goes through the classifier. Read commands pass; write commands
without a valid signature are denied.

## Install

```bash
/plugin install sshgate
/sshgate:setup
```

`/sshgate:setup` is the guided one-time installer: it builds the Go
binaries, creates the `velsigner` system user, generates the master
key, prompts you for your @BotFather token, installs the systemd
unit, and captures your Telegram `chat_id` after you send `/start`.
It is idempotent — safe to re-run.

The full manual procedure (for users without Claude Code or who want
to read what `/sshgate:setup` does) is in
[`docs/install-step-by-step.md`](docs/install-step-by-step.md).

Requirements: Linux with systemd, Go 1.22+, `sudo`, a Telegram
account. Remote servers must be reachable over SSH and run Linux.

### macOS (laptop) support

`sshgate-mcp` and `velsigner` cross-compile to macOS — Mac users
running Claude Code can build them with `make darwin`, which produces
`bin/sshgate-mcp-darwin-{amd64,arm64}` and
`bin/velsigner-darwin-{amd64,arm64}`. `velgate` stays Linux-only
because it's deployed to remote Linux servers, not your laptop.

v1.1 macOS support is **cross-compile only**: `scripts/install.sh`
is Linux-specific (it uses `useradd`, `systemctl`, and
`/etc/systemd/system/`), so on macOS you'll currently install the
binaries by hand and write a launchd plist instead of the systemd
unit. File paths also differ — `/usr/local/bin` on Intel Macs,
`/opt/homebrew/bin` on Apple Silicon. A fully scripted macOS install
path (launchd plist template + `install-darwin.sh`) lands in v1.2.

## Usage examples

**Diagnose a full disk.**

> "prod-db is slow, can you check what's eating disk?"

Claude runs `df -h`, `du -sh /var/log/*`, `find / -size +100M -mtime
-7` directly — all reads, no Telegram pings. Surfaces the culprit in
chat. No approvals required.

**Restart a service.**

> "Restart nginx on prod-db."

Claude calls `sshgate.run prod-db "systemctl restart nginx"`. Your
phone buzzes with `[✓ Approve] [✗ Deny]`. Tap approve; the command
runs; Claude reports the result.

**Add a new server.**

```
/sshgate:add web-1 ubuntu@web-1.example.com
```

SSHGate bootstraps `velgate` onto the host (uses your existing SSH
agent for the first connection), installs the dedicated SSHGate key
with `command="..."` forcing, verifies end-to-end with a probe, and
saves the alias.

## MCP tools

| Tool                          | Description                                                                | Approval         |
|-------------------------------|----------------------------------------------------------------------------|------------------|
| `mcp__sshgate__run`           | Run a single command on a server. Read → immediate. Write → approval.      | Write only       |
| `mcp__sshgate__run_batch`     | Run multiple commands. Bulk-approval covers all writes in one tap.         | Write only, once |
| `mcp__sshgate__list_servers`  | Return registered server aliases with host/user/added_at.                  | None             |
| `mcp__sshgate__status`        | Velsigner socket reachability + per-server SSH reachability + ping ms.     | None             |
| `mcp__sshgate__add_server`    | Register a new server alias; auto-installs `velgate` on the remote.        | None (bootstrap) |
| `mcp__sshgate__revoke_server` | Sign and run `VELGATE_REVOKE`; clean up `authorized_keys` and `~/.velgate/`. | One approval     |

## Slash commands

| Command                        | Arguments                            | What it does                                                |
|--------------------------------|--------------------------------------|-------------------------------------------------------------|
| `/sshgate:setup`               | —                                    | One-time install; builds binaries, sets up velsigner + bot. |
| `/sshgate:add`                 | `<alias> <user@host>[:port]`         | Register a server; auto-installs velgate on the remote.     |
| `/sshgate:status`              | —                                    | Velsigner + per-server health report.                       |
| `/sshgate:revoke`              | `<alias>`                            | Tear down velgate on a remote; drop the alias.              |
| `/sshgate:run`                 | `<alias> <command...>`               | Explicit single-command run (Claude usually calls the tool directly). |

A skill at `skills/debugging-remote-servers/SKILL.md` activates
automatically when you ask Claude to debug or operate a registered
server — it teaches the agent the right tool order and the
bulk-approval pattern.

## License

TBD — to be selected before publish.

## Status / roadmap

- Design spec: [`docs/specs/2026-05-19-sshgate-design.md`](docs/specs/2026-05-19-sshgate-design.md)
- Implementation plan: [`docs/plans/2026-05-19-sshgate-v1-implementation.md`](docs/plans/2026-05-19-sshgate-v1-implementation.md)
- Morning review / decision log: [`docs/decisions/MORNING-REVIEW-2026-05-19.md`](docs/decisions/MORNING-REVIEW-2026-05-19.md)

v1.1 cascade: LLM command explainer in approvals, macOS desktop
support, automated velsigner user provisioning, refined pipe/chain
classification.

v2 cascade: hosted `velsigner-server` (HTTPS API, WebAuthn passkey +
TOTP, multi-operator approval, central audit log) — see the spec's
"v2 vision" section. The `velsigner` backend interface is the
swap-point; `velgate`, the MCP, and the slash commands do not change.
