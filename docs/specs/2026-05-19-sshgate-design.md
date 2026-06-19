# SSHGate — Design Spec v1.0

**Date:** 2026-05-19
**Author:** Ram (Claude) & Karthi
**Status:** Approved for v1 implementation
Superseded in part by [2026-06-18-signer-approval-architecture.md](../decisions/2026-06-18-signer-approval-architecture.md) (2026-06-18): the human approval window is now 300s/5 min, and approvals may route through the user's existing c3 (Tier 1) — "no c3 coupling" is no longer a principle.
**Supersedes:** VelGate Spec v1.0 (2026-03-29) — this document is the Claude Code adaptation; the prior spec was for the larger "Vel" product with a hosted dashboard.

---

## One-liner

A Claude Code plugin that lets the agent SSH into Karthi's servers to debug or do maintenance. Read commands run freely. Write commands need a single button-tap on Karthi's phone (via a dedicated Telegram bot) before they execute. The signing key is isolated from the agent at the OS level, so the agent cannot bypass the gate.

---

## How this differs from the VelGate spec

The original VelGate spec assumed a larger product ("Vel") that owns the master signing key, runs a dashboard with an approval queue, and is operated by humans through a web UI. For Claude Code adoption we collapse those roles:

| VelGate concept | SSHGate equivalent |
|---|---|
| "Vel instance" (hosted service holding master key) | Local **signer** daemon (separate OS user) on Karthi's laptop |
| "Vel dashboard approval queue" | **Telegram DM** with a dedicated signer-bot |
| Vel-to-Vel API mode | Out of scope (Karthi is the only operator) |
| Audit log / dashboard history | Claude Code transcript + Telegram chat history |
| Delegation tokens | Out of v1 (deferred indefinitely; not needed for single-operator) |
| Shared terminal (tmux) mode | Deferred to v2 |

The remote-side `gate` binary stays exactly as-spec'd — same classifier, same Ed25519 verification, same `command="~/.sshgate-gate/gate"` auto-setup, same revocation. SSHGate is a different *front end* to the same gate.

---

## Threat model

The load-bearing question: **can the LLM bypass the approval flow on its own?**

In the naive design where the MCP server holds the signing key in `~/.config/sshgate/gate.key` (mode 0600, owned by karthi), the answer is yes:

1. Claude Code runs as user `karthi`
2. Claude can `cat ~/.config/sshgate/gate.key`
3. Claude can shell out to `openssl` or write a few lines of Go/Node to forge a `SSHGATE_SIG:...` blob for any command
4. gate on the remote verifies the signature, sees it's valid, runs the write
5. `AskUserQuestion` to the human is theater — Claude never had to invoke it

The cryptographic gate's whole purpose is to enforce "approver ≠ runner." If they're the same OS user, the gate is local-only and trivially bypassed.

**SSHGate's solution:** OS-level user separation. The signing key lives under a separate Unix user (`sshgate-signer-telegram`), 0600 perms, in a directory Claude (running as `karthi`) cannot read. The signer daemon performs all signing operations and only signs after receiving an authenticated approval from Karthi via a channel Claude does not control.

The chosen approval channel is a dedicated Telegram bot in DM with Karthi. Telegram authenticates `from.id` at the protocol level — Claude has no Telegram identity tied to Karthi's user_id (`12345678`) and no path to obtain one (Telegram account auth requires phone + 2FA, not on Karthi's laptop). signer enforces `from.id == 12345678` on every approval callback.

### What Claude can still do (acceptable)

- Read commands directly (gate auto-allows them; no signing needed). This is the *intent* of the design.
- Request approvals for writes. Each request shows up in Karthi's Telegram DM. Karthi taps approve or deny. If Karthi disapproves or ignores, no write happens.
- Talk to signer over the local Unix socket — but signer won't sign without the user's tap.

### What Claude cannot do

- Read the signing key file (different Unix user, 0600 perms).
- Read signer's process memory (different Unix user; modern Linux blocks `ptrace` across users by default via `kernel.yama.ptrace_scope=1`).
- Impersonate Karthi on Telegram (no Telegram session; Telegram authenticates `from.id` on its servers).
- Tamper with signer-bot's traffic (signer-bot has its own bot token, owned by sshgatesigner user, separate from any other bot on the laptop).
- Bypass the remote-side gate (gate on each server enforces classification + signature verification independently).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ Karthi's laptop                                                      │
│                                                                      │
│  ┌─────────────────────┐         ┌──────────────────────────┐        │
│  │ Claude Code         │  Unix   │ signer daemon         │        │
│  │ (user: karthi)      │ socket  │ (user: signer)        │        │
│  │  ┌────────────────┐ │ ──────► │ - owns gate.key       │        │
│  │  │ SSHGate MCP    │ │  sign() │ - owns SSH client key    │        │
│  │  │ - Go binary    │ │         │ - owns signer-bot tok │        │
│  │  │ - signs via    │ │         │ - posts approval to TG   │        │
│  │  │   signer    │ │         │ - polls TG for callback  │        │
│  │  │ - SSH client   │ │         │ - verifies from.id       │        │
│  │  └────────────────┘ │         │ - returns signatures     │        │
│  └─────────┬───────────┘         └──────────────┬───────────┘        │
│            │                                    │                    │
│            │ SSH (signed writes,                │ Telegram Bot API   │
│            │      unsigned reads)               │ (DM with Karthi)   │
└────────────┼────────────────────────────────────┼────────────────────┘
             │                                    │
             ▼                                    ▼
   ┌──────────────────┐                  ┌─────────────────┐
   │ Remote server    │                  │ Karthi's phone  │
   │ ~/.sshgate-gate/      │                  │ Telegram client │
   │   gate (bin)  │                  │ [Approve all]   │
   │   gate.pub    │                  │ [Deny]          │
   └──────────────────┘                  └─────────────────┘
```

Three trust domains:

1. **karthi user** — runs Claude Code and the SSHGate MCP. Has SSH client key. Can read/write its own files. Cannot read signer's files.
2. **signer user** — runs signer daemon. Owns master signing key + bot token. Cannot SSH out (no SSH key in this domain unless we choose to put it here; see "SSH key placement" below). Only communicates with karthi via a Unix socket on which it accepts a narrow protocol.
3. **Telegram** — Karthi's phone, authenticated by Telegram. Sends approve/deny callbacks for specific request IDs.

---

## Components

### 1. gate (remote binary, Go)

Same as the original VelGate spec. Single Go binary, ~500 LOC. Lives at `~/.sshgate-gate/gate` on each remote server. Triggered by SSH `command=` forcing. Classifies the incoming command (read/write), verifies the `SSHGATE_SIG:` prefix if present, executes or denies.

No changes from spec §"Command Classification" and §"Signature Scheme" sections, except:
- v1 pipe handling: any pipe → treated as write (per spec's "Not in v1" note)
- Time-scoped tokens ("Dangerous Mode" in spec): **out of v1.** Bulk approval covers most batch-ops use cases at the UX layer.

### 2. signer daemon (Go, separate OS user)

New component. ~500-700 LOC of Go.

**Responsibilities:**
- Owns master Ed25519 signing key for gate (`/var/lib/sshgatesigner/keys/gate.key`, 0600, owned by `sshgate-signer-telegram`)
- Owns signer-bot's Telegram token (`/var/lib/sshgatesigner/tokens/telegram.token`, 0600)
- Listens on Unix socket `/run/sshgatesigner/sock` (created at daemon start, group-readable by `karthi` via the `sshgatesigner` group)
- Implements abstract `Backend` interface for the approval channel (today: `TelegramBackend`; future: `HostedServerBackend`)
- On sign request: generates request ID, posts approval message to Telegram, awaits callback, verifies `from.id`, signs each command in the request

**Wire protocol (Unix socket, JSON lines):**

Request from MCP:
```json
{
  "kind": "sign",
  "request_id": "r_a1b2c3d4",
  "commands": [
    {"server": "prod-db", "cmd": "systemctl restart nginx", "ttl_seconds": 60},
    {"server": "prod-db", "cmd": "apt install -y certbot", "ttl_seconds": 60}
  ]
}
```

Response from signer:
```json
{
  "request_id": "r_a1b2c3d4",
  "status": "approved",
  "signatures": [
    {"cmd": "systemctl restart nginx", "sig": "SSHGATE_SIG:..."},
    {"cmd": "apt install -y certbot", "sig": "SSHGATE_SIG:..."}
  ]
}
```

Or:
```json
{"request_id": "r_a1b2c3d4", "status": "denied"}
{"request_id": "r_a1b2c3d4", "status": "timeout"}
```

**Backend interface (Go):**

```go
type Backend interface {
    // PostApprovalRequest sends the request to the approval channel
    // and returns a result channel that yields the outcome.
    PostApprovalRequest(ctx context.Context, req ApprovalRequest) (<-chan ApprovalResult, error)
}

type TelegramBackend struct {
    BotToken    string
    AllowedUserID int64  // 12345678
    Chat        ChatStore  // remembers the user's DM chat_id once they /start
}
```

The abstract `Backend` interface is the seam that lets v2's HostedServerBackend drop in without changing signer's core or the MCP.

### 3. SSHGate MCP server (Go)

New component. ~600-900 LOC of Go.

**Responsibilities:**
- Reads server registry from `~/.config/sshgate/servers.json`
- Owns the dedicated SSH client key (`~/.config/sshgate/ssh/sshgate_ed25519`, 0600, owned by `karthi`)
- Exposes MCP tools to Claude (see §"MCP tool surface")
- For read commands: SSHes immediately, returns output
- For write commands: builds a sign request, sends to signer via socket, waits for response, then SSHes the signed command, returns output
- Bulk approval: when Claude queues N writes, all go into a single sign request (one Telegram tap covers all N)

**MCP tool surface:**

| Tool | Description |
|---|---|
| `sshgate.list_servers` | Return registered server aliases + connection status |
| `sshgate.run` | Run a single command on a server. Read → immediate. Write → request approval, then run. |
| `sshgate.run_batch` | Run multiple commands on one or more servers. Writes bulk-approve together. |
| `sshgate.add_server` | Register a new server alias. Triggers auto-setup. |
| `sshgate.revoke_server` | Remove gate from a server. Cleans up `authorized_keys` and `~/.sshgate-gate/`. |
| `sshgate.status` | Health of signer socket, server reachability, last-used timestamps |

### 4. signer-bot (Telegram bot, DM-only)

New Telegram bot. Created via @BotFather. Token lives at `/var/lib/sshgatesigner/tokens/telegram.token` (0600 owned by sshgatesigner).

**Setup flow:**
1. Karthi creates the bot via @BotFather, gets token
2. `/sshgate:setup` writes the token to `/var/lib/sshgatesigner/tokens/telegram.token` (via a privileged helper or initial sudo step during install)
3. Karthi opens the bot in Telegram and sends `/start`
4. signer captures the chat_id and user_id from that interaction, stores them in `/var/lib/sshgatesigner/config/peer.json` (also 0600)
5. From this point, signer only DMs that chat_id and only accepts callbacks where `from.id == stored user_id`

No groups. No supergroups. No c3 coupling. Just signer talking directly to Karthi via a one-on-one bot DM. (Superseded: the dedicated-bot DM is still the current same-machine implementation, but "no c3 coupling" is no longer a principle — Tier 1 may route via the user's existing c3. See the 2026-06-18 approval-architecture doc.)

**Approval message shape:**

```
🔐 SSHGate approval — prod-db

3 commands queued:
1. systemctl restart nginx
2. apt install -y certbot
3. certbot --nginx -d example.com

Request ID: r_a1b2c3
Expires in 5m

[✓ Approve all]   [✗ Deny]
```

The inline keyboard buttons post `callback_data` like `approve:r_a1b2c3` or `deny:r_a1b2c3`. signer verifies:
- `from.id == 12345678`
- `request_id` matches a pending request that hasn't expired
- Request hasn't been previously resolved (one-shot)

Then signs each command and returns signatures to the MCP via the socket.

### 5. SSHGate Claude Code plugin scaffold

The user-facing wrapper. Directory layout:

```
SSHGate/
  plugin.json                  # plugin manifest
  .mcp.json                    # registers the Go MCP binary
  commands/
    add.md                     # /sshgate:add <alias> <user@host>
    status.md                  # /sshgate:status
    revoke.md                  # /sshgate:revoke <alias>
    setup.md                   # /sshgate:setup (one-time: bot token, signer install)
    run.md                     # /sshgate:run <alias> <cmd>  (rarely used; Claude calls the tool directly)
  skills/
    debugging-remote-servers.md  # how to use SSHGate to debug servers
  bin/
    sshgate-mcp                # Go MCP binary (pre-built, committed for distribution)
    gate                    # Cross-compiled gate binary for linux/amd64 (deployed to servers)
    signer                  # Go signer daemon binary
  src/
    mcp/                       # Go source for MCP
    gate/                   # Go source for gate binary
    signer/                 # Go source for signer daemon
    common/                    # shared types: classifier, signing payload
  docs/
    specs/
      2026-05-19-sshgate-design.md   # this document
```

---

## SSH key management

**Generated fresh, dedicated to SSHGate, never reuses Karthi's `~/.ssh/id_ed25519`.**

Why this matters (three reasons):

1. **`command=` forcing is per-key.** Auto-setup rewrites the SSHGate key's `authorized_keys` entry to:
   ```
   command="~/.sshgate-gate/gate",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... sshgate@laptop
   ```
   That `command=` traps every connection using that key into gate. If we used Karthi's normal key, every interactive `ssh server`, every `git push`, every `scp` would route through gate. UX disaster.

2. **Your default key probably has unrestricted entries already.** If `~/.ssh/id_ed25519.pub` is in a target server's `authorized_keys` without restriction, the unrestricted entry stays in effect — adding a second `command=`-restricted entry for the same key doesn't override the first. Any process holding the key bypasses gate.

3. **Blast radius separation.** The dedicated key only exists for SSHGate use. If it leaks, the damage is bounded to "gate-gated operations on these specific servers." Normal SSH workflow is untouched.

**Storage layout (decided):**

```
~/.config/sshgate/
  ssh/
    sshgate_ed25519       # private (0600, owned by karthi — MCP needs this for SSH client)
    sshgate_ed25519.pub   # public  (deployed to remote authorized_keys with command= forcing)
  servers.json            # registry: aliases → host/port/user/added_at/last_seen
  pubkey-distrib/
    gate.pub           # copy of signer's signing pubkey (deployed to ~/.sshgate-gate/ during auto-setup)

/var/lib/sshgatesigner/         # owned by sshgatesigner user, 0700
  keys/
    gate.key            # signing private (0600)
    gate.pub            # signing public  (mirrored to ~/.config/sshgate/pubkey-distrib/)
  tokens/
    telegram.token         # bot token (0600)
  config/
    peer.json              # captured Telegram chat_id + user_id allowlist
  log/
    approvals.log          # audit: every sign request, decision, timestamp
```

**SSH key placement:** the SSH client key lives in the `karthi` domain (under `~/.config/sshgate/ssh/`), not signer's. This is deliberate. The remote-side `command=` forcing + gate's classifier already ensures any SSH connection using this key is restricted; nothing useful is gained by adding signer→SSH-client plumbing.

The signing key for gate (i.e., the master key that authorizes writes) lives under signer — that's the one Claude must not be able to read.

---

## Approval flow (end-to-end)

### Read command (e.g., `df -h` on prod-db)

```
Claude → MCP.run("prod-db", "df -h")
MCP   → classify locally → read → SSH directly using sshgate_ed25519
MCP   → server gate verifies the cmd is read → executes → returns output
MCP   → returns output to Claude
```

Latency: one SSH round-trip. No signer involvement. No Telegram notification.

### Write command (e.g., `systemctl restart nginx`)

```
Claude → MCP.run("prod-db", "systemctl restart nginx")
MCP   → classify locally → write → build sign request
MCP   → signer.sock: { kind: sign, request_id: r_xxx, commands: [...] }
signer → posts Telegram DM to Karthi with approve/deny buttons
        → starts the 5-minute (300s) approval window
Karthi → taps [✓ Approve all] on phone
Telegram → callback to signer-bot: from.id=12345678, data="approve:r_xxx"
signer → verifies from.id, request_id, not-expired
        → signs cmd: payload = {cmd, ts, exp, nonce}; sig = ed25519.Sign(key, payload)
        → writes audit log
        → returns { status: approved, signatures: [{cmd, sig}, ...] }
MCP   → SSH with prefix: "SSHGATE_SIG:<sig>:<payload> systemctl restart nginx"
remote gate → verifies sig against gate.pub → cmd matches → not expired → executes
MCP   → returns output to Claude
```

Latency: ~3s (Telegram round-trip dominates).

### Bulk approval (Claude wants to run several writes)

```
Claude → MCP.run_batch("prod-db", [
   "apt update",
   "apt install -y nginx",
   "systemctl enable nginx",
   "systemctl start nginx"
])
MCP   → classify each → all writes → build single sign request with 4 commands
MCP   → signer.sock: { request_id: r_yyy, commands: [4 entries] }
signer → single Telegram DM listing all 4 commands
Karthi → one tap [✓ Approve all]
signer → signs all 4, returns 4 signatures
MCP   → SSH each in order, returns combined output
```

One tap covers N commands. Each command is still individually signed (audit trail unchanged). The "bulk" is purely the approval UI.

### Denial / timeout

If Karthi taps Deny: signer returns `{status: denied}` immediately. MCP returns "denied by operator" to Claude.

If the 5-minute (300s) approval window elapses with no callback: signer returns `{status: timeout}`. MCP returns "approval timed out" to Claude. Pending message in Telegram is edited to show "Expired."

---

## Phased build plan

Per Karthi's architect-style preference (each phase locked and validated before the next):

### Phase 1 — Cryptographic loop end-to-end (target: today)

Smallest end-to-end thing that proves the security model works. One server (manually provisioned), reads-only, signing infra in place even if no writes are exercised yet.

Deliverables:
- gate binary (Go) — classifier + Ed25519 verify + `SSH_ORIGINAL_COMMAND` parsing
- signer daemon (Go) — separate user, owns key, accepts sign requests over socket, **stub backend that always rejects** (no Telegram yet)
- SSHGate MCP server (Go) — `sshgate.run` tool, SSH client with dedicated key, classifier, signer socket caller
- Manually scp gate to test server, manually add authorized_keys entry
- End state: Claude can run `df -h` against the test server through the full SSH→gate→exec path. Trying a write returns "denied by operator" because signer stub rejects.

Validation:
- `df -h` returns disk usage
- `rm /tmp/foo` is classified as write, blocked by signer stub, never reaches the remote

### Phase 2 — Real approval via Telegram + bulk approval (target: today)

Wire up the actual approval channel. After this, writes are usable.

Deliverables:
- signer-bot Telegram bot (via @BotFather)
- `TelegramBackend` implementation (replaces stub) — `getUpdates` polling, inline keyboard callbacks, from.id verification
- `sshgate.run_batch` MCP tool for bulk operations
- Approval message formatting with command list
- `/sshgate:setup` slash command for one-time bot-token registration

Validation:
- A write triggers Telegram DM to Karthi
- Tap approve → command runs on remote
- Tap deny → no command runs
- Batch of 4 writes → one Telegram message, one tap, 4 commands run in order

### Phase 3 — Auto-setup flow (target: today, stretch)

Make adding a new server one command instead of manual scp.

Deliverables:
- `sshgate.add_server` MCP tool — implements §"Installation (Auto-Setup)" from VelGate spec
- Cross-compile pipeline: `GOOS=linux GOARCH=amd64 go build ./cmd/gate` produces `bin/sshgate-gate` for shipping to remote
- `/sshgate:add` slash command
- Connection validation: post-setup test runs `echo SSHGATE_OK` and confirms

Validation:
- `/sshgate:add prod-db karthi@example.com` succeeds end-to-end on a fresh server
- The server's `authorized_keys` shows the `command=` forcing
- A `df -h` afterward works

### Phase 4 — Multi-server polish + revoke + skill (target: today, stretch)

UX layer; ship-quality polish.

Deliverables:
- `sshgate.list_servers`, `sshgate.status`, `sshgate.revoke_server` MCP tools
- `/sshgate:status` slash command (shows registered servers + reachability)
- `/sshgate:revoke` slash command (issues `SSHGATE_REVOKE` signed command)
- `skills/debugging-remote-servers.md` skill — tells Claude how to use SSHGate naturally
- README + install instructions

Validation:
- Two servers registered simultaneously, can switch between them
- `/sshgate:revoke prod-db` cleans up `authorized_keys` and `~/.sshgate-gate/` on the remote
- A fresh Claude session reads the skill and naturally calls `sshgate.run` when Karthi asks "debug what's eating disk on prod-db"

---

## v1 scope — what's in and what's out

### In v1
- gate binary with read/write classifier (as spec)
- signer daemon with key isolation
- Dedicated Telegram bot, DM-only, single user_id allowlist
- Go MCP server with read/write tools, dedicated SSH key
- Auto-setup flow
- Bulk approval
- Slash commands: `setup`, `add`, `status`, `revoke`, `run`
- Skill for debugging workflows

### Deferred to v1.1
- LLM command explainer (signer posts a brief explanation of what each command does before the approve buttons)
- `sshgate.shell` for interactive-ish multi-command sessions
- Pipe/chain classification (currently any pipe → write)
- Time-scoped tokens ("dangerous mode") — only if bulk approval proves insufficient

### Deferred to v2
- Centralized signer server (see §"v2 vision")
- Shared terminal mode (tmux integration from VelGate spec §"Shared Terminal Mode")

### Out (no plan)
- Delegation tokens
- Vel-to-Vel API
- Session multiplexing
- Interactive editor support (vi, nano, etc. — out of scope; use file edits via `cat > file`-style writes with approval)

---

## v2 vision: Centralized signer server

> Captured in detail per Karthi's request so the vision isn't lost.

### Motivation

The v1 design ships a local signer daemon with a Telegram backend. That hits the security bar at low cost, but it has limits:

- One operator (Karthi). Multi-operator approval (e.g., "two team members must approve") is not possible without rebuilding around a shared state store.
- Approval channel is Telegram — fine for a personal tool, less professional for a team-shared tool.
- Audit log is local to one laptop. If the laptop dies, history is lost. Compliance/review across machines is impossible.
- LLM explainer for commands is awkward in a Telegram message format — the rich UI of a web page is a much better surface for showing commands + plain-English explanations + history + filters.
- No central source of truth for "which servers are gated, who has access."

### Proposed architecture

A hosted signer service running on a small VPS (or any always-on host) that you reach over HTTPS. Multiple SSHGate plugins on different machines (or different developers' machines) talk to the same server. The server holds the master signing key, runs the approval UI, and signs after a verified human approval.

```
┌───────────────────────────────────────────────────────────────────────┐
│ Hosted sshgate-signer-server (HTTPS, e.g. signer.example.com)           │
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐   │
│  │ HTTP API     │   │ Web UI       │   │ Sign engine              │   │
│  │ - POST /sign │   │ - login      │   │ - holds gate.key      │   │
│  │ - GET /poll  │   │ - approve    │   │ - sign(cmd, payload)     │   │
│  │ - GET /audit │   │ - audit log  │   │ - audit log writer       │   │
│  └──────┬───────┘   │ - settings   │   └──────────────────────────┘   │
│         │           └──────┬───────┘                                  │
│         │                  │                                          │
│         │  ┌───────────────┴────────────────────┐                     │
│         │  │ Auth: TOTP + WebAuthn passkey      │                     │
│         │  │ Session: short-lived JWT (15min)   │                     │
│         │  │ MFA enforced for every approval    │                     │
│         │  └────────────────────────────────────┘                     │
│         │                                                             │
│         │  ┌────────────────────────────────────┐                     │
│         │  │ State: Postgres (or SQLite)        │                     │
│         │  │ - users, sessions                  │                     │
│         │  │ - pending requests                 │                     │
│         │  │ - signed request history (audit)   │                     │
│         │  │ - server registry (optional)       │                     │
│         │  └────────────────────────────────────┘                     │
└─────┬─────────────────────────────────────────────┬───────────────────┘
      │                                             │
      │ API key                                     │ session cookie
      ▼                                             ▼
┌──────────────────┐                       ┌──────────────────────┐
│ SSHGate plugin   │                       │ Karthi's phone/laptop│
│ (any laptop)     │                       │ Browser              │
│ - signer shim │                       │ [Approve all]        │
│ - long-polls /poll                       │ [Deny]               │
└──────────────────┘                       └──────────────────────┘
```

### Wire protocol (HTTPS)

**POST /v1/sign — request signature**

```http
POST /v1/sign
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "client_id": "karthi-laptop",
  "commands": [
    {"server": "prod-db", "cmd": "systemctl restart nginx", "ttl_seconds": 60}
  ],
  "context": {
    "claude_session_id": "...",
    "user_intent": "Karthi asked me to restart nginx after the cert update"
  }
}

→ 202 Accepted
{
  "request_id": "r_a1b2c3",
  "poll_url": "/v1/poll/r_a1b2c3"
}
```

**GET /v1/poll/{request_id} — long-poll for result**

```http
GET /v1/poll/r_a1b2c3?wait=60s
Authorization: Bearer <api_key>

→ (blocks up to 60s, returns when human approves/denies/timeout)
200 OK
{
  "request_id": "r_a1b2c3",
  "status": "approved",
  "signatures": [
    {"cmd": "systemctl restart nginx", "sig": "SSHGATE_SIG:..."}
  ],
  "approved_by_user": "karthi",
  "approved_at": "2026-05-19T09:14:22Z"
}
```

Long polling mirrors Telegram's `getUpdates` pattern (mentioned in Karthi's voice note). Plugin issues `wait=60s`, server holds connection until a real event or timeout, plugin retries.

### Auth on the web UI (the load-bearing piece)

Web auth correctness is the #1 thing that determines whether v2 is more or less secure than v1. The threat is "anyone who logs in can approve any pending command," so login must be very hard to bypass.

**Tier 1 — TOTP only (acceptable minimum)**
- Username + password + TOTP (Google Authenticator / Authy)
- Industry standard, well-understood
- Vulnerable to phishing (operator types TOTP into a phishing page)

**Tier 2 — TOTP + WebAuthn passkey (recommended)**
- Phishing-resistant: passkey is bound to the origin domain
- iOS/Android both support platform-bound passkeys (Face ID / Touch ID / fingerprint)
- Single tap on phone after entering username; no password to remember
- Library: `github.com/go-webauthn/webauthn`

**Tier 3 — Hardware key (YubiKey) as the WebAuthn authenticator**
- Optional upgrade
- Requires plugging in the YubiKey per approval
- Maximum resistance to phone compromise

**Session policy:**
- Short-lived JWT (15 min)
- Re-authenticate (passkey tap or TOTP) for every approval, not just for login
- Logout invalidates all sessions
- All session tokens stored in `httpOnly; Secure; SameSite=Strict` cookies

### What v2 buys you

- **Approval anywhere with a browser.** Phone, second laptop, work computer — all work.
- **Multi-operator approval rules.** "Two reviewers must approve any prod write." Enforced server-side.
- **Rich UI for approvals.** Each command listed with:
  - Plain-English explanation (LLM-generated server-side)
  - Diff preview for file writes
  - Likely impact ("this restarts nginx; expect 1-2s downtime")
  - Recent history ("you ran this command 3 days ago, approved by you")
- **Centralized audit.** Every sign request and decision logged with timestamps, IPs, user agents. Queryable.
- **Multi-tool reuse.** Other tools beyond SSHGate could request signatures through the same gate (CI pipelines, terraform applies, etc.).

### Migration from v1 to v2

The MCP doesn't know which backend signer uses. The signer Backend interface (defined in v1) has two implementations:

```go
type TelegramBackend struct { /* v1, local */ }
type HostedServerBackend struct {
    BaseURL string  // https://signer.example.com
    APIKey  string  // stored 0600 under signer
}
```

To migrate, replace the `TelegramBackend` instance with a `HostedServerBackend` instance in signer's main. MCP and gate are unchanged. The migration is a config swap.

For full migration:
- Stand up the hosted server with the same `gate.key` (or rotate the key + re-deploy `gate.pub` to all servers)
- Update signer's config to use HostedServerBackend
- Optionally keep TelegramBackend running as a fallback for when the hosted server is unreachable

### What v2 does NOT change

- gate binary on remote servers — same classifier, same Ed25519 verification, same key trust anchor
- MCP server — same tools, same protocol with signer
- SSH key management — unchanged

The change is strictly in the approval-channel layer.

### v2 build cost (rough)

- Hosted server (Go, Postgres, web UI): 25-40h
- Auth (TOTP + WebAuthn): 8-15h
- LLM explainer integration: 4-6h
- Hosting setup (VPS, DNS, TLS, monitoring): 2-4h

Total: ~40-65h. A 1-2 week project standalone, sized for after v1 is in real use and pain points emerge.

---

## Open questions (resolved)

All resolved 2026-05-19; recorded here for design provenance.

1. **sshgatesigner user creation strategy.** Decision: manual one-time `sudo useradd sshgatesigner` walk-through during `/sshgate:setup` for v1 (only applies when the chosen backend is `TelegramBackend`; `HostedServerBackend` doesn't need a local signer user). Automation of the user-creation step deferred to v1.1.
2. **Plugin distribution mechanism.** Decision: ship Go source in the plugin; `/sshgate:setup` runs `go build ./cmd/...` during install. No pre-committed binaries. `bin/` is gitignored and populated by `go build`. Requires Go toolchain on the user's machine (probe at first install, clear error if missing — per plugin.md §8.5).
3. **Telegram bot rate limits.** Non-issue (~30 msg/s ceiling vastly exceeds expected approval rate). No action.
4. **signer crash mid-request.** Out of scope. signer is a small Go binary expected to be very stable; revisit only if it becomes a real operational pain.
5. **Cross-compilation / target platforms.** v1 targets Linux only (laptop + remote servers). v1.1 adds macOS desktop (for users who run Claude Code on a Mac); gate binary cross-compiles via `GOOS=linux GOARCH=amd64 go build` for remote-server deploy regardless of laptop OS. No BSD, no Windows — explicitly not planned.

## Testing approach

This project uses **strict test-driven development.** Every component lands red-green-refactor:

1. Write the failing test that describes the desired behavior.
2. Confirm RED (run test, see it fail for the right reason).
3. Write the minimum code to make it pass. Confirm GREEN.
4. Refactor if needed. Confirm still GREEN.

Test categories per `go.md §4`:

- **Unit** — per-package, table-driven via `t.Run`, real-implementation-first (mocks only for boundaries per `go.md §4.8`). Each package has a `<name>_test.go` covering its public API.
- **Integration** — multi-package wiring tests in `tests/integration/`. Examples:
  - End-to-end signing loop with an in-process signer using a `MockBackend` that immediately approves.
  - SSH client against a Dockerized `linuxserver/openssh-server` container.
  - gate classifier against a corpus of read/write commands (golden file in `testdata/`).
- **Goleak** — every package that spawns goroutines runs `goleak.VerifyTestMain` (per `go.md §4.11`).
- **Manual smoke** — for the user-driven steps (real Telegram bot, real remote server) the implementation plan calls out which steps Karthi runs by hand; everything else the agent executes itself (per memory `feedback_agent_executes_smoke_tests`).

Verification gate before each phase is locked:

```
go vet ./...
go test -race ./...
staticcheck ./...   (if installed)
```

All three clean → phase is shippable. Any failure → fix before moving on.

## Review & audit gates

Before v1 is considered done, three independent passes:

1. **Code review against `~/arogara/code-review/` guidelines.** Files applicable: `general.md` + `go.md` + `cli.md` + `daemon.md` + `plugin.md`. Run methodology per `~/arogara/code-review/METHODOLOGY.md` — dispatch a review subagent, write the report to `~/arogara/code-review/reports/sshgate-YYYY-MM-DD.md`, fix BLOCKERs and MAJORs, defer MINOR/NIT with reason.
2. **PII / secrets audit via `~/arogara/pii-audit/scan.sh`.** Runs gitleaks plus the custom wordlist. No MUST-FIX findings allowed in v1. The `pii-wordlist.txt` may need additions specific to SSHGate (e.g. Karthi's Telegram user_id `12345678` should be flagged if it leaks into source).
3. **Security audit (self-conducted).** Specific attack scenarios to verify against the running build:
   - Can Claude read the master signing key file? (Expected: permission denied — different Unix user.)
   - Can Claude ptrace signer? (Expected: blocked by `ptrace_scope=1`.)
   - Can Claude post a fake "approve" message via c3? (Expected: c3's bot is irrelevant; signer-bot is separate; `from.id` check rejects.)
   - Can Claude forge a Telegram callback by hitting signer's socket with a spoofed payload? (Expected: socket protocol doesn't expose an "approved" injection; approval comes only from signer's own Telegram polling.)
   - Can Claude bypass `command="..."` forcing? (Expected: no — OpenSSH enforces.)
   - What's the recovery path if the master signing key is rotated? (Documented procedure.)

Each gate produces an artifact (review report, audit report, security log) committed under `docs/audits/`.

## Cascade goal

This is a single autonomous session targeting maximum forward progress. Order of work:

1. **Ship v1 fully**: all four phases, all tests green, code review + PII + security audits clean. Commit history tells the story.
2. **If time remains, begin v1.1**: LLM command explainer in approval messages, macOS desktop support (cross-compile + smoke), automated signer user provisioning, pipe/chain classification refinement.
3. **If time remains after v1.1, begin v2**: scaffold the hosted sshgate-signer-server (Go + Postgres + WebAuthn passkey + TOTP) per §"v2 vision." May or may not finish in this session.

Decisions during the cascade — implementation tradeoffs, dependency choices, test coverage thresholds — are the agent's to make, with the rationale captured in commit messages and (where significant) in `docs/decisions/<date>-<topic>.md`. Session ends when Karthi says stop.
