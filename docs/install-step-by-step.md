# SSHGate — install step-by-step

This is the human-readable install guide. The quick path is to let
Claude Code drive: open a Claude Code session in this repo and run
`/sshgate:setup`. The slash command walks the tiered flow below and
pauses for your input where needed.

If you'd rather do it by hand (or don't have Claude Code installed),
follow the manual path.

---

## Tiers

SSHGate ships three install tiers. Pick the one matching how much
trust you want to delegate.

### Tier 1 — Read-only

- gate is deployed on each remote; the SSHGate dedicated SSH key
  is forced through it via `command="~/.sshgate-gate/gate"`.
- **No** signer is installed: `sshgatesigner` user/daemon does not exist,
  no master key, no Telegram bot.
- gate's keystore treats the absent `gate.pub` as "no signing
  key configured" — reads execute, writes exit 77 with:
  `gate: no signing key configured (read-only install — re-run /sshgate:setup to add a signer)`.
- **Trust model:** you trust Claude not to actively exploit SSH read
  access (file enumeration, log harvesting); you rely on gate to
  deny writes locally without any approval channel.
- **Use when:** you want to try the gate quickly; you don't yet have
  a phone you want tied to the laptop; the remotes are low-stakes.

### Tier 2 — Local Telegram signer

- Everything in tier 1, plus:
  - `sshgate-signer-telegram` Unix user (no shell, no login) owns
    `/var/lib/sshgatesigner/keys/gate.key` — the master signing key.
  - `sshgate-signer-telegram.service` systemd unit talks Telegram.
  - Each write command queues for a phone-tap approval before
    signer signs it; gate verifies the signature against
    `gate.pub` on the remote.
- **Trust model:** the master key is isolated under a dedicated Unix
  user. Claude (running as you) cannot read it. Every write requires
  your active tap on Telegram. The bot's `allowed_user_id` pins the
  channel to your account.
- **Use when:** you want active human-in-the-loop approvals; you're
  comfortable with a Telegram bot as the second factor.

### Tier 3 — Hosted server signer

- **NOT YET AVAILABLE (v2.x).** The hosted signer
  (`src/signer-server`) is scaffolded but the web UI + WebAuthn
  approval flow is incomplete.
- Master key lives on a dedicated VPS behind WebAuthn; multiple
  operators can share approvals. Documented for completeness.
- **Use when:** v2.x ships and you want to share SSHGate access
  across a team without each operator running their own signer.

---

## Prerequisites

- Linux with systemd (Ubuntu 22.04+, Debian 12+, Arch — anything
  systemd-based).
- Go 1.22 or newer on `$PATH` (https://go.dev/dl/).
- `sudo` access on the local machine — we create a system user,
  install binaries to `/usr/local`, and drop a systemd unit.
- A Telegram account and access to @BotFather to create the approval
  bot.
- (Phase 3, not Phase 2:) one or more remote Linux servers reachable
  over SSH; you'll add them later with `/sshgate:add`.

### macOS users

The Linux automation below (`scripts/install.sh`, systemd unit) does
not run on macOS. For v1.1, the macOS install path is **semi-manual**:

1. Run `make darwin` to produce
   `bin/sshgate-mcp-darwin-{amd64,arm64}` and
   `bin/sshgate-signer-telegram-darwin-{amd64,arm64}`.
2. Install the binaries by hand (`/usr/local/bin` on Intel,
   `/opt/homebrew/bin` on Apple Silicon).
3. Write a launchd plist (the macOS equivalent of the systemd unit
   `scripts/install.sh` drops at `/etc/systemd/system/sshgate-signer-telegram.service`)
   that runs `signer --config …` as a dedicated user.
4. Skip the `useradd`/`usermod`/`systemctl` steps in this guide —
   their macOS equivalents (`dscl`, `launchctl`) aren't yet scripted.

A scripted macOS install path (launchd plist template +
`install-darwin.sh`) lands in v1.2. v1.1's macOS support is
cross-compile + structural validation only — the rest of this guide
assumes Linux.

---

## Quick path — `/sshgate:setup`

```
/sshgate:setup
```

That's it. Claude Code probes on-disk state, classifies the current
tier, and either offers a tier menu (fresh install) or a re-run menu
(upgrade an existing install). Tier 1 needs no sudo at all; Tier 2
pauses for `sudo ./scripts/install.sh` runs. The command is
idempotent; re-running is safe.

---

## Manual path — Tier 1 (read-only)

Three steps, no sudo.

### 1. Verify Go is installed

```bash
go version
```

You need 1.22 or newer. If missing, install from https://go.dev/dl/.

### 2. Build the binaries

```bash
go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' \
    -o bin/sshgate-gate-linux-amd64 ./src/gate/cmd/sshgate-gate
```

(signer is **not** needed for tier 1.)

### 3. Create the SSHGate SSH key + registry

```bash
mkdir -p ~/.config/sshgate/ssh && chmod 700 ~/.config/sshgate/ssh
ssh-keygen -t ed25519 -N '' -C 'sshgate-dedicated' \
    -f ~/.config/sshgate/ssh/sshgate_ed25519
echo '{"servers":{}}' > ~/.config/sshgate/servers.json
```

Confirm the private key is mode 0600:

```bash
stat -c '%a' ~/.config/sshgate/ssh/sshgate_ed25519
# expect: 600
```

### 4. Add a server (read-only deploy)

From a Claude session, ask the model to call `sshgate.add_server`
with `read_only=true`. The tool uploads gate but skips
gate.pub — the remote runs in read-only mode. Reads succeed,
writes return exit 77 with the "no signing key configured" message.

To upgrade a tier-1 server to tier-2 later (after you've added a
signer), re-run add_server with `read_only=false` and the same
bootstrap credentials. The new gate.pub is pushed idempotently.

---

## Manual path — Tier 2 (local Telegram signer)

Assumes Tier 1 is already in place (binaries built, SSH key + registry
exist). Three sudo touchpoints (two `install.sh` runs and the token
paste prompt is folded inside the second one). Every step is
idempotent: re-running after a partial failure is safe.

### 1. Build signer

```bash
go build -o bin/sshgate-signer-telegram ./src/signer/cmd/sshgate-signer-telegram
```

(Or use `make build sshgate-gate-linux` to build all three binaries.)

### 2. Run the installer (first pass)

```bash
sudo ./scripts/install.sh
```

One idempotent pass does all of the following:

- Creates the `sshgatesigner` system user (no shell, no login).
- Creates `/var/lib/sshgatesigner/{keys,tokens,config,log,bin}` with the
  right ownership and modes.
- Adds your account (`$SUDO_USER`) to the `sshgatesigner` group so you
  can stat the runtime dir and read the audit log without sudo. You
  may need `newgrp sshgatesigner` (or a fresh shell) for membership to
  take effect.
- Copies `bin/sshgate-signer-telegram` to `/usr/local/bin/sshgate-signer-telegram` and
  `bin/sshgate-gate-linux-amd64` to `/usr/local/share/sshgate/`.
- Writes `/etc/systemd/system/sshgate-signer-telegram.service` with hardened
  settings (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.).
- Runs `signer --init` (as the `sshgatesigner` user) to generate
  `keys/gate.{key,pub}` and the skeleton `config/config.toml`
  (initial `type = "stub"`).
- `systemctl enable --now sshgate-signer-telegram`.

The script exits non-zero with a clear message if the daemon fails
to come up. Verify:

```bash
systemctl is-active sshgate-signer-telegram
# expect: active
```

### 3. Configure the Telegram backend

The `--init`-generated config selects the stub backend. To get
phone-tap approvals you switch it to telegram and add your numeric
user_id.

Find your Telegram user_id by messaging @userinfobot — it replies
with `Id: NNNN`. That number is your `allowed_user_id`.

Append the telegram block (replace `NNNN`):

```bash
sudo tee -a /var/lib/sshgatesigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path      = "/var/lib/sshgatesigner/tokens/telegram.token"
allowed_user_id = NNNN
chatstore_path  = "/var/lib/sshgatesigner/config/peer.json"
EOF
```

Flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' \
    /var/lib/sshgatesigner/config/config.toml
```

Sanity-check with `sudo cat /var/lib/sshgatesigner/config/config.toml`.
You should see `type = "telegram"` and the three telegram keys, no
duplicates.

### 4. Run the installer again (token + restart)

Create the Telegram bot first: message @BotFather, send `/newbot`,
choose a name and a username ending in `bot`. BotFather replies with
a token shaped like `7123456789:AAH...`. Copy it.

Now re-run the installer:

```bash
sudo ./scripts/install.sh
```

It detects `type = "telegram"` and the missing token file, then
prompts:

```
[install] Paste the BotFather token (input hidden), or press Enter to skip:
```

Paste the token. Input is hidden (terminal echo disabled) — nothing
appears on screen. Press Enter.

The installer writes the token to
`/var/lib/sshgatesigner/tokens/telegram.token` (mode `0600`, owned by
`sshgatesigner:sshgatesigner`), restarts the daemon, and asserts it came up.

Verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/telegram.token
# expect: 600 sshgatesigner:sshgatesigner

systemctl is-active sshgate-signer-telegram
# expect: active
```

If the daemon fails after the token write, run
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`. Common causes: token
copy-paste included a stray newline (the installer's regex catches
this and refuses to write, but check the file mode if it's there),
or `allowed_user_id = 0` (you forgot to substitute `NNNN`).

### 5. Capture chat_id from `/start` and validate

Open Telegram, find the bot you created (search the username you
gave to BotFather), and send it `/start`. signer's polling loop
captures the chat_id and writes it to
`/var/lib/sshgatesigner/config/peer.json`.

**Expected reply on Telegram:**

> Linked — SSHGate approvals will now reach you here.

If you see that text in the bot DM, the link succeeded. If you sent
`/start` from a Telegram account whose user_id does not match
`allowed_user_id`, the bot replies with "this bot only serves
…" and silently drops the message — signer stays in the
unlinked state.

Confirm on the laptop side:

```bash
sudo cat /var/lib/sshgatesigner/config/peer.json
# expect a JSON object containing your chat_id
```

If nothing appears after ~30 seconds, check the logs:

```bash
journalctl -u sshgate-signer-telegram -n 30 --no-pager
```

What to look for in the log:

- `telegram backend ready` — the daemon reached its polling loop.
- `/start: linked chat_id=NNN for user_id=NNN` — capture succeeded.
- `/start from unauthorized user_id=NNN ignored` — wrong Telegram
  account; check `allowed_user_id` matches your @userinfobot reply.
- `401 Unauthorized` from `getMe` / `getUpdates` — the bot token is
  wrong or was revoked in BotFather.

Final validation:

```bash
sudo -u sshgatesigner /usr/local/bin/sshgate-signer-telegram --version
systemctl status sshgate-signer-telegram --no-pager
```

You should see `Active: active (running)` and the version string.

If you upgraded from Tier 1 — that is, you had read-only servers
already registered — you also need to push the new `gate.pub` to
each one so signed writes can be verified. Copy the pubkey to the
MCP-side distribution path:

```bash
mkdir -p ~/.config/sshgate/pubkey-distrib
sudo cp /var/lib/sshgatesigner/keys/gate.pub \
    ~/.config/sshgate/pubkey-distrib/gate.pub
sudo chown "$USER" ~/.config/sshgate/pubkey-distrib/gate.pub
chmod 644 ~/.config/sshgate/pubkey-distrib/gate.pub
```

Then, from a Claude session, re-run `sshgate.add_server` for each
registered alias with `read_only=false` and the same bootstrap
credentials you used originally. The tool detects the existing
restricted entry in `authorized_keys` and pushes the new
`gate.pub` idempotently — no rewrites, no rollback risk.

### 6. (Optional) LLM command explainer

By default the approval message lists the queued commands verbatim.
With this step enabled, signer additionally asks an OpenAI-compatible
LLM to write a one-sentence plain-English explanation of each command
and renders them beneath the corresponding command line — handy when
you're approving from your phone and don't want to mentally parse
`certbot --nginx -d example.com` at a glance.

Approval is **never blocked** on the LLM: if the call times out or
errors, signer sends the message without explanations and adds a
small `(no explanations: …)` footer noting why.

**a. Pick a provider + model.** Any OpenAI-compatible Chat Completions
endpoint works. Two reasonable choices:

- **OpenRouter** — pay-as-you-go, broad model catalogue. Endpoint
  `https://openrouter.ai/api/v1/chat/completions`; a good cheap+fast
  model for one-liner explanations is `anthropic/claude-haiku-4.5`.
- **OpenAI** — endpoint
  `https://api.openai.com/v1/chat/completions`; `gpt-4o-mini` is the
  cost-sensible default.

Local options (LM Studio, llama.cpp's `server`) also work — point
`endpoint` at the local URL and leave any string in the key file.

**b. Write the API key to disk.** Substitute your real key on stdin:

```bash
sudo install -o signer -g signer -m 600 /dev/null \
    /var/lib/sshgatesigner/tokens/llm-api.key
sudo -u sshgatesigner tee /var/lib/sshgatesigner/tokens/llm-api.key >/dev/null
# paste key, ctrl-D
sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/llm-api.key
# expect: 600 sshgatesigner:sshgatesigner
```

**c. Add the `[backend.telegram.explainer]` block to the config.**
Replace the endpoint and model with your choice:

```bash
sudo tee -a /var/lib/sshgatesigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram.explainer]
enabled      = true
endpoint     = "https://openrouter.ai/api/v1/chat/completions"
model        = "anthropic/claude-haiku-4.5"
api_key_path = "/var/lib/sshgatesigner/tokens/llm-api.key"
timeout_sec  = 5
EOF
```

**d. Restart and verify.**

```bash
sudo systemctl restart sshgate-signer-telegram
journalctl -u sshgate-signer-telegram -n 10 --no-pager
# expect a line like:
#   telegram explainer enabled (model=… endpoint=… timeout=5s)
```

On the next approval request you should see, beneath each command,
an indented `→ <plain-English explanation>` line. If the LLM is
unreachable or slow, you'll see the verbatim commands plus a
`(no explanations: …)` footer — the daemon still asks for approval
exactly as before.

To disable the explainer later, set `enabled = false` (or remove the
block entirely) and restart the daemon.

---

## Troubleshooting

**`systemctl status sshgate-signer-telegram` shows `failed`.**
Run `journalctl -u sshgate-signer-telegram -n 50 --no-pager`. The most common
causes are a missing or malformed `config.toml` (the daemon refuses
to start if `backend.telegram.allowed_user_id` is 0 or the token file
is unreadable), or a permissions mismatch on `/var/lib/sshgatesigner/`
(re-run `scripts/install.sh` to repair — it's idempotent and re-applies
the canonical modes).

**`401 Unauthorized` in the log.**
The bot token is wrong. Re-run `sudo ./scripts/install.sh` after
removing the bad token: `sudo rm /var/lib/sshgatesigner/tokens/telegram.token`.
The installer will prompt again.

**`peer.json` never appears.**
You sent `/start` to the wrong bot, or your `allowed_user_id` doesn't
match the user that sent the message — signer drops messages from
other users silently. Double-check `Id:` from @userinfobot.

**"Address already in use" on the socket.**
A previous signer is still running. `sudo systemctl restart sshgate-signer-telegram`
clears it; if that fails, find the holder with
`sudo fuser /run/sshgatesigner/sock`.

**`go build` fails with "cannot find module".**
You're not in the SSHGate repo root. `cd` to the directory containing
`go.mod` and re-run.

**Approval messages always show `(no explanations: …)`.**
The LLM explainer is configured but every call is failing. Check
`journalctl -u sshgate-signer-telegram -n 50 --no-pager` for the underlying error.
Common causes: wrong/expired API key, unreachable endpoint URL,
`timeout_sec` set too low for the chosen model. Set
`enabled = false` in `[backend.telegram.explainer]` and restart to
disable the explainer entirely while you investigate.

---

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

This stops + disables the systemd unit, removes the unit file, removes
`/usr/local/bin/sshgate-signer-telegram` and `/usr/local/share/sshgate/`, and prompts
before removing `/var/lib/sshgatesigner/` (which holds the master signing
key and audit log — destructive). Pass `--purge` to skip the prompts.

Removing `/var/lib/sshgatesigner/` invalidates every gate deployment
keyed against this signer; you'll need to re-run `/sshgate:add` (and
auto-setup) on every server after re-installing.
