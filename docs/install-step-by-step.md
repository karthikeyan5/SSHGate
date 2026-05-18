# SSHGate — install step-by-step

This is the human-readable install guide. The quick path is to let
Claude Code drive: open a Claude Code session in this repo and run
`/sshgate:setup`. The slash command walks the same six steps below
and pauses for your input where needed.

If you'd rather do it by hand (or don't have Claude Code installed),
follow the manual path.

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
   `bin/velsigner-darwin-{amd64,arm64}`.
2. Install the binaries by hand (`/usr/local/bin` on Intel,
   `/opt/homebrew/bin` on Apple Silicon).
3. Write a launchd plist (the macOS equivalent of the systemd unit
   `scripts/install.sh` drops at `/etc/systemd/system/velsigner.service`)
   that runs `velsigner --config …` as a dedicated user.
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

That's it. Claude Code will build the binaries, run the installer,
walk you through the Telegram config, prompt you for the bot token,
and capture the chat_id. The command is idempotent; re-running is safe.

---

## Manual path

Six steps. Three sudo touchpoints (two `install.sh` runs and the
token paste prompt is folded inside the second one). Every step is
idempotent: re-running after a partial failure is safe.

### 1. Verify Go is installed

```bash
go version
```

You need 1.22 or newer. If missing, install from https://go.dev/dl/.

### 2. Build the binaries

From the SSHGate repo root:

```bash
go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
go build -o bin/velsigner   ./src/velsigner/cmd/velsigner
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' \
    -o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate
```

Or use the Makefile:

```bash
make build velgate-linux
```

### 3. Run the installer (first pass)

```bash
sudo ./scripts/install.sh
```

One idempotent pass does all of the following:

- Creates the `velsigner` system user (no shell, no login).
- Creates `/var/lib/velsigner/{keys,tokens,config,log,bin}` with the
  right ownership and modes.
- Adds your account (`$SUDO_USER`) to the `velsigner` group so you
  can stat the runtime dir and read the audit log without sudo. You
  may need `newgrp velsigner` (or a fresh shell) for membership to
  take effect.
- Copies `bin/velsigner` to `/usr/local/bin/velsigner` and
  `bin/velgate-linux-amd64` to `/usr/local/share/sshgate/`.
- Writes `/etc/systemd/system/velsigner.service` with hardened
  settings (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.).
- Runs `velsigner --init` (as the `velsigner` user) to generate
  `keys/velgate.{key,pub}` and the skeleton `config/config.toml`
  (initial `type = "stub"`).
- `systemctl enable --now velsigner`.

The script exits non-zero with a clear message if the daemon fails
to come up. Verify:

```bash
systemctl is-active velsigner
# expect: active
```

### 4. Configure the Telegram backend

The `--init`-generated config selects the stub backend. To get
phone-tap approvals you switch it to telegram and add your numeric
user_id.

Find your Telegram user_id by messaging @userinfobot — it replies
with `Id: NNNN`. That number is your `allowed_user_id`.

Append the telegram block (replace `NNNN`):

```bash
sudo tee -a /var/lib/velsigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path      = "/var/lib/velsigner/tokens/telegram.token"
allowed_user_id = NNNN
chatstore_path  = "/var/lib/velsigner/config/peer.json"
EOF
```

Flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' \
    /var/lib/velsigner/config/config.toml
```

Sanity-check with `sudo cat /var/lib/velsigner/config/config.toml`.
You should see `type = "telegram"` and the three telegram keys, no
duplicates.

### 5. Run the installer again (token + restart)

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
`/var/lib/velsigner/tokens/telegram.token` (mode `0600`, owned by
`velsigner:velsigner`), restarts the daemon, and asserts it came up.

Verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/velsigner/tokens/telegram.token
# expect: 600 velsigner:velsigner

systemctl is-active velsigner
# expect: active
```

If the daemon fails after the token write, run
`journalctl -u velsigner -n 30 --no-pager`. Common causes: token
copy-paste included a stray newline (the installer's regex catches
this and refuses to write, but check the file mode if it's there),
or `allowed_user_id = 0` (you forgot to substitute `NNNN`).

### 6. Capture chat_id from `/start` and validate

Open Telegram, find the bot you created (search the username you
gave to BotFather), and send it `/start`. velsigner's polling loop
captures the chat_id and writes it to
`/var/lib/velsigner/config/peer.json`.

**Expected reply on Telegram:**

> Linked — SSHGate approvals will now reach you here.

If you see that text in the bot DM, the link succeeded. If you sent
`/start` from a Telegram account whose user_id does not match
`allowed_user_id`, the bot replies with "this bot only serves
…" and silently drops the message — velsigner stays in the
unlinked state.

Confirm on the laptop side:

```bash
sudo cat /var/lib/velsigner/config/peer.json
# expect a JSON object containing your chat_id
```

If nothing appears after ~30 seconds, check the logs:

```bash
journalctl -u velsigner -n 30 --no-pager
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
sudo -u velsigner /usr/local/bin/velsigner --version
systemctl status velsigner --no-pager
```

You should see `Active: active (running)` and the version string.

---

## Troubleshooting

**`systemctl status velsigner` shows `failed`.**
Run `journalctl -u velsigner -n 50 --no-pager`. The most common
causes are a missing or malformed `config.toml` (the daemon refuses
to start if `backend.telegram.allowed_user_id` is 0 or the token file
is unreadable), or a permissions mismatch on `/var/lib/velsigner/`
(re-run `scripts/install.sh` to repair — it's idempotent and re-applies
the canonical modes).

**`401 Unauthorized` in the log.**
The bot token is wrong. Re-run `sudo ./scripts/install.sh` after
removing the bad token: `sudo rm /var/lib/velsigner/tokens/telegram.token`.
The installer will prompt again.

**`peer.json` never appears.**
You sent `/start` to the wrong bot, or your `allowed_user_id` doesn't
match the user that sent the message — velsigner drops messages from
other users silently. Double-check `Id:` from @userinfobot.

**"Address already in use" on the socket.**
A previous velsigner is still running. `sudo systemctl restart velsigner`
clears it; if that fails, find the holder with
`sudo fuser /run/velsigner/sock`.

**`go build` fails with "cannot find module".**
You're not in the SSHGate repo root. `cd` to the directory containing
`go.mod` and re-run.

---

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

This stops + disables the systemd unit, removes the unit file, removes
`/usr/local/bin/velsigner` and `/usr/local/share/sshgate/`, and prompts
before removing `/var/lib/velsigner/` (which holds the master signing
key and audit log — destructive). Pass `--purge` to skip the prompts.

Removing `/var/lib/velsigner/` invalidates every velgate deployment
keyed against this signer; you'll need to re-run `/sshgate:add` (and
auto-setup) on every server after re-installing.
