# SSHGate — install step-by-step

This is the human-readable install guide. The quick path is to let
Claude Code drive: open a Claude Code session in this repo and run
`/sshgate:setup`. The slash command walks the same nine steps below
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

---

## Quick path — `/sshgate:setup`

```
/sshgate:setup
```

That's it. Claude Code will build the binaries, prompt you for the bot
token, ask for your Telegram user_id, install the systemd unit, and
capture the chat_id. The command is idempotent; re-running is safe.

---

## Manual path

If you're doing this without Claude Code, run each step below in order.
Every step is idempotent: re-running after a partial failure is safe.

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

### 3. Create the velsigner system user

```bash
sudo ./scripts/create-velsigner-user.sh
```

This creates the `velsigner` user (no shell), `/var/lib/velsigner/`
with the right ownership and modes, and adds your user to the
`velsigner` group. You may need to log out and back in (or run
`newgrp velsigner` in a fresh shell) for group membership to take
effect.

### 4. Install binaries + initialise keys and config

```bash
sudo install -m 0755 bin/velsigner /usr/local/bin/velsigner
sudo mkdir -p /usr/local/share/sshgate
sudo install -m 0755 bin/velgate-linux-amd64 /usr/local/share/sshgate/velgate-linux-amd64
sudo -u velsigner /usr/local/bin/velsigner --init \
    --config /var/lib/velsigner/config/config.toml
```

`--init` generates `/var/lib/velsigner/keys/velgate.{key,pub}` and
writes a skeleton TOML config. It refuses to overwrite existing keys —
if you need to start over, remove the state directory first.

### 5. Register the Telegram bot token

Create a bot via @BotFather: send `/newbot`, choose a name and a
username ending in `bot`. BotFather replies with a token shaped like
`7123456789:AAH...`.

Save it (replace `TOKEN_VALUE` with the real token):

```bash
sudo install -m 0600 -o velsigner -g velsigner /dev/stdin \
    /var/lib/velsigner/tokens/telegram.token <<< 'TOKEN_VALUE'
```

Verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/velsigner/tokens/telegram.token
# expect: 600 velsigner:velsigner
```

### 6. Configure the Telegram backend

Find your numeric Telegram user_id by messaging @userinfobot — it
replies with `Id: NNNN`. That number is your `allowed_user_id`.

Append the Telegram block to the config (replace `NNNN`):

```bash
sudo tee -a /var/lib/velsigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path      = "/var/lib/velsigner/tokens/telegram.token"
allowed_user_id = NNNN
chatstore_path  = "/var/lib/velsigner/config/peer.json"
EOF
```

Switch the backend type from `stub` to `telegram`:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' \
    /var/lib/velsigner/config/config.toml
```

Sanity-check the file with `sudo cat /var/lib/velsigner/config/config.toml`.
You should see `type = "telegram"` and the three telegram keys, no
duplicates.

### 7. Install the systemd unit + start velsigner

```bash
sudo ./scripts/install.sh
```

This (re-)installs the binaries, writes
`/etc/systemd/system/velsigner.service` with the hardened settings
(`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
etc.), reloads systemd, and runs `systemctl enable --now velsigner`.
The script exits non-zero with a clear message if the daemon fails to
come up.

Verify:

```bash
systemctl is-active velsigner
# expect: active
```

### 8. Capture chat_id from `/start`

Open Telegram, find the bot you created in step 5 (search the
username you gave to BotFather), and send it `/start`. velsigner's
polling loop captures the chat_id and writes it to
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

### 9. Validate

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
(re-run `scripts/create-velsigner-user.sh` to repair).

**`401 Unauthorized` in the log.**
The bot token is wrong. Re-paste it from BotFather (`/mybots` →
select your bot → "API Token").

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
