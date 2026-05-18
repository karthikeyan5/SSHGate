---
description: One-time setup for SSHGate — install velsigner daemon, generate keys, link Telegram bot
argument-hint:
allowed-tools: Read, Bash, Write, Edit
---

You are walking the user (Karthi) through one-time SSHGate installation.
The user has already done `/plugin install sshgate` and is invoking this
command; everything below is your job.

Be terse. Surface every command verbatim. Stop on the first failure and
print the literal error. Every step is idempotent — detect existing
state and skip rather than re-doing.

Pause where the body explicitly says PAUSE; proceed automatically
otherwise.

---

## Step 1 — Probe prerequisites

Run:

```bash
go version
```

If the command is not found or the version is older than `go1.22`,
tell the user: "Go 1.22+ is required. Install from https://go.dev/dl/
and re-run `/sshgate:setup`." Stop.

## Step 2 — Build binaries

Build each binary individually so a failure in one is obvious. Use
`${CLAUDE_PLUGIN_ROOT}` for the source tree (the plugin's install
location):

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
```

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/velsigner ./src/velsigner/cmd/velsigner
```

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate
```

After each build, run `ls -la ${CLAUDE_PLUGIN_ROOT}/bin/<name>` and
report the size. Three binaries should now exist in `bin/`.

## Step 3 — Run the installer (first pass)

`install.sh` is the single entry point. One idempotent pass creates the
`velsigner` system user, the `/var/lib/velsigner/` skeleton, adds your
account to the `velsigner` group, installs binaries to `/usr/local`,
writes the hardened systemd unit, runs `--init` to generate the signing
key + skeleton config (`type = "stub"` initially), and starts the
daemon.

**PAUSE** and tell the user verbatim:

> Open a separate terminal and run:
>
>     sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh
>
> (replace `${CLAUDE_PLUGIN_ROOT}` with the actual path printed below).
>
> The script is idempotent — safe to re-run if it fails partway. Tell
> me when it's done.

Print the resolved path with `echo "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh"`
so the user can copy-paste it.

After confirmation, verify the daemon is up:

```bash
systemctl is-active velsigner
```

Expect `active`. If `failed` or `activating`, run:

```bash
journalctl -u velsigner -n 30 --no-pager
```

…surface the output, and stop. You may also need to run `newgrp velsigner`
(or log out and back in) before subsequent commands can read
`/var/lib/velsigner/` without sudo.

## Step 4 — Configure the Telegram backend

The `--init`-generated config has `type = "stub"`. To get phone-tap
approvals you switch it to `telegram` and add the user_id + chatstore
pointers.

**PAUSE** and tell the user:

> Find your numeric Telegram user_id. Easiest way: message @userinfobot
> on Telegram and copy the `Id:` line.
>
> Paste it here.

Receive the user_id. Sanity-check: positive integer. If not, ask again.

Read the current config so you know what `--init` produced:

```bash
sudo cat /var/lib/velsigner/config/config.toml
```

If the file already has `type = "telegram"` AND a `[backend.telegram]`
block with the user's id, log "config already configured for telegram;
skipping" and proceed to Step 5.

Otherwise, tell the user to run (substituting their user_id for `NNNN`):

```bash
sudo tee -a /var/lib/velsigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path        = "/var/lib/velsigner/tokens/telegram.token"
allowed_user_id   = NNNN
chatstore_path    = "/var/lib/velsigner/config/peer.json"
EOF
```

…and then to flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' /var/lib/velsigner/config/config.toml
```

Re-read the file and confirm with the user that it looks right
(`type = "telegram"`, the three telegram keys, no duplicates from a
previous re-run). If duplicates exist, ask the user to clean by hand.

## Step 5 — Run the installer again (token + restart)

Now that the config selects the telegram backend, re-running install.sh
will prompt for the bot token (echoed nothing — `read -rs`) and restart
the daemon.

**PAUSE** and tell the user:

> First, create a Telegram bot via @BotFather (https://t.me/BotFather):
> send `/newbot`, pick a name, pick a username ending in `bot`.
> BotFather replies with a token shaped like `7123456789:AAH...`.
>
> Then, in your sudo terminal, run:
>
>     sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh
>
> The script will detect the new `type = "telegram"` and prompt:
>
>     [install] Paste the BotFather token (input hidden), or press Enter to skip:
>
> Paste the token. Input is hidden — nothing echoes. Press Enter.
>
> The script writes the token to `/var/lib/velsigner/tokens/telegram.token`
> (mode 0600, owned by `velsigner`) and restarts the daemon. Tell me
> when it's done.

After confirmation, verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/velsigner/tokens/telegram.token
```

Expect `600 velsigner:velsigner`.

```bash
systemctl is-active velsigner
```

Expect `active`. If not, run `journalctl -u velsigner -n 30 --no-pager`
and surface the output.

## Step 6 — Capture chat_id from /start and validate

**PAUSE** and tell the user:

> Open Telegram, find the bot you just created (search the username
> you gave to @BotFather), and send `/start`. velsigner's poller will
> capture your chat_id and write it to `/var/lib/velsigner/config/peer.json`.

Poll for the file (up to ~30 seconds):

```bash
for i in $(seq 1 30); do
  if sudo test -f /var/lib/velsigner/config/peer.json; then
    echo "captured"
    break
  fi
  sleep 1
done
sudo test -f /var/lib/velsigner/config/peer.json || echo "not yet"
```

If captured, read it and report the chat_id back:

```bash
sudo cat /var/lib/velsigner/config/peer.json
```

If still not present after 30s, tell the user to double-check they
sent `/start` to the right bot, then re-poll once. If still nothing,
stop and ask the user to share `journalctl -u velsigner -n 30 --no-pager`.

Finally:

```bash
sudo -u velsigner /usr/local/bin/velsigner --version
systemctl status velsigner --no-pager
```

Confirm the version prints and the unit shows `Active: active (running)`.

Then print this summary to the user (substituting real values):

> SSHGate is installed.
>
> - Daemon: velsigner (active, running as user `velsigner`)
> - Socket: /run/velsigner/sock
> - Audit log: /var/lib/velsigner/log/approvals.log
> - Bot chat_id captured: <N>
>
> Try it:
>
>     /sshgate:add prod-db karthi@example.com   # register a server (Phase 3)
>
> Or from a Claude session, ask the model to run a read command on a
> registered server — it'll go through automatically. A write command
> will buzz your phone for approval.
>
> Re-running `/sshgate:setup` is safe; it detects existing state.
