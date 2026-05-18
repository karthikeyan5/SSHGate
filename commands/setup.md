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

## Step 3 — Create the velsigner system user

Check whether the user already exists:

```bash
getent passwd velsigner
```

If the command exits 0, log "velsigner user already exists; skipping"
and proceed to Step 4.

Otherwise, **PAUSE** and tell the user verbatim:

> Open a separate terminal and run:
>
>     sudo ${CLAUDE_PLUGIN_ROOT}/scripts/create-velsigner-user.sh
>
> (replace `${CLAUDE_PLUGIN_ROOT}` with the actual path printed below).
>
> The script creates the `velsigner` system user, the
> `/var/lib/velsigner/` state directory skeleton, and adds your user
> account to the `velsigner` group. It's idempotent.
>
> Tell me when it's done.

Print the resolved path with `echo "${CLAUDE_PLUGIN_ROOT}/scripts/create-velsigner-user.sh"`
so the user can copy-paste it.

After the user confirms, re-run `getent passwd velsigner` to verify.
If it still fails, stop and surface the user's reported error.

## Step 4 — Install binaries + initialise keys and config

Copy the freshly-built binaries into their canonical locations.
**PAUSE** and tell the user to run, in their sudo terminal:

```bash
sudo install -m 0755 ${CLAUDE_PLUGIN_ROOT}/bin/velsigner /usr/local/bin/velsigner
sudo mkdir -p /usr/local/share/sshgate
sudo install -m 0755 ${CLAUDE_PLUGIN_ROOT}/bin/velgate-linux-amd64 /usr/local/share/sshgate/velgate-linux-amd64
```

Wait for confirmation.

Then check whether keys + config already exist:

```bash
sudo test -f /var/lib/velsigner/keys/velgate.key && sudo test -f /var/lib/velsigner/config/config.toml
```

If both exist (exit 0), log "keys + config already initialised; skipping
--init" and proceed to Step 5.

Otherwise tell the user to run:

```bash
sudo -u velsigner /usr/local/bin/velsigner --init --config /var/lib/velsigner/config/config.toml
```

This generates `/var/lib/velsigner/keys/velgate.{key,pub}` and writes a
skeleton TOML config. Wait for confirmation. If it fails because the
config already exists but the keys don't (or vice versa), surface the
error and ask the user to clean up by hand — do NOT auto-delete the
config (it might contain hand edits worth preserving).

## Step 5 — Telegram bot token

Check whether the token file already exists:

```bash
sudo test -f /var/lib/velsigner/tokens/telegram.token
```

If yes (exit 0), log "bot token already present; skipping" and proceed
to Step 6.

Otherwise **PAUSE** and tell the user:

> Create a new Telegram bot via @BotFather (https://t.me/BotFather):
> send `/newbot`, pick a name, pick a username ending in `bot`. BotFather
> replies with a token shaped like `7123456789:AAH...`.
>
> Paste it here.

Receive the token. Sanity-check: it should match `^[0-9]+:[A-Za-z0-9_-]+$`.
If it doesn't, ask for it again — don't write garbage to the token file.

Tell the user to run, in their sudo terminal (replacing `TOKEN` with
the actual token they pasted):

```bash
sudo install -m 0600 -o velsigner -g velsigner /dev/stdin /var/lib/velsigner/tokens/telegram.token <<< 'TOKEN_VALUE_HERE'
```

Do NOT echo the token back in your own response. Wait for confirmation.

Verify mode and ownership:

```bash
sudo stat -c '%a %U:%G' /var/lib/velsigner/tokens/telegram.token
```

Expect `600 velsigner:velsigner`. If wrong, ask the user to fix and
re-run the stat.

## Step 6 — Allowed Telegram user_id + chatstore path

**PAUSE** and tell the user:

> Find your numeric Telegram user_id (positive integer). Easiest way:
> message @userinfobot on Telegram and copy the `Id:` line.
>
> Paste it here.

Receive the user_id. Sanity-check: positive integer. If not, ask again.

Now edit `/var/lib/velsigner/config/config.toml` to add the Telegram
backend stanza. First read it back so you know what's there:

```bash
sudo cat /var/lib/velsigner/config/config.toml
```

The `--init`-generated skeleton has `[backend]` with `type = "stub"`.
You need to:
  1. Change `type = "stub"` to `type = "telegram"`.
  2. Append a `[backend.telegram]` block with the three required keys.

Tell the user to run (substituting their user_id for `NNNN`):

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

## Step 7 — Install systemd unit + start velsigner

**PAUSE** and tell the user to run, in their sudo terminal:

```bash
sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh
```

This script copies binaries (idempotent — already done in Step 4 but
the script re-applies them in case the user skipped that step), writes
the hardened systemd unit, and runs `systemctl enable --now velsigner`.
It exits non-zero with a clear message if the daemon fails to come up.

Wait for confirmation. Then verify yourself:

```bash
systemctl is-active velsigner
```

Expect `active`. If `failed` or `activating`, run:

```bash
journalctl -u velsigner -n 30 --no-pager
```

…surface the output, and stop.

## Step 8 — Capture chat_id from /start

**PAUSE** and tell the user:

> Open Telegram, find the bot you just created (search the username
> you gave to @BotFather), and send `/start`. velsigner's poller will
> capture your chat_id and write it to `/var/lib/velsigner/config/peer.json`.

Poll for the file (up to ~30 seconds). Run:

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

## Step 9 — Validate + summary

Run:

```bash
sudo -u velsigner /usr/local/bin/velsigner --version
```

```bash
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
