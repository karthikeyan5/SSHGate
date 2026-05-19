---
description: One-time setup for SSHGate — tiered install (read-only, local Telegram signer, or hosted)
argument-hint:
allowed-tools: Read, Bash, Write, Edit, AskUserQuestion
---

You are walking the user (Karthi) through SSHGate installation. The
command is tiered and idempotent — every run starts by probing on-disk
state, then either offers tier selection (fresh install) or a re-run
menu (upgrade an existing install).

Be terse. Surface every command verbatim. Stop on the first failure
and print the literal error. PAUSE markers mean "wait for user input
before proceeding."

## Tier overview (for your own reference; do not narrate verbatim)

- **Tier 1 — Read-only:** velgate is deployed on remotes but NO
  velgate.pub is uploaded. Reads work; writes are denied locally at
  the gate. No velsigner, no Telegram, no master key. Fastest install.
- **Tier 2 — Local Telegram signer:** master keypair under the
  `velsigner` system user, velsigner systemd unit, Telegram bot for
  approvals. Writes get a phone-tap approval. velgate.pub pushed to
  every already-registered server (tier-1 → tier-2 upgrade).
- **Tier 3 — Hosted server signer:** NOT YET AVAILABLE. The hosted
  signer (`src/velsigner-server`) needs the v2.x web UI + WebAuthn
  flow to ship before this can be wired in.

---

## Step 0 — Probe on-disk state

Run these to detect the current tier. Capture each one's result; you
will branch on them below.

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && echo "ssh:yes" || echo "ssh:no"
```

```bash
getent passwd velsigner >/dev/null 2>&1 && echo "user:yes" || echo "user:no"
```

```bash
systemctl is-active velsigner 2>/dev/null || echo inactive
```

```bash
sudo test -f /var/lib/velsigner/keys/velgate.key 2>/dev/null && echo "key:yes" || echo "key:no"
```

```bash
sudo grep -E '^[[:space:]]*type[[:space:]]*=[[:space:]]*"telegram"' /var/lib/velsigner/config/config.toml 2>/dev/null && echo "tg:yes" || echo "tg:no"
```

Classify:

- `ssh:no` AND `user:no` → **FRESH** install.
- `ssh:yes` AND `user:no` → **TIER-1 PRESENT** (read-only).
- `ssh:yes` AND `user:yes` AND `tg:yes` → **TIER-2 PRESENT** (local Telegram signer).
- Anything else → **PARTIAL** (mid-install; report the mismatch and ask the user to clean up before continuing).

Tell the user the detected tier in one line, e.g.
`Detected: fresh install (no SSHGate SSH key, no velsigner user).`

## Step 1 — Branch on detected tier

### Branch A: FRESH install

Use `AskUserQuestion` to offer the three tiers. Question:
`"Which install tier do you want? You can upgrade from tier 1 to tier 2 later by re-running this command."`

Options (header / description):

1. `"Read-only"` / `"Tier 1 — deploy velgate to remotes, NO signer.
   Reads work; writes are denied at the gate. Fastest install, no
   sudo for the rest of the flow. Recommended for first try."`
2. `"Local Telegram signer"` / `"Tier 2 — install velsigner + master
   key + Telegram bot. Writes require a phone-tap approval. Adds
   ~5 minutes of setup."`
3. `"Hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE. The
   hosted signer needs the v2.x web UI + WebAuthn flow. Pick read-only
   or local-telegram for now."`

Branch on the answer:

- Tier 1 → continue to **Tier 1 flow**.
- Tier 2 → continue to **Tier 2 flow** (do tier-1 prep first, then tier-2 add-ons).
- Tier 3 → print:
  `Hosted server signer is not yet available (waiting on web UI + WebAuthn auth — tracked in src/velsigner-server/README.md). Pick read-only or local-telegram for now.`
  Stop.

### Branch B: TIER-1 PRESENT (re-run)

Use `AskUserQuestion` with:
`"Tier 1 is already installed. What would you like to do?"`

Options:

1. `"Verify"` / `"Re-check on-disk state, confirm the SSHGate SSH key is intact."`
2. `"Add local Telegram signer"` / `"Upgrade tier 1 → tier 2. Generate the master key, install velsigner, configure Telegram bot, push velgate.pub to all registered servers."`
3. `"Add hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE."`

Branch on the answer:

- Verify → run **Verify flow**.
- Tier 2 → continue to **Tier 2 flow**.
- Tier 3 → print the not-available message from Branch A and stop.

### Branch C: TIER-2 PRESENT (re-run)

Use `AskUserQuestion` with:
`"Tier 2 is already installed. What would you like to do?"`

Options:

1. `"Verify"` / `"Re-check on-disk state, confirm velsigner is active and the Telegram link works."`
2. `"Reconfigure Telegram"` / `"Re-prompt for the bot token and/or allowed_user_id. Useful if you rotated the bot."`
3. `"Add hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE."`

Branch on the answer:

- Verify → run **Verify flow**.
- Reconfigure → jump to **Tier 2 — Telegram configure** section.
- Tier 3 → print the not-available message and stop.

### Branch D: PARTIAL

Print the detected state line by line (which of `ssh/user/key/tg`
came back yes/no) and tell the user the install is mid-migration.
Suggest running `scripts/uninstall.sh` or manually cleaning state.
Stop.

---

## Tier 1 flow — read-only

### T1.1 — Probe prerequisites

```bash
go version
```

If not 1.22 or newer, tell the user to install Go from
https://go.dev/dl/ and stop.

### T1.2 — Build binaries

Build `sshgate-mcp` and `velgate-linux-amd64`. velsigner is NOT needed
in tier 1; skip it.

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
```

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate
```

After each build, run `ls -la ${CLAUDE_PLUGIN_ROOT}/bin/<name>` and
report the size.

### T1.3 — Create the SSHGate SSH key

The SSHGate dedicated SSH key (`sshgate_ed25519`) is what
`sshgate.add_server` lays into each remote's `authorized_keys` behind
the `command="~/.velgate/velgate"` forcing entry. The key never
leaves the laptop; the public half goes to the remote.

```bash
mkdir -p "${HOME}/.config/sshgate/ssh" && chmod 700 "${HOME}/.config/sshgate/ssh"
```

Skip key generation if it already exists (idempotent):

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && echo "exists" || ssh-keygen -t ed25519 -N '' -C 'sshgate-dedicated' -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Verify mode is 0600:

```bash
stat -c '%a' "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Expect `600`. If looser (e.g. 644), tighten:

```bash
chmod 600 "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
chmod 644 "${HOME}/.config/sshgate/ssh/sshgate_ed25519.pub"
```

### T1.4 — Initialise the registry

```bash
mkdir -p "${HOME}/.config/sshgate" && touch "${HOME}/.config/sshgate/servers.json"
```

If the file is empty (a fresh `touch` left it 0 bytes), write the
empty-registry JSON skeleton:

```bash
test -s "${HOME}/.config/sshgate/servers.json" || echo '{"servers":{}}' > "${HOME}/.config/sshgate/servers.json"
```

### T1.5 — Summarise

Print verbatim (substituting the real PLUGIN_ROOT):

> SSHGate tier 1 (read-only) is ready.
>
> - SSH key: ~/.config/sshgate/ssh/sshgate_ed25519
> - Registry: ~/.config/sshgate/servers.json
> - velgate binary: <PLUGIN_ROOT>/bin/velgate-linux-amd64
>
> Add a server:
>
>     /sshgate:add <alias> <user@host>
>
> Reads will work through the gate; writes will be denied locally with:
>
>     velgate: no signing key configured (read-only install — re-run /sshgate:setup to add a signer)
>
> Re-run /sshgate:setup any time to add a Telegram signer.

If the caller picked Tier 1, stop here. If they picked Tier 2,
continue to **Tier 2 flow** (Tier-1 state is the prerequisite).

---

## Tier 2 flow — local Telegram signer

This builds on Tier 1 (which must be in place — re-probe Step 0 if you
got here without running Tier 1 first).

### T2.1 — Build velsigner

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/velsigner ./src/velsigner/cmd/velsigner
```

### T2.2 — Run the installer (first pass)

`scripts/install.sh` is the single entry point for the system-level
install (velsigner user, /var/lib/velsigner/ skeleton, systemd unit,
--init for the signing keypair).

**PAUSE** and tell the user verbatim:

> Open a separate terminal and run:
>
>     sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh
>
> (replace `${CLAUDE_PLUGIN_ROOT}` with the actual path printed below).
>
> The script is idempotent — safe to re-run if it fails partway. Tell
> me when it's done.

Print the resolved path with:

```bash
echo "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh"
```

After confirmation, verify the daemon:

```bash
systemctl is-active velsigner
```

Expect `active`. If `failed`, run:

```bash
journalctl -u velsigner -n 30 --no-pager
```

…surface the output and stop. The user may need `newgrp velsigner`
(or a fresh login) before subsequent commands can read
`/var/lib/velsigner/` without sudo.

### T2.3 — Tier 2 — Telegram configure

The `--init`-generated config has `type = "stub"`. Switch it to
`telegram` and add the user_id + chatstore pointers.

**PAUSE** and tell the user:

> Find your numeric Telegram user_id. Easiest way: message @userinfobot
> on Telegram and copy the `Id:` line.

Use `AskUserQuestion` with:
`"What is your Telegram user_id? (numeric, e.g. 12345678)"`

Then sanity-check the answer with:

```bash
printf '%s' "<ANSWER>" | grep -Eq '^[0-9]+$' && echo "ok" || echo "bad: not a positive integer"
```

If bad, re-ask.

Read the current config so you know what `--init` produced:

```bash
sudo cat /var/lib/velsigner/config/config.toml
```

If the file already has `type = "telegram"` AND a `[backend.telegram]`
block with this user's id, log "config already configured for telegram;
skipping" and proceed to T2.4.

Otherwise, tell the user to run (substituting their user_id for `NNNN`):

```bash
sudo tee -a /var/lib/velsigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path        = "/var/lib/velsigner/tokens/telegram.token"
allowed_user_id   = NNNN
chatstore_path    = "/var/lib/velsigner/config/peer.json"
EOF
```

…and then flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' /var/lib/velsigner/config/config.toml
```

Re-read the file and confirm with the user (`type = "telegram"`, the
three telegram keys, no duplicates). If duplicates exist, ask the user
to clean by hand.

### T2.4 — Run the installer again (token + restart)

Now that the config selects telegram, re-running install.sh will
prompt for the bot token (echoed nothing — `read -rs`) and restart
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

### T2.5 — Capture chat_id from /start

**PAUSE** and tell the user:

> Open Telegram, find the bot you just created (search the username
> you gave to @BotFather), and send `/start`. velsigner's poller will
> capture your chat_id and write it to
> `/var/lib/velsigner/config/peer.json`.

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
stop and surface `journalctl -u velsigner -n 30 --no-pager`.

### T2.6 — Push velgate.pub to all registered servers

The signer is now live with a new master key. Every server registered
in tier 1 has velgate but NO velgate.pub on it — pushing the pubkey
flips each one from "read-only" to "signed-write."

Make the pubkey available to the MCP layer at the canonical local
path:

```bash
mkdir -p "${HOME}/.config/sshgate/pubkey-distrib"
sudo cp /var/lib/velsigner/keys/velgate.pub "${HOME}/.config/sshgate/pubkey-distrib/velgate.pub"
sudo chown "$USER" "${HOME}/.config/sshgate/pubkey-distrib/velgate.pub"
chmod 644 "${HOME}/.config/sshgate/pubkey-distrib/velgate.pub"
```

Then enumerate the servers in the registry:

```bash
jq -r '.servers | keys[]' "${HOME}/.config/sshgate/servers.json" 2>/dev/null || echo "(no servers registered)"
```

If the list is empty, skip to T2.7 — there's nothing to upgrade.

For each registered alias, tell the user to run (from a Claude
session attached to this MCP server, since the upgrade routes through
the bootstrap leg which needs the operator's normal SSH access):

> For each alias listed above, re-run `/sshgate:add <alias> <user@host> --read-only=false`
> using the SAME bootstrap credentials you used originally. The
> `add_server` tool will detect the existing restricted entry and
> push the new velgate.pub idempotently.

(If a real automation hook lands later — e.g. an `upgrade_server`
MCP tool — surface that here instead.)

### T2.7 — Final summary

Print verbatim:

> SSHGate tier 2 (local Telegram signer) is installed.
>
> - Daemon: velsigner (active, running as user `velsigner`)
> - Socket: /run/velsigner/sock
> - Audit log: /var/lib/velsigner/log/approvals.log
> - Telegram bot chat_id captured: <N>
> - velgate.pub distributed to: <list of registered aliases>
>
> Reads route directly; writes will buzz your phone for approval.
>
> Re-run /sshgate:setup any time — it's idempotent and detects the
> current tier.

---

## Verify flow

Run these checks in order; report each one's pass/fail.

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && stat -c '%a' "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Expect `600`.

```bash
test -f "${HOME}/.config/sshgate/servers.json" && jq -r '.servers | length' "${HOME}/.config/sshgate/servers.json"
```

Reports the count of registered servers.

If Tier 2 is supposed to be present:

```bash
getent passwd velsigner
systemctl is-active velsigner
sudo test -f /var/lib/velsigner/keys/velgate.key && echo "key:yes" || echo "key:no"
sudo test -f /var/lib/velsigner/config/peer.json && echo "peer:yes" || echo "peer:no"
sudo -u velsigner /usr/local/bin/velsigner --version
```

Report each line. Any failure tells the user which tier-2 piece is
missing and points back at the relevant section.
