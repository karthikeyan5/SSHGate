# Install SSHGate

> **For human users:** open a Claude Code session in any directory and paste:
>
>     follow https://github.com/karthikeyan5/SSHGate/blob/main/INSTALL.md to install sshgate
>
> (or `follow /path/to/local/SSHGate/INSTALL.md` if you've cloned locally)
>
> The agent does everything below. You'll be asked for sudo (Tier 2 only) and
> a Telegram bot token (Tier 2 only). Tier 1 is read-only and needs no sudo.

> **For Claude Code (or any) agent reading this:** you are installing SSHGate
> for the user. Execute the numbered steps in order. Surface errors verbatim
> and stop on first failure. Don't paraphrase commands — run them exactly.
> Every step is idempotent (safe to re-run).

> **Launch flag — NOT required.** Unlike c3, SSHGate does NOT need
> `--dangerously-load-development-channels`. SSHGate is a regular MCP plugin
> that exposes tool calls; approvals flow OUT to the user's phone via
> Telegram, never INTO the Claude conversation. Plain `claude` works.

---

## 1. Verify prerequisites

```bash
go version
```

If "command not found": tell the user to install Go ≥1.22 from
https://go.dev/dl/, then re-run this install. Stop.

If the printed version is older than 1.22: tell the user to upgrade Go and
re-run. Stop.

Tier 2 also needs `sudo` access on the local machine and a Telegram account
(for the approval bot). Tier 1 needs neither — defer those checks until the
user picks a tier in step 4.

The remote hosts must be Linux with SSH reachable. They get checked
per-server later via `/sshgate:add`, not here.

## 2. Clone the repo and add as a local marketplace

`/sshgate:setup` needs access to the full Go source tree (`src/`, `scripts/`,
`Makefile`). Claude Code's marketplace cache from a remote GitHub source only
ships the plugin subtree, not the build inputs. So the canonical install is:
clone the repo first, then point Claude Code at the local clone as a
marketplace.

Tell the user:

> "Pick a directory to keep the SSHGate source (e.g. `~/src`), then run:
>
>     mkdir -p ~/src && cd ~/src && git clone https://github.com/karthikeyan5/SSHGate
>
> Then in this Claude Code session, run these three slash commands and tell
> me when they're done:
>
>     /plugin marketplace add ~/src/SSHGate
>     /plugin install sshgate@sshgate
>     /reload-plugins
>
> Replace `~/src/SSHGate` with wherever you cloned. The `git clone` location
> is permanent — the plugin's `/sshgate:setup` reads source from there to
> compile binaries."

Wait for the user to confirm completion and capture the clone path (we'll
need it in step 3).

## 3. Verify the plugin loaded

After step 2's `/reload-plugins`, the SSHGate slash commands should be
available. Probe:

```bash
PLUGIN_ROOT=$(ls -d ~/.claude/plugins/cache/*/sshgate 2>/dev/null | head -1)
if [ -z "$PLUGIN_ROOT" ]; then
  echo "ERROR: sshgate plugin not found in ~/.claude/plugins/cache — did step 2 complete?"
  exit 1
fi
SRC_ROOT=$(cd "$PLUGIN_ROOT/../.." 2>/dev/null && pwd)
if [ -z "$SRC_ROOT" ] || [ ! -f "$SRC_ROOT/go.mod" ]; then
  # The marketplace.json points "source" at "." so PLUGIN_ROOT itself may be
  # the repo root. Try that.
  if [ -f "$PLUGIN_ROOT/go.mod" ]; then
    SRC_ROOT="$PLUGIN_ROOT"
  else
    echo "ERROR: no go.mod near $PLUGIN_ROOT — looks like the marketplace points at a remote GitHub source, not a local clone. Go back to step 2 and 'git clone' first, then 'marketplace add' the clone path."
    exit 1
  fi
fi
echo "Plugin source root: $SRC_ROOT"
```

If `go.mod` is missing, the marketplace was added with a remote source
rather than a local clone path. Stop and send the user back to step 2.

## 4. Run /sshgate:setup

`/sshgate:setup` is the tiered installer. It probes on-disk state, classifies
the current tier (fresh, tier-1 present, tier-2 present, or partial), and
either offers a tier menu or a re-run menu. It's idempotent — safe to invoke
any time.

Tell the user:

> "In this Claude Code session, run:
>
>     /sshgate:setup
>
> It will ask which tier you want:
>
>   - **Tier 1 (read-only)** — gate is deployed on remotes, no signer.
>     Reads work; writes are denied locally at the gate. No sudo, no
>     Telegram, fastest install (~2 min).
>   - **Tier 2 (local Telegram signer)** — full v1. Master keypair under
>     `sshgatesigner` system user, systemd unit, Telegram bot for
>     approvals. Writes need a phone tap. Adds ~10 min and a sudo run.
>   - **Tier 3 (hosted server signer)** — NOT YET AVAILABLE (v2.x).
>
> Pick Tier 1 first if you want to try SSHGate without committing to the
> phone-tap flow. You can upgrade to Tier 2 later by re-running this same
> command."

The setup command walks every step itself. For Tier 2 it will:

- Build `bin/sshgate-mcp`, `bin/sshgate-gate-linux-amd64`, `bin/sshgate-signer-telegram`.
- PAUSE for the user to run `sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh`
  in a separate terminal.
- Walk the Telegram config (user_id from @userinfobot, bot token from
  @BotFather, second install.sh pass).
- Capture chat_id from a `/start` Telegram message.
- (Optional) walk the LLM command-explainer setup at step T2.5b.

The agent driving this INSTALL.md script does NOT need to duplicate
`/sshgate:setup`'s logic — just invoke it and let the user respond to its
prompts. Surface errors verbatim if `/sshgate:setup` reports any.

## 5. Verify

After `/sshgate:setup` reports completion, run:

```
/sshgate:status
```

For a Tier 1 install with no servers yet registered, expect:

```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: no   (signer not configured for tier 1 — expected)

No servers registered. Add one with /sshgate:add <alias> <user@host>.
```

For a Tier 2 install with no servers yet, expect the signer socket
reachable. Either case is healthy at this point.

If `signer_socket.reachable: no` AND the user picked Tier 2, the daemon
didn't come up. Run `systemctl status sshgate-signer-telegram` and
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`, surface the
output, and ask the user whether to keep debugging or roll back.

## 6. Tell the user the install is complete

> "Installation complete.
>
> **No special launch flag needed** — plain `claude` is fine. (Unlike c3,
> SSHGate doesn't push channel notifications into the conversation; all
> tool I/O is normal MCP request/response, and approvals flow to your
> phone via Telegram.)
>
> Add a server:
>
>     /sshgate:add <alias> <user@host>
>
> Then ask me anything in plain English — `What's eating disk on prod-db?`
> or `Restart nginx on staging.` Reads stream back instantly. Writes
> queue for a Telegram approval and run after you tap approve.
>
> Useful slash commands going forward:
>   `/sshgate:setup`   — re-run the tiered installer (idempotent)
>   `/sshgate:status`  — health check signer + every registered server
>   `/sshgate:add`     — register a new server (auto-installs gate)
>   `/sshgate:run`     — explicit one-shot SSH command (debug aid)
>   `/sshgate:revoke`  — uninstall gate from a server (needs approval)
>
> Day-to-day guide: `docs/install-step-by-step.md` covers the manual flow
> and troubleshooting if anything in `/sshgate:setup` falls over."

End.

---

## Manual install (without an agent)

The same steps run by hand work fine — see
[`docs/install-step-by-step.md`](docs/install-step-by-step.md) for the full
human-readable walkthrough with copy-paste shell blocks for each tier, the
Telegram bot creation flow, the optional LLM command explainer, and the
troubleshooting guide.
