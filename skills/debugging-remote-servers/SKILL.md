---
name: debugging-remote-servers
description: This skill should be used when the user asks to debug, diagnose, or operate a remote server registered with SSHGate — phrases like "debug X on prod-db", "what's eating disk on staging", "restart nginx on the app server", "is my server reachable", "ssh into prod and check journalctl", "tail the logs on web-1", or "fix the broken nginx config on staging". Teaches the right tool order (list_servers → run for diagnostics → run_batch for fixes), the cost shape (reads are free, writes need one Telegram tap each), and the bulk-approval pattern that keeps multi-step fixes to a single approval.
---

# Debugging remote servers with SSHGate

SSHGate gives you SSH access to the user's registered servers through
three MCP tools: `sshgate.list_servers`, `sshgate.run`, and
`sshgate.run_batch`. Read commands run instantly. Write commands need
the user to tap a Telegram approval button on their phone. Optimise
for: fast diagnosis, one approval per fix, no surprises.

## Tool order

1. **`sshgate.list_servers`** first, every session, before touching
   anything. Confirms the alias the user mentioned is actually
   registered and surfaces the host/user so you can speak about it
   accurately. If the alias is not registered, say so and stop —
   suggest `/sshgate:add` rather than guessing.
2. **`sshgate.run`** for diagnostics. Reads execute on the remote
   immediately, no approval, no notification. Stream the output back
   and reason from it.
3. **`sshgate.run_batch`** for fixes. Group every write that belongs
   to one logical change into a single batch so the user approves
   once, not N times.
4. **`sshgate.run`** again at the end, to verify the fix landed.

## Cost shape — reads free, writes tap

Every write command triggers a Telegram DM to the user with the
command text and `[✓ Approve all] [✗ Deny]` buttons. The user is
probably away from the laptop; each prompt is a small interruption.

- A single `sshgate.run` with a write costs **one tap**.
- A `sshgate.run_batch` with N writes costs **one tap total** — the
  user approves the whole batch in one go.
- N separate `sshgate.run` calls with writes cost **N taps**. Avoid
  this. Always batch related writes.

Read commands cost nothing. Run as many as you need to understand
the situation.

## Diagnostics — the free part

For "what's wrong with X" questions, lead with these:

- `df -h` — disk full?
- `free -h` — memory pressure?
- `top -bn1 | head -30` — what's hot?
- `uptime` and `who` — when did it start, who's logged in?
- `systemctl status <unit>` — is the service alive?
- `journalctl -u <unit> -n 50 --no-pager` — recent log lines.
- `ss -tlnp` or `ss -tnp state established` — open sockets.
- `ls -lah <path>` / `cat <file>` — inspect specific paths.

All of these are reads. Fire them off one after another via
`sshgate.run`. The user does not get pinged.

## Fixes — the batched part

Before calling `run_batch`, **show the user the planned writes**. Use
a fenced block, exactly the commands you'll send, no surprises:

```
Planned writes on prod-db (one Telegram approval covers all 4):

  1. nginx -t                                # validate new config
  2. cp /etc/nginx/sites-available/app.conf /etc/nginx/sites-available/app.conf.bak
  3. tee /etc/nginx/sites-available/app.conf < /tmp/new-app.conf
  4. systemctl reload nginx

Approving the prompt on your phone will run them in order. Reply
"go" to proceed, or tell me to adjust.
```

Wait for the user to acknowledge. Then call `sshgate.run_batch` with
the same list, `stop_on_error: true` (the default — abort the
sequence if any step fails). Surface the per-step output verbatim
when it comes back. After a successful batch, run one more diagnostic
read (`systemctl status nginx`, `nginx -t`, whatever proves the fix)
to confirm.

## Read-only (Tier-1) servers — writes refused before any tap

A server can be registered **read-only** (`/sshgate:add … --read-only`):
the gate is installed but no signer pubkey was pushed, so it executes
reads and denies every write locally. When you send a write to such a
server, `sshgate.run` / `sshgate.run_batch` **refuse it before
soliciting any Telegram approval** — no tap is wasted — and return an
error like:

```
server "prod-db" is registered read-only — writes are denied at the
gate (no signer pubkey was pushed). Run /sshgate:setup to add a
Telegram signer, then re-run /sshgate:add prod-db <user@host> to
upgrade it to signed-write.
```

Do NOT retry. Surface that upgrade path to the user and stop. Reads on
the same server still work normally — keep diagnosing with `sshgate.run`.

## Denial, timeout, and signer-access handling

A failed write surfaces one of these. **Do not loop** on any of them —
resubmitting the same batch is rude and (for the first three) hopeless.

- **Denied** (`denied by operator`) — the user tapped Deny. Surface it
  verbatim; ask why (wrong time, wrong server, command needs a tweak);
  propose an alternative or wait for direction.
- **Timeout** (`approval timed out`) — the approval window elapsed
  (signer's default is ~5 minutes / 300s). The user was probably away. Tell them and
  offer to re-send when they're ready, but don't auto-resubmit.
- **Signer permission denied** (`signer socket … is present but not
  accessible (permission denied) — your shell/session is not yet in the
  sshgatesigner group`) — the daemon is ALIVE; the current Claude Code
  session just hasn't picked up `sshgatesigner` group membership. This
  happens right after the first `/sshgate:setup`. STOP and tell the user
  to **log out and back in, fully restart Claude Code, then run `/mcp`**
  to confirm the `sshgate` server is live before retrying. Do not treat
  this as "the daemon is dead."
- **Unreachable** (`signer unreachable` / "not configured") — if
  `sshgate.status` reports the socket `configured:false`, there is no
  signer at all (Tier-1 read-only): writes need `/sshgate:setup`. If it
  reports `configured:true` but UNREACHABLE, the daemon is installed but
  down — escalate with `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 50`.

### Gate deny exit codes (77 / 65)

A write that reaches the gate but is rejected there comes back with a
non-zero exit, now **annotated** with remediation: `sshgate.run`
surfaces it as the tool error; `sshgate.run_batch` folds it into the
failing command's stderr and the batch summary. You don't have to
memorise the codes, but:

- **exit 77** — missing signature OR the host has no signer pubkey
  (read-only / Tier-1). Check `sshgate.status`; if the signer is not
  configured, `/sshgate:setup` then re-`/sshgate:add` to upgrade.
- **exit 65** — bad / expired signature: usually clock skew or a stale
  approval. Retry once.

## Classification gotchas

The local classifier flags any command as a write if it can't prove
it's a read. A few non-obvious cases:

- **`journalctl --rotate`**, **`journalctl --vacuum-time=…`** — writes
  (they mutate the journal).
- **`apt update`** — write (mutates the apt cache).
- **`curl -X POST …`**, any non-GET HTTP method — write.
- **Pipelines are classified per-segment** (since v1.1). A pure-read
  pipeline like `cat /etc/hosts | grep foo` or `ps aux | grep nginx`
  is a READ — no Telegram approval. A pipeline with *any* write
  segment (e.g. `cat /etc/foo | tee /tmp/bar`, or `cmd > /tmp/x |
  echo done`) is a WRITE.
- **An unquoted newline is a command separator** (like `;`). The gate
  execs via `sh -c`, so `ls\nrm -rf x` runs two commands — the
  classifier splits on the newline and any write segment makes the
  whole thing a WRITE. (This closed a read-only-gate bypass where a
  read first line masked a write second line. Newlines *inside* quotes
  do not split.)
- **Redirects (`>`, `>>`)** are ALWAYS WRITE, regardless of what's on
  the left side.
- **Command substitution `$(...)`** and **process substitution
  `<(...)`, `>(...)`** are ALWAYS WRITE (fail-safe: the classifier
  doesn't try to inspect the substituted command).
- **`tee`, `sudo`, `find -delete / -exec / -fprint*`, `awk` with
  `system()`, `sed` with `e`/`w`/`r` script flags** — always WRITE
  (true-write triggers, no exceptions).
- **`sed -i` / `--in-place`, including bundled short flags** — always
  WRITE. The classifier catches the in-place flag even when it is
  bundled onto other no-arg flags, e.g. `sed -ni`, `sed -Ei`,
  `sed -ri`, `sed -si`, `sed -nri …`, and suffix forms like `-i.bak`.
  (A bundled `-i` editing in place is a file mutation, not a read —
  this closed a read-only-gate bypass.) Plain `sed 's/a/b/' file`
  with no `-i` and no dangerous script flag is still a READ.
- **`docker exec …`** — write (the inner command is opaque to the
  classifier).

If a pure-read pipeline still classifies as write (e.g. an obscure
read tool the classifier doesn't recognise), run the segments
unpipelined and grep the output yourself in the conversation.

## Concrete example — bulk-approval pattern

User: "The nginx config on prod-db is wrong; ssl_certificate points
at the old path. Fix it."

1. `sshgate.list_servers` → confirm `prod-db` is registered.
2. `sshgate.run prod-db "cat /etc/nginx/sites-available/app.conf"` →
   read the current config. Diagnose: `ssl_certificate` line points
   at `/etc/letsencrypt/live/old-domain/fullchain.pem`.
3. `sshgate.run prod-db "ls -la /etc/letsencrypt/live/"` → find the
   new cert dir.
4. Compose the fixed config locally (in conversation). Show it to
   the user.
5. Show the user the planned write batch:

   ```
   Planned writes on prod-db (one approval, 4 commands):
     1. cp /etc/nginx/sites-available/app.conf /etc/nginx/sites-available/app.conf.bak
     2. tee /etc/nginx/sites-available/app.conf < /tmp/new-app.conf
     3. nginx -t
     4. systemctl reload nginx
   ```

6. On "go" → `sshgate.run_batch` with those 4 commands. One Telegram
   tap covers all 4. Each command is still individually signed —
   audit log is preserved.
7. After approval and run, `sshgate.run prod-db "systemctl status
   nginx"` → confirm reload succeeded, no errors in the most recent
   log lines.

That's the pattern. One read pass → propose → one approval → one
verify pass.
