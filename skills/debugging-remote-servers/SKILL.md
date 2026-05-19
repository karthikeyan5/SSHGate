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

## Denial handling

If the user taps Deny (or the 60s window expires), the tool returns
an error like `denied by operator` or `approval timed out`. **Do not
loop.** Resubmitting the same batch the user just denied is rude.
Instead:

1. Surface the denial verbatim.
2. Ask why — there's usually context you don't have (wrong time,
   wrong server, command needs a tweak).
3. Propose an alternative or stop and wait for direction.

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
- **Redirects (`>`, `>>`)** are ALWAYS WRITE, regardless of what's on
  the left side.
- **Command substitution `$(...)`** and **process substitution
  `<(...)`, `>(...)`** are ALWAYS WRITE (fail-safe: the classifier
  doesn't try to inspect the substituted command).
- **`tee`, `sudo`, `find -delete / -exec / -fprint*`, `awk` with
  `system()`, `sed` with `e`/`w`/`r` flags** — always WRITE
  (true-write triggers, no exceptions).
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
