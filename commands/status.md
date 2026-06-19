---
description: Show SSHGate health — signer socket + per-server reachability
argument-hint:
allowed-tools: mcp__sshgate__status
---

The user invoked `/sshgate:status`. Print a readable health report for
the local signer socket and every registered server.

Call the MCP tool `mcp__sshgate__status` with an empty input object.
The tool returns:

- `signer_socket`: `{ path, configured, reachable, error }` (`configured` is true when the signer socket file exists; on Tier 1 it is false, which is normal)
- `servers`: array of `{ alias, reachable, ping_ms, error }`

Format the result as two short sections. Signer first — it's the
load-bearing component, and if its socket is unreachable every
write-bound `sshgate.run` will fail.

```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: yes
```

Branch on `signer_socket.configured` before deciding what to print:

- `configured: false` → this is a **Tier-1 (read-only)** install: no
  signer daemon exists, so an unreachable socket is EXPECTED. Print it
  as normal, e.g.:

  ```
  Signer
    socket:    /run/sshgatesigner/sock
    status:    not configured (read-only / Tier 1) — writes denied at the gate
  ```

  Do NOT suggest debugging the daemon; suggest `/sshgate:setup` to add a
  signer instead.
- `configured: true` AND `reachable: false` → a real Tier-2 daemon
  problem. Surface the error verbatim and suggest
  `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 30 --no-pager`. Do not run
  them yourself unless the user asks.

Then a per-server table (use plain text, not markdown tables — they
render poorly in the CLI):

```
Servers
  alias       reachable   ping
  prod-db     yes         42 ms
  staging     no          —      (dial tcp: i/o timeout)
```

If the registry is empty, say so plainly:

```
No servers registered. A human adds one with `sshgate pubkey` (paste the key into the host), then `sshgate add <alias> <user@host>`.
```

If the tool itself returns an error (not the same as a server being
unreachable — that's data), surface the error and stop. Don't guess
at health.
