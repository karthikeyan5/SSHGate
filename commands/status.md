---
description: Show SSHGate health — signer socket + per-server reachability
argument-hint:
allowed-tools: mcp__sshgate__status
---

The user invoked `/sshgate:status`. Print a readable health report for
the local signer socket and every registered server.

Call the MCP tool `mcp__sshgate__status` with an empty input object.
The tool returns:

- `signer_socket`: `{ path, reachable, error }`
- `servers`: array of `{ alias, reachable, ping_ms, error }`

Format the result as two short sections. Signer first — it's the
load-bearing component, and if its socket is unreachable every
write-bound `sshgate.run` will fail.

```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: yes
```

If unreachable, surface the error verbatim and suggest
`systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 30 --no-pager`
as next steps. Do not run them yourself unless the user asks.

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
No servers registered. Add one with /sshgate:add <alias> <user@host>.
```

If the tool itself returns an error (not the same as a server being
unreachable — that's data), surface the error and stop. Don't guess
at health.
