---
description: Run a single command on a registered server (rarely needed — Claude usually calls the tool directly)
argument-hint: <alias> <command...>
allowed-tools: mcp__sshgate__run
---

The user invoked `/sshgate:run <alias> <command...>`. This is the
explicit entry point for the `sshgate.run` MCP tool. In ordinary use,
the user types something like "run df -h on prod-db" and Claude calls
the tool directly — this slash command is the scriptable / belt-and-
suspenders form.

Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`.
- `command` — everything after the alias, joined with single spaces.
  Preserve the user's quoting as-is; do not re-quote.

If either is missing or alias is malformed, print:

```
Usage: /sshgate:run <alias> <command...>
Alias must match [a-z][a-z0-9-]{0,30}.
```

…and stop. Do not prompt inline.

Call `mcp__sshgate__run` with `{ "alias": "<alias>", "command": "<command>" }`.

The tool classifies the command:
- Read → executes immediately, no approval.
- Write → requests approval via the signer; the user gets a Telegram
  prompt. Tell the user that's coming if `classification.kind == "write"`
  is observable from the tool output; otherwise just wait.

Surface the tool's output structure:

```
exit:   <exit_code>
stdout:
<stdout>
stderr:
<stderr>
```

Omit empty stdout/stderr sections. If `exit_code` is non-zero, lead
with that. If the tool itself errors (denied, timeout, sshgate-signer-telegram
unreachable, unknown alias), surface the error verbatim — do not
re-interpret it.

Do not run a follow-up command on your own. Stop after one
invocation.
