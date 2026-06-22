# SSHGate Roadmap

The forward-looking work for SSHGate, in priority order. This is the single
canonical roadmap; design rationale for individual items lives in the design and
decision docs referenced inline.

For the security model these items extend, see [design.md](design.md) and
[approval-architecture.md](approval-architecture.md).

---

## Already shipped

- **Human-only provisioning CLI.** Onboarding a server is a control-plane action
  done with the `sshgate` CLI (`pubkey` → paste → `add [--read-only]`), not an
  agent tool. The agent surface is exactly five tools (`run`, `run_batch`,
  `list_servers`, `status`, `revoke_server`); there is deliberately no
  `add_server` tool, so the agent can never expand its own reach.
- **Read-only (Tier-1) and signed-write (Tier-2) provisioning**, selectable at
  `sshgate add` time.
- **Inline secret redaction on the read path** in the gate.
- **Local Telegram signer** with separate-Unix-user key isolation, one-tap
  approval, and bulk (single-tap, N-command) approval.

---

## Next

These are the highest-priority forward items.

- **Standing grants, secret-reveal, per-server binding, audit trail (in progress).**
  A bundle that all touches the signed payload, so it ships as one wire change:
  signer-issued **standing grants** (scope `all` or an exact command-set, ≤24h,
  server-bound, revocable) for unattended write windows; an approved
  **secret-reveal** that bypasses output redaction for a single signed command;
  **per-server identity** binding each signature to the target's SSH host-key
  fingerprint (closes cross-server replay); a **two-tier audit trail** — a
  gate-side, separate-user, append-only authoritative log plus an MCP-side
  rolling full-output live view; plus a tighter 60s default signature window and
  `servers.json` 0600. Design at
  [docs/proposed/feature3-grants-reveal-audit-binding.md](proposed/feature3-grants-reveal-audit-binding.md).

- **Argv-exec structural classifier fix (#22).** Replace the fail-closed shell
  heuristic on the read path with direct execution from a parsed `argv`
  (`execve`, no intervening `/bin/sh`), so the classifier's view of a command is
  exactly the view that executes. This eliminates the entire shell-parse-mismatch
  class (escapes, quoting, separators, substitution, redirects) and ends the
  per-tool flag arms race. Read *pipelines* are handled by a safe mini-executor
  that verifies each stage's binary against the read allowlist and wires the
  stages without a shell, or are routed through approval. Likely combined with
  kernel-level confinement (read-only mounts + seccomp denying write/exec
  syscalls) for defense in depth.

- **Interactive prompt / confirmation / password forwarding (Feature 1).** A
  remote command can trigger an interactive prompt mid-run — a `sudo`/password
  prompt, a `[Y/n]` confirmation, an "are you sure?". The gate currently execs
  non-interactively, which would force the operator to SSH in by hand just to
  answer. Allocate a PTY for the remote command, detect a prompt or input stall,
  surface it to the operator (Telegram and/or a web UI), capture the response,
  and write it to the command's stdin. Passwords must be handled securely — never
  logged or echoed. Reuses the existing approval channel. A design proposal exists
  at [docs/proposed/feature1-interactive-prompt-forwarding.md](proposed/feature1-interactive-prompt-forwarding.md)
  to start from.

- **Read-only SQL via per-service adapters (Feature 2).** Full SQL access over
  SSH is effectively all-or-nothing today. Support **read-only** SQL queries
  against common engines (PostgreSQL, MariaDB, SQLite, …), with **write** SQL
  requiring a signature — the same read/write-plus-sign model the gate applies to
  shell, but applied to SQL. The architecture is a customized per-service
  whitelist **adapter** (a SQL adapter, a shell adapter, …) built one engine at a
  time. This pairs naturally with #22: explicit per-service argv/grammar-based
  adapters can *be* the structural replacement for the single heuristic shell
  classifier. Design the adapter framework and the argv-exec fix together. A design
  proposal exists at [docs/proposed/feature2-service-adapters-argv-exec.md](proposed/feature2-service-adapters-argv-exec.md)
  to start from.

---

## Planned

- **In-place Tier-1 → Tier-2 upgrade (#17).** Today, changing a server from
  read-only to signed-write means revoking and re-provisioning it. Provide a
  smoother in-place upgrade, including how the upgrade is surfaced and wired in
  the setup flow.

- **Gated interactive session mode (#25).** A shell-*like* interactive prompt
  (history, `cd`/env that feel normal) where **every** command is still gated.
  The safe form is *not* wrapping a live `/bin/sh` — that is the read-only arms
  race on hard mode (persistent shell state, `eval`, history, interactive-program
  escapes like `:!sh`). Instead the gate *is* the shell: it reads a line, parses
  it into `argv` itself, classifies it, runs it via argv-exec (no `/bin/sh`),
  prints output, and loops, tracking cwd/env itself. Interactive sub-programs
  (`vim`, `mysql`, …) are handled by the per-service adapters (Feature 2) or
  blocked. **Depends on the #22 argv-exec foundation; build after it.**

- **Friendlier gate responses (#26).** When the gate denies a write (or any
  command needing a signature), return a clear, structured, agent-friendly
  message stating *what* is needed and *how* to get it ("this is a write — it
  needs an approved signature; request approval, then resubmit with the
  `SSHGATE_SIG` envelope") instead of a bare reject/kill. In an agent-driven flow
  this is the handshake that tells the agent to go get approval and resubmit.
  Applies to current single-command mode now and to the gated session (#25)
  later, where a write could optionally trigger inline approval.

- **Gate auto-update (`SSHGATE_UPDATE`).** A signed control verb to update the
  gate binary in place (a stub handler already exists in the gate). Deferred
  until its security is designed separately: an update path is a code-execution
  path, so it must be at least as strict as the signing model — signed,
  versioned, fail-closed, and audited. Until then, a changed gate is redeployed
  via the `sshgate` CLI (revoke + re-add).

- **Signed-at-rest redactor (deferred).** Strengthen the redaction path's signing
  posture and merge the deferred redactor work.

---

## Deferred

- **Tier-3 hosted signer (the real boundary).** The headless backend exists — a
  signing engine, N-of-M approval, WebAuthn/TOTP auth, and a plane-separated API.
  What remains to ship it as a product: the rendered web UI (the backend serves
  JSON only), the Telegram channel on the hosted signer, a stable HTTPS hostname
  (passkeys are origin-bound), and deployment. This is the larger, recommended
  investment for anyone who needs an approval boundary that holds against a
  privileged rogue agent on the operating machine. See
  [approval-architecture.md](approval-architecture.md).

- **Redaction scanner performance work.** An Aho-Corasick / keyword-prefilter
  rewrite of the redaction scanner for large outputs. Security-sensitive, so
  deprioritized behind correctness work.

- **Sign-wire struct consolidation.** Internal cleanup of the signed-command
  request structures shared between the signer and the MCP, best done alongside
  the signed-at-rest envelope work.

---

Deferred / longer-term directions and the honest limitations of the shipped
surface: see [FUTURE.md](FUTURE.md).
