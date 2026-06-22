# Proposal: Standing Grants, Secret-Read, Server-Binding, Audit Trail, Window Tightening

**Status:** proposal — not yet implemented. Awaiting Karthi's ratify, then TDD build + triple review + PII audit before any push.
**Date:** 2026-06-22
**Driver:** the server-consolidation migration (#27) needs unattended overnight write windows; the discussion surfaced several related gate/signer changes.

This bundles features that all touch the **signed payload** (`sigwire.SigPayload`), so they ship as one coherent wire change (gate + signer redeployed in lockstep — `DecodeSigned` uses `DisallowUnknownFields`, so old gates fail closed on a new payload, which is the safe degrade).

---

## 0. Invariants we preserve

- **The gate stays stateless.** No runtime state, no nonce store, no job table. The only files the gate reads are its binary, `gate.pub`, and (new) the host's own SSH host public key. Grants and reveal are *signed payloads presented with each command*, never gate-side state. Long-running job state lives in the **OS process table + files on the target**, not in the gate.
- **Every elevated capability is encoded in the SIGNED payload** that the human approves. The agent can *request*; only the signer (on Karthi's tap) *grants*; the gate *enforces* against the verified signature. The agent can never self-elevate, and the gate can never self-grant.
- **The gate is the authoritative enforcement point** (independent of the signer), as today.

---

## 1. Long-running commands, concurrency, and "is the agent blind?" (grounding + answer)

**How it works today (verified):**
- `run`/`run_batch` are **synchronous and buffered**: `ssh.Client.Run` blocks until the remote command exits and returns stdout/stderr all at once (`src/mcp/ssh/client.go:120-124`). There is **no streaming**.
- **No execution-duration cap.** The SSH client `Timeout` (prod = 30s, `sshgate-mcp/main.go:47,140`) bounds **dial + handshake only** — the conn deadline is *cleared* after the handshake (`client.go:100`); exec is bounded only by the parent ctx, which is the MCP root ctx (`context.Background()` + signal, `main.go:88`) → **no deadline**. So a 30-minute command runs to completion. The gate likewise runs under a signal-only ctx (`gate main.go:179`) — unbounded. ✅ Long single commands already work.
  - **Doc bug to fix:** `client.go:27` claims `Timeout` "bounds the entire dial+auth+exec window." It does not (deadline cleared post-handshake). Fix the comment and add a regression test asserting a >Timeout command still completes, so nobody "fixes" it into killing long commands.
- **The real limitation Karthi flagged is real:** because `run` is synchronous, a naive `run("mysqldump … 30 min")` **blocks the agent's turn** for 30 minutes with no visibility and no way to query/kill. That is a blind state.
- `run_batch` runs each command as a **separate SSH session, sequentially** (`run_batch.go:173-184`), but all write sigs are minted at **one** approval with a 60s TTL each — so if an early command runs long, later commands' sigs expire (exit 65) before their turn.

**Answer (no gate state needed): detached-launch + poll-by-PID.** For any long op, the agent launches it detached and polls:
1. `run("nohup <cmd> >job.log 2>&1 & echo $!")` → returns the **PID** immediately (the shell backgrounds + exits; the gate process exits; the detached child survives).
2. Poll with cheap **reads**: `tail job.log`, `ps -p <pid>`, `ls -l <output>`, `cat done.flag`.
3. Control with **writes**: `kill <pid>`.
4. Completion signal: launch as `nohup sh -c '<cmd>; echo $? >done.flag' &`.

The **"executor ID" Karthi described = the OS PID** (or a per-job dir with a flag file). State lives in the OS + filesystem on the target — the gate stays stateless. Response correlation is 1:1 per `run` call (each poll is its own request/response); nothing is fire-and-forget. This pattern goes into the migration playbook as the required idiom for long ops, and means **no executor-ID/job-table is added to the gate**.

**Gate control verbs stay minimal.** Today the gate interprets exactly: empty-probe → `SSHGATE_OK`, `SSHGATE_REVOKE`, `SSHGATE_UPDATE` (stub); everything else → `/bin/sh -c`. Monitoring needs **no new verbs** (`ps`/`kill`/`tail` are ordinary shell). We keep the gate-verb namespace tiny — good for statelessness and attack surface.

**Part-A clarifications (Karthi's questions, 2026-06-22 — grounded):**
- **No persistent connection.** Each `run` dials a fresh TCP+SSH, runs ONE command, tears down (`client.go:18-19,79-124`); `run_batch` re-dials per command. No pool, no keepalive, no reconnect. Every `run` is its own synchronous request→response, so reply-correlation is 1:1 by construction — there's no "whose reply is this?" ambiguity.
- **The agent gets back exactly what the command printed** (raw stdout+stderr+exit, `run.go:35-45,154-160`) — nothing else. So `nohup … & echo $!` returns just the PID; a normal command returns its output. PID vs output is purely a function of what you run; the gate has **no custom wire format** for ordinary commands (only the `SSHGATE_SIG:` prefix on writes + control verbs).
- **Yes, the agent polls** (by design): a detached job + cheap read-polls keeps the gate stateless, doesn't block the agent's turn, and — crucially — **survives pipe-breaks** (the `nohup` job lives on; only the current poll fails, the next re-dials). A synchronous long `run` instead dies on pipe-break (SIGHUP) and blocks the agent. Server-push/streaming would need gate state + a held connection. So poll-a-detached-job is the robust choice, not a compromise.
- **Regular-terminal login:** there is **no interactive shell today** — the gate key is locked to `command=`; `ssh <box>` (even `-t`) returns `SSHGATE_OK` and closes (`sshgate-gate/main.go:88-93`, `authorizedkeys.go:18`). Humans reach these boxes out-of-band with their own admin creds (how the gate key got pasted). A **gated interactive shell** is future roadmap (§9).

---

## 2. Signature window: ts vs exp, one-field, timezone, 1-minute default

**The two checks (`src/gate/verify.go`):**
- `:60` `now < exp` — has it expired? (`exp` is the **"valid till"** — exactly your mental model.)
- `:68` `exp − ts ≤ 5 min` — caps the **maximum validity window** so a buggy/hostile signer can't mint a long-lived token. `exp` = `ts + ttl` (signer-set); the gate independently re-caps.

**Timezone:** `ts`/`exp` are **Unix epoch seconds (int64, UTC)** — timezone is irrelevant (`now.Unix()`). Only **clock skew** between signer host and target matters (a skewed clock breaks the app *and* the gate's `now < exp`).

**One-field simplification (your idea):** feasible — drop `ts`, keep only `exp`, and have the gate check `now < exp` AND `exp − now ≤ Max`. **Trade-off to decide:** the current `exp − ts` caps the *issued* window using the signer's clock (skew-immune for the cap); `exp − now` caps the *remaining* window using the gate's clock (skew-**sensitive**). With a tight 1-min default, skew tolerance matters, so **recommendation: keep `ts`** (it's free, keeps the window-cap skew-robust, and feeds the audit log's "signed-at"). You already have your "valid till" — it's `exp`. *(Open: drop `ts` anyway for minimalism? Recommend no.)*

**Default window → 60s (your call):** change `DefaultWriteTTLSec` 120→60 and keep `BatchWriteTTLSec` 60. Because the gate checks `now < exp` only at **receipt** (then runs unbounded), 60s is plenty for any single command (it's received instantly after signing, then runs as long as it needs). Longer windows are only needed for *sequential batches of long commands* — which the agent requests explicitly (5/10-min, with a reason) or covers via a standing grant. Shrinks the replay window 2×.

---

## 3. Per-server identity & spoof-resistance (the "robust" requirement)

**Problem:** the same `gate.pub` is on every Tier-2 server and the signed payload carries no server identity, so a signature approved for server X verifies on any Tier-2 box (replay bounded only by the window). A 24h grant makes this unacceptable.

**Design — bind to the target's SSH host key:**
- Add a `host` field to the signed payload = the target's SSH **host-key fingerprint** (the one the MCP TOFU-pinned at provision, already in `known_hosts`).
- The **signer** puts the target's fingerprint into the payload when signing for that alias (the MCP supplies it from `known_hosts`).
- The **gate** reads its *own* host public key (`/etc/ssh/ssh_host_*.pub`, world-readable) and rejects unless `payload.host` matches one of its own host keys.
- **Spoof-resistance:** a captured signature for X cannot run on Y (Y's gate computes Y's fingerprint ≠ X's). Forging a payload for Y needs the master signing key. Binding is to the **machine's real identity**, not a writable label.
- **Stateless:** the gate reads an existing OS file; nothing new is synced (both sides derive from the host key). If the host key rotates (rebuild), the binding breaks → re-provision (a desirable property: a replaced machine must be re-trusted).
- Applies to **every** signature (per-command and grants), closing cross-server replay generally.
- *Alternative considered:* a provision-written `~/.sshgate-gate/server_id` file — simpler but a writable label and needs a new provision write; **host-key binding preferred.**
- **Residual (inherent to host-key binding, not a defect):** two machines that genuinely **share** their `/etc/ssh` host keys (a cloned VM / golden image) are **one identity** to this mechanism — a signature bound to one verifies on the other. This is the standard property of host-key binding. **Migration implication:** confirm the source/target boxes have *distinct* host keys (they will, unless cloned from the same image); if any were cloned, regenerate host keys before relying on per-server binding to separate them.

---

## 4. Standing grants (the keystone — replaces the spec's "Time-Scoped Tokens" §155)

A **signed grant** the signer issues on one approval, carrying `{scope, window, host}`:
- **Scope = `all`** → any command on that server runs without a fresh tap (used for the fresh **target** during the overnight build).
- **Scope = exact command-set** → only the pre-shown, exact command strings auto-run (used for the **source** boxes: shutdown + backup + ship). *Exact-string match, no patterns* (Karthi's call — no ambiguity).
- **Server-bound** via the host-key fingerprint (§3) → a target grant physically cannot run on a source.
- **Window ≤ 24h** hard ceiling (Karthi's call; gate enforces the ceiling independent of the signer).
- **Revocable:** stopping the signer kills all grants; plus an explicit revoke. The grant is presented with each command (stateless gate); revoking = the signer/MCP stops presenting it and/or a deny-list.
- **Audited:** the grant issuance and every command run under it are logged (§6).
- **Replay posture:** within the window a grant authorizes its scope by design; the mitigations are **server-binding** (can't cross machines) + **exact-command-set scope** on the sensitive source boxes (only the approved commands, nothing else). The `all` scope is reserved for the throwaway target.

"Extended-TTL" is the degenerate case (scope = a few commands, longer window) — same primitive.

---

## 5. Secret-read / reveal (orthogonal, agreed)

- Add `reveal bool` (omitempty) to the signed payload. Single seam: `executor.go:70` becomes `if !opts.Reveal && len(opts.Rules) > 0` → that one command's output is **not** redacted.
- **Single command only** (never in `run_batch`, no bulk reveal). Mandatory agent **reason**, shown to Karthi.
- **Distinct, scary approval UX** ("⚠️ SECRET-REVEAL — output will NOT be redacted; raw values go to the agent + AI provider + this chat").
- **Accepted exposure (eyes open):** an approved reveal pushes the raw secret into the agent context → Anthropic → the session transcript → possibly Telegram. For the migration, prefer moving secret *files* box-to-box (never read); reveal is for the rare case a value must be *seen*.

---

## 6. Audit trail — TWO TIERS (Karthi's correction 2026-06-22: the authoritative log MUST be gate-side)

The original "MCP-side only" plan was wrong: the agent shares the MCP's trust domain, so an MCP-side log is erasable by the very actor it audits. Split into two logs with different jobs:

### 6a. Gate-side authoritative log (tamper-resistant — the record that matters)
- **Written by the gate, on the target host**, for every command it sees (reads + writes + rejections) — classification, approval status, exit code, output **metadata** (bytes/lines/duration), NOT raw output by default.
- **Tamper-resistance:** the log is owned by a **separate user** (not the gate's run-as user), so the agent — which only ever speaks *through* the gate — cannot rewrite or delete it. Mechanism, strongest-available-by-privilege: if provisioning has root → a dedicated `sshgate-audit` user + append-only (`chattr +a` / syslog-journald which the gate's user can't rewrite); if only the unprivileged target user → best-effort restrictive perms + separate group. **Accepted limit (Karthi):** a full write-bypass that nukes the folder is tolerable — "if they're in, the logs are the least of our problems." Defense-in-depth, not perfection.
- **Does NOT break statelessness:** append-only logging is a *side effect*; the gate never *reads* the log to make a decision. It stays a pure (payload, command) → (allow/deny, exec) function.
- **Leveled + configurable, write-gated:** levels below; the level is set via the human `sshgate` control plane, never an agent tool — the agent can't quiet its own audit.

### 6b. MCP-side live/convenience log (rolling, full-output — powers the live view)
- **Size-capped rolling buffer** (terminal-scrollback style — older lines auto-dropped; a bit larger since it's on disk). Holds the **whole** command + full output. Auto-rolls/clears, so it's transient by design.
- This is what `tail -f` watches for a **live operator view** — it **subsumes "Live Command View"** (§7). It is a convenience/observability surface, NOT the system of record (that's 6a).

### Levels (apply to the gate-side authoritative log; default in bold)
- `off`
- `writes` — write commands only
- `all` — read + write commands
- **`all+meta`** (default) — all commands + rejections + output metadata (size/lines/duration/exit), **no raw output**
- `all+full` — everything incl. full output (verbose)
- Rejections/denials always logged from `writes` up.

### 6c. As-built notes (TDD landing, 2026-06-22)

**Tier 6a — gate-side authoritative log** (`src/gate/audit.go`, wired in `src/gate/cmd/sshgate-gate/main.go`):
- One append-only JSON-Lines record per command at the gate dispatch chokepoint — read, write, AND rejection. Fields: `ts` (UTC epoch), `command`, `classification` (read/write), `approval_status` (`signed` / `unsigned` / `denied`), `exit_code`, and `meta` (`stdout_bytes`/`stderr_bytes`/`lines`/`duration_ms`) at `all+meta`+. Raw `stdout`/`stderr` only at `all+full`.
- **Leveling** read from `~/.sshgate-gate/audit-level` (one token per the list above); **default `all+meta`** when the file is absent/unreadable/garbage — `ParseAuditLevel` fails to the default, the gate never crashes on bad config. `Record` additionally blanks raw output below `all+full` (belt-and-braces: `all+meta` provably cannot leak raw output).
- **Output metadata** comes from the widened executor (below). Counts are measured **post-redaction** — what the agent actually receives. `all+full` makes the executor tee a **capped** copy (256 KiB/stream, truncation-marked) so the level is meaningful without unbounded gate memory.
- **Append-only + fsync**, opened `O_APPEND|O_CREATE|O_WRONLY` mode 0640, **open→append→fsync→close per invocation** (a fresh gate per `SSH_ORIGINAL_COMMAND`, so per-invocation == per-command). The gate never holds an FD between commands and **never reads the log back** — statelessness preserved.
- **Path is configurable** via `~/.sshgate-gate/audit-path` (default `~/.sshgate-gate/audit.log`) so an admin can point it at a separate-user-owned append-only location.
- **Fail-open:** every audit error (open/write/fsync/marshal) is swallowed — a logging failure NEVER blocks the command (the audit is a side effect, not a gate; the gate also has no safe out-of-band error sink, since stderr is the SSH stream). Tested with an unwritable path.
- **Config-change protection:** the level/path files live in the gate dir. Changing them through a gate command is itself a WRITE (signed + approved); an admin with box access edits them directly. The agent cannot silently quiet its own audit.

**Tamper-resistance posture — what is built vs deferred (IMPORTANT):**
- The gate writes **append-only + fsync** regardless of who owns the directory — that is the best-effort baseline and it always holds.
- **TRUE tamper-resistance requires a root-time setup that SSHGate does NOT automate:** a dedicated `sshgate-audit` user owning an append-only directory (`chattr +a`, or a journald/syslog sink the gate's run-as user cannot rewrite), with the gate's run-as user granted append-but-not-rewrite/delete. An admin provisions that out-of-band and points `audit-path` at it. **We deliberately do NOT build root provisioning automation here** (out of scope, and root-time host policy is the admin's call).
- Absent that setup, the log degrades to **gate-user-owned best-effort append-only** — defense in depth, not perfection. Per Karthi's accepted limit: a full host compromise that nukes the folder is tolerable ("if they're in, the logs are the least of our problems").

**Executor widening** (`src/gate/executor.go`): `ExecWithRedaction` now returns `(ExecResult, error)` instead of `(int, error)`. `ExecResult` carries `ExitCode` plus `StdoutBytes`/`StderrBytes`/`Lines`/`Duration` (and, only when `CaptureLimit>0`, a capped `Stdout`/`Stderr`). Counting writers sit **below** the redactor so byte/line counts reflect the post-redaction stream. Existing redaction + reveal behaviour is unchanged (the redactor wiring and the `Reveal`/`Rules` seam are untouched; only the destination is wrapped in a counting writer).

**Tier 6b — MCP-side rolling live log** (`src/mcp/livelog/`, wired in `src/mcp/server.go` `runHandler`/`runBatchHandler`, configured in `src/mcp/cmd/sshgate-mcp/main.go`):
- Size-capped **rolling** JSON-Lines at `~/.config/sshgate/audit-live.log`, holding the **whole** command + **full** output per command (one entry per `run`, one per non-skipped `run_batch` result). When the file exceeds the cap it is rewritten keeping only the newest suffix of complete lines (oldest dropped, terminal-scrollback style) via a temp-file + atomic rename.
- **On by default**, cap = **5 MiB**, configurable via `~/.config/sshgate/audit-live-cap` (byte count; `0` disables — a nil log, a silent no-op). Fail-open like 6a.
- This is the `tail -f` operator view and **subsumes "Live Command View"**; it is the convenience surface, **NOT** the system of record (that's 6a).

---

## 7. Minor / deferred

- **`servers.json` perms — ALREADY 0600 (verified 2026-06-22).** The earlier "currently 0644" claim was **incorrect**: the registry has written 0600 since its original commit (`tmp.Chmod(0o600)` in the tmp+fsync+rename `persist()` path, `src/mcp/registry/servers.go:204`). So this is a no-op; the leaf just added perm-assertion coverage across all three persist paths (create / rewrite-in-place / remove). Encrypt-at-rest (age/kiln) dropped as over-spec for non-secret metadata.
- **Auto-update (`SSHGATE_UPDATE`)** — defer; **add to the roadmap** as a next-feature-set item (sort out its security separately). For now, redeploy a changed gate via `sshgate` CLI (revoke + re-add).
- **Live Command View** — now explicitly delivered by the **MCP-side rolling log (§6b)**: a real-time operator stream via `tail -f`. No dedicated UI unless Karthi wants one later.

---

## 8. Sequencing vs the migration (Karthi's call 2026-06-22)

**The migration waits for the FULL feature build to be done AND tested — it does NOT run in parallel with the build.** Karthi's reasoning: the gate is still changing under this build; he wants to test the whole thing end-to-end once, on a stable gate, then migrate. So: finish + test all features → then Phase A (inventory) → then Phase B (unattended, least-consequential-first cutover). The *build* is parallelized as far as the dependency graph allows (below); the *migration* is strictly after.

**Build order (parallelized where the dependency graph allows):**
- **Spine — SEQUENTIAL (security core, shared files):** payload wire change (`host`/`scope`/`window`/`reveal`, `DisallowUnknownFields` fail-closed) + verify.go (host-binding check, 60s default, keep `ts`, window cap) + gate reads its own host key. Parallel-editing these would corrupt the core, so one careful TDD implementer.
- **Leaves — FAN OUT after the spine lands** (parallel where files don't overlap; sequence the two that both touch `executor.go`): standing grants; reveal; two-tier audit (§6); servers.json 0600; docstring/exec-cap doc fix + regression test.
- **Separate gate security audit (Karthi's explicit ask): "make sure the gate is actually a gate."** An adversarial panel, each reviewer attacking ONE bypass class: read/write classifier bypass; cross-server replay (does host-binding actually hold?); grant-scope escape (is exact-command-set truly exact?); reveal abuse (batch leak / self-elevation?); payload forgery / unknown-field / signature edges; statelessness violation (did any feature sneak gate state in?); gate-side audit tamper. Adversarial verify, not self-report.
- Each feature: TDD → spec-compliance review → code-quality review → fix loops. Then whole-suite green + the gate security audit + **PII audit before any push**. Lands on a HELD branch; gate+signer redeploy in lockstep on merge.

---

## 9. Resolved (Karthi, 2026-06-22)

1. **`ts`:** KEEP (no one-field change). ✅
2. **Per-server binding:** host-key fingerprint (the recommended option). ✅
3. **Audit:** restructured to **two tiers** (§6) — gate-side authoritative (tamper-resistant, separate-user, append-only) + MCP-side rolling full-output live view. `all+meta` default stands. ✅
4. **Migration timing:** strictly AFTER the full build + test (§8). ✅

**Future / roadmap (not in this build):**
- **Gated interactive shell** ("login from a regular terminal" *through* SSHGate, every keystroke classified/approved/audited) — already tracked as task #25. Today the gate gives no interactive shell to anyone (forced-command intercepts → `SSHGATE_OK` → close); humans reach the boxes out-of-band with their own admin creds.
- **Auto-update (`SSHGATE_UPDATE`)** — defer; on the roadmap (§7).
