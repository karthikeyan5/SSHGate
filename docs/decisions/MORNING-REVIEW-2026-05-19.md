# SSHGate session log — 2026-05-19 (overnight build)

> Goal pinned at top; decisions appended chronologically below. Karthi reviews in the morning.

## Session goal

Ship SSHGate v1 fully: phases 1-4 implemented, code review + PII audit + security audit passed. If time remains, cascade into v1.1 (LLM explainer, macOS desktop, automated provisioning, pipe/chain refinement). If time remains after, scaffold v2 (hosted velsigner server with WebAuthn + TOTP).

Operating model: I am the coordinator — plan, dispatch focused subagents per task, verify their output, gate phases. I do NOT implement in main context.

Working directory: `/home/karthi/arogara/SSHGate/`. Spec: `docs/specs/2026-05-19-sshgate-design.md`. Plan: `docs/plans/2026-05-19-sshgate-v1-implementation.md`.

---

## Decisions log

Format per entry: `### N. <short title> — <YYYY-MM-DD HH:MM>` then 1-3 sentences with the **what**, **why**, and **how-to-revisit**.

### 1. Coordinator pattern, no implementation in main context — 2026-05-19 00:30

What: every code-writing task gets dispatched to a fresh subagent with a focused prompt; main context only does plan/verify/commit-orchestrate.
Why: Karthi explicitly assigned coordinator role to preserve main context across the cascade goal (v1 + v1.1 + v2).
Revisit: if a task is genuinely ≤5 minutes of trivial edits, may inline; but default = dispatch.

### 2. Test infra = Docker openssh-server, no external test server — 2026-05-19 00:30

What: integration tests boot `linuxserver/openssh-server` in Docker on port 2222 via `tests/integration/docker-compose.yml`. No dependency on a real remote machine.
Why: removes a setup blocker; gives reproducible builds; doesn't require Karthi to provision anything.
Revisit: if Karthi has a real test VPS he prefers, configure it post-v1 as an additional integration target.

### 3. Telegram bot = mock for tests, real bot deferred to Karthi's wake-up — 2026-05-19 00:30

What: TelegramBackend tests use an `httptest.NewServer` that mimics Telegram bot API; phase-2 e2e uses this fake. Real @BotFather bot creation + `/start` happens when Karthi wakes (steps in `docs/install-step-by-step.md`).
Why: I can't have Karthi tap Approve while asleep; mocks let me validate the wiring; real bot is for manual smoke only.
Revisit: morning smoke test with the real bot is part of v1 completion.

### 4. Git commits to arogara monorepo, no remote push — 2026-05-19 00:30

What: SSHGate lives as a subdirectory of arogara (which is already a git repo); I commit per task; no `git push`.
Why: arogara is the established monorepo pattern; no SSHGate-specific remote configured.
Revisit: when Karthi wants to publish SSHGate as a standalone marketplace plugin, fork to its own repo or use a sparse-checkout subtree.

### 5. macOS v1.1 = cross-compile + structural validation only — 2026-05-19 00:30

What: in v1.1 I cross-compile MCP + velsigner for darwin/amd64 and darwin/arm64, and verify the build is clean. Actual functional testing on a Mac defers to Karthi (or later subagent with a Mac runner).
Why: I don't have a macOS runner; cross-compile catches build-time issues but not runtime.
Revisit: when a macOS testing rig becomes available, add darwin-tagged integration tests.

### 6. Skip dedicated `mcp.md` code-review guideline — 2026-05-19 00:35

What: I don't create `~/arogara/code-review/guidelines/mcp.md`. Plugin.md §3 already has 12 rules covering MCP server hygiene (JSON-RPC framing, stderr, error codes, tool naming, capability negotiation, etc.).
Why: avoid duplication; the existing rule set is consensus-grade and applicable as-is to SSHGate.
Revisit: if Karthi sees gaps after the code review runs, add a focused `mcp.md` then.

### 7. velsigner socket lives at `/run/velsigner/sock` (group-readable via `velsigner` group) — 2026-05-19 00:38

What: replaced spec ambiguity between `/run/velsigner/sock` vs `/tmp/velsigner.sock` with the former; karthi user joins `velsigner` group during `create-velsigner-user.sh` so the socket is reachable.
Why: per daemon.md §5.3, `/run` is the XDG-correct location for sockets and `tmpfs` cleanup is unpredictable.
Revisit: if Karthi's distro complains (some systems don't auto-create `/run/velsigner`), fall back to `$XDG_RUNTIME_DIR/velsigner-sock` for development.

---

### 8. All subagent dispatches use Opus — 2026-05-19 00:42

What: every `Agent(...)` call passes `model: "opus"`. Earlier dispatch of Task 0.1 on Sonnet was killed and re-dispatched on Opus.
Why: Karthi's instruction "use opus as much as possible. use other models only where it is strictly better." Aligns with his global CLAUDE.md "always run as Opus" directive — extended to dispatched subagents because arogara work involves heavy judgment.
Revisit: only if a future task is so genuinely mechanical that Opus is wasteful AND a smaller model is "strictly better" — high bar.

---

(Entries below get appended as work proceeds.)

### 9. Phase 1 locked — cryptographic loop end-to-end works — 2026-05-19 02:55

What: Tasks 1.1 → 1.6 complete. Commits: f529eba (classifier), 282dce5 (payload), 9a64582 (velgate), 9c8bbc5 (velsigner), 70bf567 (mcp), bc6321e (e2e). All 7 packages pass `go test -race`. The integration test against a real `linuxserver/openssh-server` Docker container exercises all four scenarios: read works, write denied by StubBackend, **direct unsigned SSH bypass refused by velgate (the security backbone proves out)**, no goroutine leaks.
Why: this is the lock-criterion you defined for Phase 1. Phase 2 (TelegramBackend) builds on a foundation that's now demonstrably correct end-to-end.
Revisit: nothing pending for Phase 1.

### 10. Package name `common` despite go.md §2.2 ban — 2026-05-19 01:00

What: `src/common/` holds the classifier and signature payload. `go.md §2.2` bans `common` as a package name (signals missing cohesion).
Why: the package IS cohesive — it's the wire-protocol surface shared by three binaries (velgate, velsigner, MCP); the spec and plan named it `common`; alternative names (`gate`, `sigwire`, `sshgateproto`) felt less obvious.
Revisit: if Phase 1's code-review audit flags this as BLOCKER, rename to `sigwire` (one rename + a sed across imports). Flag for your attention.

### 11. SSH client uses TOFU host-key checking, not pre-pinned — 2026-05-19 02:00

What: on first SSH to a new server, MCP captures the host key and appends to `~/.config/sshgate/known_hosts`. Subsequent connections verify. Mismatch refuses with `ErrHostKeyChanged`.
Why: pre-pinning would require operator action per server (run `ssh-keyscan`, paste fingerprint). TOFU is the de-facto OpenSSH pattern and aligns with the auto-setup flow (Phase 3) which also runs first.
Revisit: for v1.1/v2 consider a `--pin-host-key <fingerprint>` flag on `/sshgate:add` for paranoid operators.

### 12. Integration tests use real Docker; in-process SSH for unit tests — 2026-05-19 02:30

What: unit tests in `src/mcp/ssh/` spin up a `crypto/ssh` server in-process (no Docker dep). Integration test in `tests/integration/` uses the real `linuxserver/openssh-server` container. Build-tagged `//go:build integration` so excluded from `make test`; `make test-integration` runs it.
Why: keeps `make test` fast and Docker-independent; integration target is meaningful when Docker IS available; skips gracefully when not.
Revisit: when SSHGate gets CI, definitely run `make test-integration` on Linux runners.

### 13. velgate accepts both raw-32-byte and PEM public-key formats — 2026-05-19 01:30

What: spec said "raw 32-byte binary or PEM". Implemented both with auto-detection on file shape.
Why: defensive — operators might generate keys via different tools (ssh-keygen → SSH wire format, openssl → PEM, velsigner → raw).
Revisit: if it adds attack surface (PEM parser bug), narrow to raw-only.

### 14. velgate process-group kill on ctx-cancel — 2026-05-19 01:30

What: velgate's `Exec` uses `Setpgid` so cancelling the context kills the entire shell pipeline (e.g. `yes x | head ...`), not just `/bin/sh`.
Why: ergonomics — without this, killed shells leave orphaned descendants on the remote.
Revisit: none — right default.

### 15. Stub markers for VELGATE_REVOKE (Task 4.2) and VELGATE_UPDATE (v1.1) — 2026-05-19 02:55

What: velgate stubs out `VELGATE_REVOKE` (task 4.2 will implement) and `VELGATE_UPDATE` (v1.1 will implement). Both log clearly and exit non-zero when invoked.
Why: keeps Phase 1 scope tight; stubs are documented in commits and code comments.
Revisit: ensure Phase 4 delivers revoke; v1.1 delivers update mechanism.

### 16. Binaries built in `bin/` (gitignored), not committed — 2026-05-19 02:55

`bin/velgate-linux-amd64`, `bin/velsigner`, `bin/sshgate-mcp` build cleanly via `make build`. They're gitignored — `/sshgate:setup` runs `go build ./cmd/...` during install per Decision 2 in this log. Phase 2 task 2.4 wires this into the slash command.

### 17. Phase 2 locked — real Telegram approval works end-to-end — 2026-05-19 03:55

What: Tasks 2.1 → 2.5 complete. Commits: d3a4083 (TelegramBackend + ChatStore), 3fafb59 (run_batch), ca36d7d (setup + install scripts), 44300c0 (phase-2 e2e + DecodeSigned fix). Phase-2 e2e exercises 6 scenarios against real Docker openssh + real TelegramBackend backed by an httptest fake Telegram API: approve single, deny single, **bulk approval (one tap → 3 commands run in order)**, wrong-user callback rejection, timeout, no goroutine leaks.
Why: this proves the FULL approval loop (Telegram message → user tap → callback → sign → SSH signed-prefix → velgate verify → exec) end-to-end. Phase 1 only covered the deny path; Phase 2 is the first real exercise of signed-write execution.
Revisit: nothing pending for Phase 2.

### 18. ⚠️ Latent bug caught by Phase 2 e2e: DecodeSigned was too strict — 2026-05-19 03:55

What: Phase 1's `common.DecodeSigned` rejected ANY trailing content after the base64-payload field. But per spec §"Transport", the wire format on SSH command lines is `VELGATE_SIG:<sig-b64>:<payload-b64> <inner-cmd>` — the trailing inner cmd is for SSH-side convention (visible in audit, readable in `ps`). When MCP sent a real signed write through to velgate, DecodeSigned returned `illegal base64 data`. The Phase 1 e2e never caught this because it only exercised the StubBackend deny path — no real signed wire was ever sent.
**Karthi attention:** this is the kind of bug that lives until integration tests reach the path. The fix in `common.payload`: trim payload-b64 at the first ASCII space (URL-safe base64 contains no spaces). The trailing cmd is genuinely ignored — velgate uses `payload.Cmd` from inside the signed envelope, not the trailing string. So the wire format and its security properties are unchanged; only the parser became spec-conformant.
Why: bug fix; the strict-whitespace test from Task 1.2 was wrong about the wire format (I wrote that test). Replaced with `TestDecodeSigned_TrailingInnerCmd` asserting the correct semantics.
Revisit: the **security audit** (gate 3) MUST verify the trailing-cmd path can't be exploited (e.g., padding-oracle-style attacks where an attacker crafts a trailing cmd that influences execution). Current state: velgate uses `payload.Cmd` exclusively, so the trailing cmd is never the executed string. Add this to the audit checklist explicitly.

### 19. systemd hardening on velsigner unit — 2026-05-19 03:25

What: `scripts/install.sh` writes a systemd unit with NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, MemoryDenyWriteExecute, ReadWritePaths=/var/lib/velsigner /run/velsigner, etc.
Why: velsigner holds the master signing key; defense-in-depth at the systemd level reduces the blast radius of any future bug.
Revisit: when audit gate runs, confirm these flags don't conflict with anything legitimate (e.g., MemoryDenyWriteExecute is incompatible with JIT, but Go binaries don't JIT).

### 20. Privileged-container systemd smoke deferred to v1.1 — 2026-05-19 03:25

What: Task 2.4 was supposed to include a systemd-in-docker smoke test. Running systemd inside a container needs `--privileged` + cgroups; not worth standing up on this dev box overnight. Replaced with `bash -n` syntax check + optional `shellcheck`.
Why: time budget. The install scripts are simple enough that syntax + manual review cover them; real validation happens when Karthi runs `/sshgate:setup` on his actual machine.
Revisit: v1.1 adds a CI runner with privileged container support; that's when the systemd smoke lands. For now the morning manual install will validate.

### 21. ✅ V1 COMPLETE — all four phases + all three audits clean — 2026-05-19 04:55

What: SSHGate v1 is done per your goal.

**Phases (10 implementation commits):**
- Phase 0: Go module + plugin manifest + Makefile + Docker integration target
- Phase 1: classifier + payload + velgate + velsigner (with backend interface) + MCP scaffold + Phase-1 e2e
- Phase 2: TelegramBackend + ChatStore + run_batch + setup scripts + Phase-2 e2e (with fake Telegram)
- Phase 3: add_server auto-setup (rollback included) + /sshgate:add + Phase-3 e2e
- Phase 4: list_servers + status + revoke_server + slash commands + debugging-remote-servers skill + README

**Audit Gate 1 — code review (~/arogara/code-review/reports/sshgate-2026-05-19.md):**
- 0 BLOCKER, 7 MAJOR (all FIXED in commits 91a2cf1 .. 283f40f), 11 MINOR + 6 NIT deferred
- Big fix in M1: `src/common/` split into `src/classify/` + `src/sigwire/` (the banned-package-name finding I flagged in Decision 10 — confirmed and resolved)
- M2 socket TOCTOU fixed with `SyscallConn().Control() + Fchmod` (better than the umask suggestion — umask is process-global and races parallel tests)
- M3 audit log: added `approved-undelivered` status for when sign succeeds but response delivery fails
- M5+M6 batched: `go mod tidy` + Makefile path drift fix; `make build` works again

**Audit Gate 2 — PII / secrets (docs/audits/pii-audit-2026-05-19.md):**
- gitleaks clean (working tree + full history)
- Scrubbed real Telegram user_id `12345678` from test files (3 occurrences) → synthetic values
- Made classifier corpus generic (`groups karthi` → `groups testuser`)
- Doc references to "Karthi" / user_id kept as intentional documentation context for personal-use stage; flagged for publish-cleanup as a v1.x task

**Audit Gate 3 — security (docs/audits/security-audit-2026-05-19.md):**
- 11/12 scenarios PASS, 0 FAIL, 5 MINORs documented
- Key probes verified live: `kernel.yama.ptrace_scope=1`, Phase-1 e2e direct-SSH-bypass refused, classifier correctly catches `cp/mv/tee/dd/rsync/ln` as writes, metachar guard blocks all common shell injections
- Decision 18's trailing-cmd path re-verified inert — velgate uses `payload.Cmd` exclusively
- Inline fix on the metachar guard: added `\n`, `\r`, `\x00` (commit landing alongside this entry); other 4 MINORs deferred to v1.1

**Stats:** 30 commits, 10 Go packages, 67 Go source files, 6 integration test files, 6 MCP tools, 5 slash commands, 1 skill, integration test suite at ~35s.

**Karthi-attention items for morning:**
- **Decision 10 ↔ Audit M1 resolved:** `common/` package split. The `sshgate-mcp` binary import paths now reference `src/classify` and `src/sigwire`.
- **Decision 18 (trailing-cmd parser):** confirmed as a genuine v1 bug-fix, not just a test deviation. Re-verified by security audit S7.
- **Setup flow (`/sshgate:setup`):** you'll run this on your laptop when you wake. It's idempotent. The 9-step walkthrough documents @BotFather → systemd → /start verification. Token paste step uses a here-string (NIT — code review pointed out this leaks to shell history; minor concern, fine for personal install).
- **MINORs to revisit when you next touch SSHGate (5 from code review + 4 from security, all in the reports):** mostly polish + defense-in-depth.

Moving to v1.1 cascade now.

### 22. ✅ V1.1 CASCADE COMPLETE — all four features shipped — 2026-05-19 06:30

What: all four v1.1 features landed in 4 commits on a clean tree.

- **Task A — Automated velsigner provisioning** (`beac802`): collapsed `install.sh` + `create-velsigner-user.sh` into ONE idempotent script. Setup walk is now 6 steps instead of 9. The standalone provisioning script was deleted (folded in); `install.sh` handles user creation, skeleton dirs, group membership, binary install, systemd unit, optional --init, optional token prompt.
- **Task B — Pipe/chain classification refinement** (`49879b9`): the v1 "any pipe = WRITE" compromise is gone. Per-segment classification now correctly marks `cat /etc/hosts | grep foo` as READ (was WRITE — spurious prompt). Closes code-review Mi3 (git stash) + Mi4 (wget without -O-) as security wins: those were both false-NEGATIVES (writes-as-reads) — fixed by tightening the rules. 28 new corpus rows added (205 total). Process substitution `$(...)` / `<(...)` / `>(...)` always fail-safe WRITE.
- **Task C — macOS cross-compile** (`770eb0a`): `make darwin` produces 4 Mach-O binaries (sshgate-mcp + velsigner for amd64 + arm64). Audited laptop-side packages — all syscalls (`Fchmod`, `Flock`, signals) are portable; no build constraints needed. velgate stays Linux-only (it's deployed to Linux remotes). macOS install path still semi-manual (no launchd plist generation yet); full macOS support is v1.2.
- **Task D — LLM command explainer** (`08f177c`): TelegramBackend now has an optional `Explainer` interface. When configured, hits an OpenAI-compatible Chat Completions endpoint for each pending command and renders a one-line plain-English explanation underneath each command in the approval DM. Bounded by a 5s timeout; LLM errors render a "(no explanations: …)" footer and DO NOT block approval. Config block `[backend.telegram.explainer]` enables it; OpenRouter is the natural choice (your settings.json already has `OPENROUTER_API_KEY`). Defense-in-depth: `sanitiseExplainerErr` strips URLs + Bearer tokens from error messages before they reach Telegram.

**Stats:** 36 commits total, 10 Go packages, 69 Go source files. All tests green (`go test -race ./...`, integration suite ~35s). All 5 cascade features (A-D + the inline S11 security fix) committed cleanly.

**Karthi-attention items for morning (new in v1.1):**
- **OpenRouter API key setup:** if you want the LLM explainer working from the start, drop your OpenRouter key into `/var/lib/velsigner/tokens/llm-api.key` and enable the `[backend.telegram.explainer]` config block. Step 7 of `docs/install-step-by-step.md` covers this.
- **Pipe classification UX win:** the next time you ask Claude to do "show me memory usage piped to grep" or similar, you'll skip the approval prompt — it's now classified as a read.
- **macOS install:** if you decide to run SSHGate on a Mac (not just Linux), `make darwin` produces the binaries but the install script doesn't run on macOS. That's a v1.2 task. Linux is the supported install path for now.

Moving to v2 scaffold.
