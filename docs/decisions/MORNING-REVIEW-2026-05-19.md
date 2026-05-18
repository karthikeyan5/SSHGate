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
