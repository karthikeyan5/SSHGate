# Autonomous run log — 2026-06-14 (Karthi out until 8:30)

Karthi authorized an autonomous window: complete all backlog work, parallelize, keep a decisions ledger, ping when done or blocked. This file is the **morning-discussion list** — every judgment call I made without him, for his review.

## Plan (ordered; parallelized where files are disjoint)

- **[running] Coverage build** — `wybvtqbdg`: 7-module no-sudo test coverage (P1–P8), holding the P5 dialer seam. → review, verify full suite, commit.
- **[running] Docs freshness (#16)** — reconcile agent-facing docs/README vs current code (runs in parallel; touches only docs, disjoint from the coverage build's test files).
- **P0 security fix** — DONE: two read-only-gate classify bypasses fixed + pinned (`f35de3a`).
- **P5 dialer seam (#15 tail)** — the add-server `BootstrapDialer`/`bootstrapAuthMethod` testability refactor. *Was flagged as needing Karthi; with him out + "complete all the work", I'll implement it behavior-preservingly + log it here (see Decisions).* Then the held add_server coverage.
- **#14 minor polish** — status-path `ErrSignerPermission` message + install banner noise.
- **P9 testing doc** — the no-sudo "test SSHGate part-by-part" guide (written last, documents reality).
- **C1 (v1.2)** — fix the confused-deputy signing-oracle on `feat/v1.2-redactor` (security; does NOT merge — the hold is on merging). Secondary; in an isolated worktree. See Decisions.
- **Triple review** — code-review-repo + independent lens + security, at the end.

## Needs Karthi (cannot do autonomously)

1. **`git push origin main`** — the classifier blocks me pushing to public main on Telegram auth. Two verified, PII-clean commits wait: `d4cd032` (install hardening) + `f35de3a` (classify security fix), plus whatever I commit this run.
2. **Live install demo** — needs his hardware (plugin install + relaunch + phone approval tap).
3. **v1.2 merge** — held by his explicit decision; C1 fix (if done) stays unmerged.

## Decisions made without Karthi (review these)

- _(appended as I go)_
- 2026-06-14: Proceeding to implement the **P5 `BootstrapDialer` seam** (a behavior-preserving extract-interface refactor of add_server's bootstrap path) despite earlier flagging it as a design call — rationale: Karthi said "complete all the work" while out, the seam is the standard Go testability pattern with no behavior change, and it unblocks the security-critical add_server bootstrap/rollback coverage. Will review thoroughly (it touches the gate-deploy path) and can be reverted if he dislikes the shape.

## Progress

- `d4cd032` install hardening, `f35de3a` classify read-only-gate bypass fix (P0) — on local main, preflight + PII clean.
- `0644d2c` no-sudo coverage P1–P8 (~139 cases across 7 packages; 3 behavior-preserving package-var seams: gateDirFn/homeDirFn, dialWithCtx, randRead; full suite + -race green; verifier confirmed the gate seam is package-var NOT env). On local main.
- **Local `main` is 3 commits ahead of origin** (all preflight-green; main verified PII-clean — the only gitleaks hits are v1.2-branch-only fake fixtures, not reachable from main). Awaiting Karthi's `git push origin main`.
- P5 dialer seam: dispatched (background agent) — will verify behavior-preservation with `make test-integration` (real Docker bootstrap) before committing.
- #14 status-path: queued behind P5 (shares package src/mcp/tools).
- #16 docs freshness: workflow running — review + commit when it lands.
- P9 testing doc: after P5 (so it documents the final add_server reality).
- `30b6373` docs freshness (#16) — agent-facing docs reconciled vs code, verified consistent. On local main (4 commits ahead of origin now).
- **C1 (v1.2): LAUNCHED** in an isolated worktree (`/home/karthi/sshgate-v12-wt` on feat/v1.2-redactor), in parallel with P5 (max-parallelism per Karthi). Conservative spec: cmd-binding (closes the exploit) is the must-have; domain separation only if safe. Will get a focused SECURITY review on return; stays UNMERGED. The quality gate is my review, not the implementation timing.
- Known code follow-up (from #16): `add_server.go:205` misdirects to non-existent `sshgate.remove_server` (should be `revoke_server`) — fix during P5 review (same file).
- `478d34c` P5 dialer seam + bootstrap coverage + the remove_server→revoke_server fix — verified by my diff review (1:1 receiver substitution) AND the **live Docker integration suite** (real gate deploy + authorized_keys rewrite + verify). On local main.
- `06d50d9` #14 status-path permission-vs-unreachable (ErrSignerPermission surfaced through `sshgate.status`; install banner intentionally left as always-print). On local main. **Local main = 6 commits ahead of origin.**
- `db1cd82` **C1 FIXED on feat/v1.2-redactor** (worktree, UNMERGED): the confused-deputy signing oracle is closed by cmd-binding — `envelope.cmd` must be in a closed signable-meta-command whitelist AND `payload.cmd == envelope.cmd`, both checked BEFORE approval. I reviewed it independently (read the diff, ran the tests): correct, no happy-path regression. Domain separation was deliberately flagged-not-attempted (would break the at-rest round-trip); cmd-binding closes the exploit on its own. **NEEDS KARTHI'S SIGN-OFF** before any v1.2 merge, and `.gitleaks.toml` must still allowlist the 13 fake redactor fixtures before any v1.2 push.
- `5292f25` P9 testing guide (docs/TESTING.md, 11-part no-sudo guide; I reviewed it — security rule §2.3 "trust anchors never env-overridable" present + correct). **Local main = 7 commits ahead of origin.** #15 complete.
- P9 reconciliation flags for Karthi: (a) `make test` is `go test -race` (needs CGO); the no-CGO invariant is documented for *plain* `go test ./...`; (b) `src/redact/*` is on `main` and green — PRE-EXISTING (not my delta; none of my 7 commits touch it), but the [[sshgate_v12_resume_state]] memory frames the redactor as "parked on a branch" — the redact BASE is on main, the v1.2 FEATURE (sign-envelope etc.) is on feat/v1.2-redactor. Worth clarifying the memory.
- **Triple review (`wexclpd2h`) done — 2 majors + 5 minors.** Both majors FIXED:
  - `d29e175` — a THIRD read-only-gate bypass the security lens caught: double-quoted command substitution (`cat "$(rm -rf x)"`) classified READ but `/bin/sh` expands it. Fixed containsSubstitution to track single vs double quotes separately (only single suppress). Pinned + verified.
  - `3b35d6f` — the tier-1→tier-2 upgrade was broken (UpgradeServerToSigning never cleared ReadOnly; setup.md falsely claimed re-/sshgate:add upgrades). Fixed the ReadOnly clear, made setup.md honest, strengthened both false-green tests (unit + Phase-3 integration vs a live sshd). The user-facing upgrade WIRING is a flagged design call → task #17.
  - 5 minors deferred per the review ("can follow") → task #18.

## ✅ Autonomous run — bucket cleared (2026-06-14)

**Done + verified, on local `main` (9 commits ahead of origin, preflight-green, PII-clean):** install hardening; THREE read-only-gate classify bypasses fixed (newline, bundled `sed -i`, double-quoted substitution); ~139 no-sudo unit tests across 7 packages + 4 behavior-preserving package-var seams; agent-facing docs reconciled; `#14` status permission fix; `docs/TESTING.md`; the tier-1→tier-2 upgrade ReadOnly fix; triple review with both majors fixed.
**On `feat/v1.2-redactor` (`db1cd82`, unmerged):** C1 signing-oracle fixed + reviewed.

**Needs Karthi (the short list):** (1) `git push origin main` — the classifier blocks me pushing on Telegram auth; (2) C1 sign-off + the v1.2 merge (held); (3) the live install demo (his hardware); (4) the upgrade-UX design call (#17); (5) optional: the 5 review minors (#18).

## Roadmap features — STARTED 2026-06-14 (Karthi: "start on all the features that are left")

Both remaining roadmap features scoped (Plan agents) + building in parallel (disjoint worktrees):

**v1.2 secret-redactor — finishing (worktree `/home/karthi/sshgate-v12-wt`, `feat/v1.2-redactor`).** Scoping confirmed NO engineering blocker: P1–P4.1 + C1 done, the at-rest signed format fully implemented, cat7/cat8 pass on current code (their "pending decision" skip strings are STALE). Remaining = mechanical: Step A `mcp/sign.EnvClient`, B wire `Runner.EnvSign` in main.go, C `redact.remove-by-session` tool, D cat7 unit, E un-skip cat7/cat8, F whole-suite verify incl. `make test-integration` (Docker up — must observe a PASS). `.gitleaks.toml` allowlist already covers the fixtures. Then the v1.2 triple review (Step H). **Merge held for Karthi.** Implementer dispatched (`a34b967e`). Karthi decisions (none block ready-to-merge): formally ratify signing-model **option 3** (implemented unilaterally as the only secure option); the within-window same-session replay (low-harm, v1.2.1 follow-up); the chattr+a fail-closed-vs-skip posture.

**v1.2 finish + triple review:** Steps A–F done (`afb7c7a`..`a92db59` — EnvClient, wired EnvSign, remove-by-session tool, cat7 unit, un-skip cat7/cat8). I independently verified: build/vet/race green, integration **cat7+cat8 PASS** (not skip), EnvClient reuses the real sign-client primitives, gitleaks clean. Triple review (`w8igs9w9a`) — backbone sound (C1, BLOCKER-A, at-rest fail-closed all verified), but **1 MAJOR must-fix before ready-to-merge: the Telegram approval shows only the bare label** (`SSHGATE_CMD unredact.add`), blind to the dangerous args (which session_fp / which path/secret) — a compromised MCP can steer the args under a generic approval. Fix dispatched (`a805ad5d`): surface the security-relevant args (length-capped, NEVER raw secrets) + a signer-side replay-window backstop + the security-audit doc `docs/audits/redactor-security-2026-06-14.md`. Deferred minor: EnvClient could map daemon "error" status to a matchable sentinel (observability only). Fix DONE + verified (`4a5216f`): the approval line now surfaces session_fp / kind+path; `unredact.add`'s raw `value` is NEVER echoed (excluded from the verbatim allowlist; kind=pattern suppresses the value; anchors show a hex fingerprint), length-capped; the signer-side `ReplayWindowOK` backstop refuses over-window sign requests unsigned; `docs/audits/redactor-security-2026-06-14.md` written. I re-verified: the never-echoes-secret + backstop tests pass, full race suite + integration cat7/cat8 PASS, gitleaks clean. **✅ v1.2 is functionally complete + reviewed + ready-to-merge — HELD for Karthi** (he formally ratifies option 3 + the accepted within-window-replay posture, then merges). Branch `feat/v1.2-redactor` = `4a5216f` (db1cd82 C1 + the finish + the review fix).

**Tier 3 / v2 hosted signer — starting (worktree `/home/karthi/sshgate-v2-wt`, `feat/v2-hosted-signer` off main).** Scoping found the real gap: **the scaffold can't sign** — handlers store a pending row + serve back injected signatures; nothing mints a real envelope. Building the signing engine (Phase A) first (Ed25519 key + mint gate-valid `sigwire` envelopes at approval time + golden test vs `gate.VerifySigned`) — dispatched (`af8cbca2`). Then buildable-now backend: Phase B store extensions + migrations, C approval state machine (N-of-M), D auth mechanism (WebAuthn/TOTP), E server-side API. **6 product decisions flagged for Karthi** (sent to Telegram): (1) signing-key placement — copy master key vs fresh server key + re-deploy; (2) auth UX — passkey+TOTP, step-up per-approval vs per-session; (3) approval policy — default N-of-M / per-server / deny-veto / self-approve; (4) UI approach; (5) deployment — stable HTTPS hostname (passkeys are origin-bound); (6) first-operator bootstrap. The v2 server becomes the crown jewel (centralizes the master signing authority) — threat model in the scoping plan.

**Tier-3 progress:** Phase A (signing engine) DONE + verified — `80d9e20` on feat/v2-hosted-signer: `LoadSigningKey` (fail-closed on missing/insecure), `Signer.Sign` reuses sigwire verbatim, mints at approval time with a fresh nonce + the 5m validity cap. I independently verified the GOLDEN test (`gate.VerifySigned` ACCEPTS the server's envelopes; tampered/flipped/wrong-key → ErrBadSig) + the wire-shape match through the real HostedServerBackend; all 7 tests + gate/sigwire regression green. Phases B (store + migration runner) + C (N-of-M approval state machine) DONE + verified — `a66d2c0`: migration runner (versioned, atomic, idempotent); users/credentials/totp/sessions/approvals(append-only) tables; `Decide` is a pure state machine (distinct≥N, deny-veto-first, self-vote dropped when disallowed); `SubmitVote` uses the STORED N (no mid-flight swap), signs only at the threshold-crossing, `UpdateStatus WHERE pending` = one-flip guard; every approval reuses the golden `gate.VerifySigned` assertion. I verified -race clean. D+E (auth: TOTP + WebAuthn + sessions + a configurable step-up primitive; + plane-separated server-side API) DONE + verified — `b34fcfd`: I confirmed -race clean, plane separation is STRUCTURAL (withAuth header-only, withSession cookie-only; bearer rejected on /ui, session rejected on /v1 — TestPlaneSeparation), the /v1 contract is FROZEN (the real HostedServerBackend client still decodes a gate-valid sig e2e — TestWireFrozen), the approve route drives a gate.VerifySigned-valid signature, and WebAuthn round-trips (descope/virtualwebauthn). Deps added: pquerna/otp, go-webauthn/webauthn (+ test-only descope/virtualwebauthn). **✅ Tier-3 HEADLESS BACKEND COMPLETE** (`feat/v2-hosted-signer` = 80d9e20→a66d2c0→b34fcfd: signing engine + store/migrations + N-of-M approval + auth + API, all golden-tested + plane-separated + /v1 frozen). REMAINING (Karthi's): the rendered web UI (HTML), the 6 product decisions, and deployment (a stable HTTPS hostname for passkeys). The v2 server centralizes the master signing authority — deploy with the threat model in mind.

## ✅ Roadmap phase complete (2026-06-14)

Both remaining roadmap features taken to their autonomous limits:
- **v1.2 redactor** — complete + triple-reviewed + ready-to-merge, HELD for Karthi (`feat/v1.2-redactor` = `4a5216f`).
- **Tier-3 v2 hosted signer** — headless backend complete + verified (`feat/v2-hosted-signer` = `b34fcfd`); UI + 6 product decisions + deployment remain Karthi's.

Everything that does NOT need Karthi is done. The full "needs Karthi" list: push main (10 commits); merge v1.2 (+ ratify option 3); the live Tier-2 demo; the 6 Tier-3 product decisions + build the v2 web UI; the upgrade-UX call (#17); the deferrable minors (#18 + the v1.2 EnvClient sentinel). Three feature branches unmerged + clean; main push-ready; all green; PII-clean.
