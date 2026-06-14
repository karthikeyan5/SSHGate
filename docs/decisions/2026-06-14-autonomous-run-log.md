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
