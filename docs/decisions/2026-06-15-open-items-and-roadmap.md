# SSHGate — open items & roadmap (2026-06-15)

> **UPDATE 2026-06-18:** Approval architecture is now DECIDED — a two-tier model; see [2026-06-18-signer-approval-architecture.md](2026-06-18-signer-approval-architecture.md). The c3-vs-dedicated-bot question is RESOLVED. Tier-2 live approval is VERIFIED end-to-end (task #12 done). The next work is the **server-consolidation migration**. (This dated snapshot's commit-count figures below are stale — local main is now ~51 commits ahead, unpushed.)

Canonical "nothing-lost" list captured before a planned compaction. Authored after the
2026-06-14/15 deep gate review + the 3-model red-team hunt loop. Pairs with the auto-memory
notes (`sshgate_classifier_arms_race`, `sshgate_v12_resume_state`, `sshgate_v2_hosted_signer`)
and the detailed ledger `docs/decisions/2026-06-14-autonomous-run-log.md`.

## Current state (local `main`)
- **39 commits ahead of `origin/main`, NOTHING pushed** (held for Karthi — the safety classifier
  blocks me pushing to a public main on Telegram auth; needs Karthi's own `git push` or CLI-typed auth).
- `make preflight` (vet + full `-race` incl. redteam live Docker tests + gitleaks + build) = **green**;
  `make test-integration` (real gate over SSH: read/write/signed/redaction/upgrade/revoke/add-server) = **green**.
- The gate red-team rig is **multi-instance** (`SSHGATE_REDTEAM_PORT`/`--port`) + standing (up/down/status)
  + has an in-container inotify write-tripwire. Hunt loop **STOPPED by Karthi** (2026-06-15) — no rigs running.
- Done this session: deep gate review (2 blockers + dead-code + lazy-compile + classifier split), triple review,
  and **two full 3-model hunt rounds** — every confirmed bypass fixed + regression-tested + live-re-confirmed
  (round 1: uniq/awk-var/curl/sed-space; round 2: curl-cache-flags/bundled-o, sort --compress-program (exec),
  wget -o logfile, hostname positional, git branch -d, HOME/XDG env redirect).

## TOP priority — Karthi's two features (RIGHT NOW, build first after compaction)
> Karthi (2026-06-15) gave these to build right away, on top of everything.

### FEATURE 1 — Interactive prompt / confirmation / password forwarding
A remote command (a read, an install, "anything") can trigger an INTERACTIVE prompt mid-run — a
sudo/password prompt, a `[Y/n]` confirmation, an "are you sure?" — and today the gate execs
non-interactively (`/bin/sh -c`, no TTY), so Karthi would have to SSH in HIMSELF just to type "yes" or a
password. He does NOT want that ("otherwise it's only half as useful"). **Build a way to forward those prompts
to the operator and relay the answer back without a manual SSH.** He's fine with a WEB PAGE, or any general
mechanism. Design sketch: allocate a PTY for the remote command, detect a prompt / input-stall, surface it to
the operator (Telegram and/or a web UI), capture the response, and write it to the command's stdin. Passwords
are sensitive — handle securely (don't log/echo). Ties into the existing Telegram-signer approval channel.

### FEATURE 2 — SQL access via per-service whitelist adapters (read-only SQL first)
You can't give full SQL access (SSH → log into the DB = unrestricted; today it's effectively blocked).
**Support READ-ONLY SQL queries against any engine (PostgreSQL / MariaDB / SQLite / …)**, with WRITE SQL
requiring a signature — the same read/write + sign model the gate uses for shell, but applied to SQL.
**Karthi's architectural direction: write a customized whitelist ADAPTER per service/program** (a SQL adapter,
a shell adapter, …); he's fine building them one-by-one for each kind of program.
> **Synergy with #22 (the architectural fix):** the per-service-adapter model could BE the structural answer —
> replace the single heuristic shell classifier with explicit per-service read/write adapters (argv/grammar-based,
> not shell-string-guessing). Design the adapter framework and the argv-exec fix TOGETHER.

## HIGH priority — the structural/architectural fix (Karthi-APPROVED, "ASAP")
> Karthi (2026-06-15): "we should work on a structural and architectural fix for this — maybe kernel-level,
> maybe the idea you said, or something else altogether. It's not possible to beat every tool's every flag on
> every server. Write it in the ToDo; we'll get to it ASAP."

**Problem:** SSHGate's Tier-1 read-only gate execs reads via `/bin/sh -c <raw>` UNSIGNED whenever the
classifier returns READ. The classifier is a heuristic predicting the shell + every allowlisted tool's
write/exec flags — a permanent arms race. Two hunt rounds + the triple review each found more bypasses, ALL
in the hand-maintained per-tool arg denylists (the default-deny allowlist gate itself held). Per-tool
enumeration cannot win against every tool's every flag on every server.

**Candidate structural fixes (decide + design):**
1. **Exec reads via parsed `argv` directly (execve, no `/bin/sh`)** — the classifier's view == the exec's
   view; the entire shell-parse-mismatch class (escapes/quotes/separators/substitution/redirects) cannot
   execute. Cost: read PIPELINES (`ps aux | grep x`) need a safe mini-executor (parse stages, verify each
   stage's binary is read-allowlisted, wire without a shell) or must be signed.
2. **Kernel-level confinement** — run reads in a locked-down sandbox: read-only rootfs/bind mounts + seccomp
   (deny write/exec syscalls) + no network, so a misclassified write/exec simply cannot persist. Defense in
   depth independent of the classifier.
3. **Strict no-metacharacter read mode** — in read-only mode refuse any command with shell metacharacters and
   run only `binary args` forms with inspected args.
(Likely a combination — e.g. argv-exec + seccomp. The standing rig is the regression net for whichever path.)
See memory `sshgate_classifier_arms_race` for the full write-up.

## Future — gated interactive session mode (task #25, lands AFTER #22)
> Karthi (2026-06-16): "add it to the roadmap right after number 22."

A **gated interactive session**: `ssh <key> host` lands the operator in a shell-LIKE interactive
**prompt** (a prompt, command history, `cd`/env that feel normal) where **every command is still
gated**. The SAFE form is **NOT** wrapping a live `/bin/sh` — that is the read-only classifier
arms-race on hard mode (persistent shell state, `eval`, history, and interactive-program escapes
like `:!sh`) and it undoes #22. Instead **the gate IS the shell**: it reads a line, parses it into
argv itself, classifies it, runs it via argv-exec (no `/bin/sh`), prints output, and loops —
tracking cwd/env itself. Classifier-view ≡ exec-view, exactly the #22 principle, so an interactive
prompt is just the argv-exec engine with a read-eval-print front end. Interactive sub-programs
(`vim`/`mysql`/…) are handled by the Feature-2 per-service adapters or blocked. **Depends on the
#22 argv-exec foundation; build after it.** (`rbash` is the cautionary counter-example — a wrapped
restricted shell, famously full of escapes.)

## Future — friendlier gate responses (task #26)
> Karthi (2026-06-16): instead of a bare reject/kill, the gate should answer with a clear,
> actionable message ("needs signature / needs approval") — for BOTH the current single-command
> mode and the #25 gated session.

When the gate denies a write (or any command needing a signature), don't just exit 77 / kill —
return a clear, structured, agent-friendly response that says *what* is needed and *how* to get it
(e.g. "this is a write — it needs an approved signature; request approval, then resubmit with the
`SSHGATE_SIG` envelope"). This is more than cosmetics: in an agent-driven flow (especially the #25
gated terminal) it is the **handshake** that tells the agent to go get approval and resubmit,
instead of guessing why a command died. In #25's interactive mode the write could optionally
trigger the Telegram approval **inline** (reusing Feature 1's prompt-relay) so the operator just
taps approve and the command proceeds. Applies to current mode now + #25 later.

## Needs Karthi / to-discuss (separate from the two features)
1. **Push `origin/main`** (39 commits) — your `git push` / CLI auth; the classifier blocks me on Telegram auth.
2. **v1.2 redactor merge** — COMPLETE + triple-reviewed on `feat/v1.2-redactor` (`4a5216f`); needs your
   ratification of signing-model **option 3** + the accepted within-window (≤5m) replay posture, then merge.
   (Held — do NOT auto-merge; the C1 confused-deputy fix needs your sign-off.) See `sshgate_v12_resume_state`.
3. **Tier-3 v2 hosted signer** — headless backend COMPLETE + verified on `feat/v2-hosted-signer` (`b34fcfd`);
   needs the **6 product decisions** (signing-key placement, auth UX, approval policy, UI approach, deployment,
   first-operator bootstrap), the rendered web UI (backend serves JSON only), and a stable HTTPS hostname
   (passkeys are origin-bound). See `sshgate_v2_hosted_signer`.
4. **Tier-1→Tier-2 upgrade UX (#17)** — design call (how the upgrade is surfaced/wired).
5. ~~**Live Tier-2 signer demo (#12)**~~ — DONE 2026-06-18 (verified end-to-end via @sshgate_example_bot + tg-api.example.com proxy).

## Deferred / lower priority (mine to do, no decision needed — but noted so nothing is lost)
- **Deferred refactors:** sign-wire struct consolidation (`signRequest`/`signRequestCmd` duplicated
  `signer/daemon.go` ↔ `mcp/sign/client.go` — do in the v1.2-merge window, designed WITH v1.2's envelope
  structs); the redaction **scanner** Aho-Corasick/keyword-prefilter (perf for large output — security-sensitive
  rewrite, deprioritized); softening the upgrade remediation message tone (#18, v1.2-diverged files).
- **gofmt drift:** local `go1.26.4` vs committed `go 1.25.0`; `make preflight` doesn't gate on gofmt. Pin a
  gofmt toolchain or add `gofmt -l` under it (not a push blocker; nothing in this work introduced it).
- **Rig corpus:** round-2 holes (curl-cache/sort-compress/wget-o/hostname/git-branch) not yet added to the
  rig corpus regression sweep (round-1 holes ARE, `905879e`); the harden4 unit tests already pin them at the
  classify level. Add to `internal/redteam/corpus.go` when convenient.
- **Known residual classifier gaps** (subsumed by the architectural fix): the per-tool denylist will keep
  leaking obscure write/exec flags; the rig is the standing regression net.

## Branches (all local, unmerged unless noted)
- `main` — all session work merged here, 39 ahead of origin, unpushed.
- `feat/v1.2-redactor` (`4a5216f`) — v1.2 redactor, ready-to-merge, HELD for option-3 ratify.
- `feat/v2-hosted-signer` (`b34fcfd`) — Tier-3 headless backend, complete; UI/decisions/deploy remain.
