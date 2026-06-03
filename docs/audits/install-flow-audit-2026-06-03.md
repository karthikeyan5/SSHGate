# SSHGate install-flow audit — 2026-06-03

**Trigger:** Karthi sent SSHGate to someone who could not install or use it. This audit answers: *can a fresh-clone user install + use Tier 1 (read-only) and Tier 2 (signer) end-to-end, right now?*

**Method:** 5-dimension parallel finder sweep (plugin-load, tier1-flow, tier2-flow, build-integrity, docs-reality), every finding adversarially re-verified against the actual source by an independent agent. 43 agents, ~1.8M tokens. Raw structured output (38 findings + per-finding verdicts) archived in the workflow run `wf_d2f05458-693`.

**Verdict: NO.** All five flows fail end-to-end (`flow_works=false` ×5). The components build and unit-test green, but they were never wired into a working fresh-machine install. Tally after verification: **6 distinct BLOCKER root-causes, 5 MAJOR, 4 MINOR, 1 refuted.** (17/13/7 raw, before deduplicating the same root cause seen from multiple angles.)

---

## The decisive finding — plugin install strips the source tree

**Empirically proven (not inferred).** Claude Code's `/plugin install` copies a marketplace plugin into a versioned cache dir (`~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`) and points `${CLAUDE_PLUGIN_ROOT}` there. **It copies only recognized component dirs** — `.claude-plugin/`, `commands/`, `skills/`, `agents/`, `hooks/`, `.mcp.json`. Everything else is dropped.

Proof, on this machine, via the sibling **c3** plugin (identical install mechanism):
- Source plugin root `~/arogara/c3/plugins/c3/` contains `.claude-plugin/  commands/  .mcp.json  stt/`.
- Cache copy `~/.claude/plugins/cache/c3/c3/0.1.0/` contains `.claude-plugin/  commands/  .mcp.json` — **`stt/` stripped.**

Therefore SSHGate's `src/`, `scripts/`, `go.mod`, `Makefile`, and (already-gitignored) `bin/` are **absent from `${CLAUDE_PLUGIN_ROOT}`** after install. SSHGate's design assumes `${CLAUDE_PLUGIN_ROOT}` == the git clone with full source. That assumption is false. Consequence: `.mcp.json`'s `${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp` can never exist, `setup.md`'s `cd ${CLAUDE_PLUGIN_ROOT} && go build ./src/...` has no `src/`, and `install.sh` isn't in the cache at all.

**The proven fix (precedent: c3).** c3 works because its `.mcp.json` uses a **bare PATH command** `"command": "c3-claude-adapter"` and it builds via `go install ./cmd/...` into `~/go/bin` (confirmed: `c3-broker`, `c3-claude-adapter`, `c3-codex-adapter` all on PATH). No `${CLAUDE_PLUGIN_ROOT}` dependence. SSHGate must adopt the same pattern.

---

## BLOCKERS (distinct root causes — each kills install or first use)

### B1. Marketplace cache strips source → `${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp` impossible
Covers findings: `marketplace-cache-strips-source-tree`, `install-step3-probe-cannot-find-source`, `setup-builds-into-cache-bin-but-source-absent`, `setup-step-minus1-wrong-diagnosis`.
- `.mcp.json:4` → `${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp`; `bin/` gitignored AND `src/` stripped from cache.
- `INSTALL.md:129-148` step-3 probe (`ls -d ~/.claude/plugins/cache/*/sshgate`, then look for `go.mod` near it) can never succeed — wrong cache depth, and no `go.mod` in the cache anyway. It then prints a misleading "marketplace points at a remote GitHub source" error and exits.
- **Fix:** adopt the c3 PATH-binary pattern (see B2 fix block).

### B2. `bin/` gitignored + no `/reload-plugins` after build → MCP server dead for the session
Covers: `no-reload-after-build` (×4), `mcp-binary-gitignored-and-fail-fast-no-reload`.
- MCP server spawns at session start / `/reload-plugins`. If the binary is missing it fails **with no retry**; slash commands still load but all `sshgate.*` tools are dead.
- INSTALL.md runs `/reload-plugins` *before* `/sshgate:setup` builds anything, and never reloads again after the build. Even if the binary built into the right place, the tool surface stays dead until a manual reload.
- **Fix (B1+B2 together):** `.mcp.json` → `"command": "sshgate-mcp"` (bare, on PATH), `env: {"SSHGATE_SIGNER_SOCK": "/run/sshgatesigner/sock"}`. Build via `go install ./src/mcp/cmd/sshgate-mcp` + `go install ./src/signer/cmd/sshgate-signer-telegram` from the **user's clone** (which has `src/`) into `~/go/bin`. Verify `~/go/bin` is on PATH (warn if not). Sequence INSTALL.md as: clone → build (`go install`) → marketplace add → install → reload (now the PATH binary exists). Optional `hooks/SessionStart` idempotent `go install` if-missing for robustness.

### B3. Gate-binary name drift → `/sshgate:add` dead on both tiers
Covers: `gate-binary-name-drift`, `gate-binary-name-mismatch` (×2), `make-build-wrong-gate-binary-name`.
- `add_server.go:526,538-539` looks for `bin/gate-linux-amd64` (no prefix); the missing-file hint (`:217`) says `make gate-linux` — **a target that does not exist**.
- `make build` produces `bin/sshgate-gate` (native); the cross target `sshgate-gate-linux` produces `bin/sshgate-gate-linux-amd64`; `setup.md:230` + `install.sh:52` expect `sshgate-gate-linux-amd64` (with prefix).
- The gate-binary read at `add_server.go:216` is **unconditional**, before the `read_only` short-circuit (`:225`), so it fails even Tier 1.
- **Fix:** unify on `sshgate-gate-linux-amd64`. Update `add_server.go` resolver path + hint; build the cross-gate into a stable location the resolver checks (`~/.config/sshgate/bin/` and/or `~/go/bin/`), since the cache `bin/` won't exist.

### B4. Signer-init hardcodes `/var/lib/signer` → Tier-2 install aborts at Step 7
Covers: `init-hardcodes-var-lib-signer-not-sshgatesigner`, `signer-init-hardcodes-wrong-paths`, `signer-init-writes-wrong-paths`.
- `signer-telegram main.go:493-499` non-dev `doInitFlow` hardcodes `root="/var/lib/signer"`, `sockPath="/run/signer/sock"`, ignoring `--config`. `install.sh` runs `sudo -u sshgatesigner ... --init --config /var/lib/sshgatesigner/config/config.toml`. As the unprivileged `sshgatesigner` user, `os.MkdirAll("/var/lib/signer/keys")` → permission denied → `--init` exits 1 → `install.sh` (`set -euo pipefail`) aborts. **The signing keypair + config are never created.**
- Also `install.sh:187` guards `--init` on `KEY_PATH=/var/lib/sshgatesigner/keys/gate.key` but init writes to `/var/lib/signer/keys/gate.key` — the guard never matches.
- **Fix:** derive `root` from the `--config` path (`<root>/config/config.toml` → `/var/lib/sshgatesigner`), set `sockPath=/run/sshgatesigner/sock`.

### B5. Signer socket path mismatch → every Tier-2 write times out
Covers: `mcp-default-socket-mismatch`, `signer-socket-path-mismatch`, `mcp-never-sets-signer-sock-env`, `systemd-unit-cannot-write-run-signer-sock`, `mcp-signer-socket-default-mismatch`.
- MCP defaults `SSHGATE_SIGNER_SOCK` to `/run/signer/sock` (`mcp main.go:42`); `.mcp.json` sets `env:{}` so nothing overrides it. The systemd unit provisions `/run/sshgatesigner/` (`RuntimeDirectory`, `ReadWritePaths`) and `ProtectSystem=strict` forbids `/run/signer`. So the daemon can't even bind `/run/signer/sock`, and the MCP dials a path that will never exist → `sign: signer unreachable` on every write.
- **Fix:** unify on `/run/sshgatesigner/sock`: set `defaultSignerSock` in `mcp main.go:42` AND set it in `.mcp.json` env AND fix the signer init (B4). Make `status` print the actually-probed path.

### B6. Gate public-key path mismatch → crypto loop can't close even if everything else works
Covers: `gatepub-source-path-mismatch`.
- `setup.md` T2.6 + step-by-step copy `gate.pub` from `/var/lib/sshgatesigner/keys/gate.pub`, but `--init` writes it to `/var/lib/signer/keys/gate.pub`. The distribution file is never created → `add_server` (tier-2) fails "gate signing public key not found", OR the remote gate never gets the pubkey → `gate.LoadPubKey` returns nil → read-only mode → **denies every signed write**.
- **Fix:** falls out of B4 (init writes to `/var/lib/sshgatesigner/keys/`). Optionally have `install.sh` auto-stage `gate.pub` into `~/.config/sshgate/pubkey-distrib/` (chown `$SUDO_USER`) so the manual cp can't be skipped/mismatched.

---

## MAJORS

- **M1. `make build` omits the linux gate binary** (`make-build-omits-linux-gate`, `make-build-misnamed-in-install`, `make-build-gate-name-mismatch`, `make-gate-linux-wrong-target-name`). INSTALL.md preamble says binaries come from `make build`, but that doesn't produce `sshgate-gate-linux-amd64`; `install.sh` then errors "run `make build` first" — the command the user just ran. Self-contradicting recovery loop. **Fix:** make `build` depend on `sshgate-gate-linux` (one `make build` produces everything), and fix the hint strings.
- **M2. go.mod requires Go 1.26.1, docs say 1.22+** (`go-version-gomod-vs-docs`). `go.mod:3` `go 1.26.1`; preflight + all docs say ≥1.22. A user with 1.22–1.25 passes preflight then `go build` hard-fails. **Fix:** pick one real floor — lower `go.mod` to the true minimum and verify it builds, or raise the documented/preflight floor to 1.26.x.
- **M3. Tier-1 setup tells user to `/sshgate:add` without `--read-only`** (`setup-no-readonly-flag-on-add`). Without the flag, `add_server` requires the gate pubkey (never created on Tier 1) → hard-fail. The Tier-1 summary contradicts the tier it just installed. **Fix:** `setup.md` T1.5 → `/sshgate:add <alias> <user@host> --read-only`; optionally auto-fallback to read-only when no signer is configured.
- **M4. `/sshgate:status` shows wrong socket + phantom-daemon debug for Tier 1** (`status-socket-path-mismatch`, `status-tier1-expected-output-mismatch`). Prints the wrong default path and an "expected" annotation the code never emits; steers Tier-1 users to debug a daemon that intentionally doesn't exist. **Fix:** print the actually-probed path; make status tier-aware so an unreachable signer is reported as normal on Tier 1; align INSTALL.md's documented output to reality.

## MINORS

- **m1. `plugin-root-env-var-mismatch` / `plugin-root-env-not-passed`** — `add_server` reads `SSHGATE_PLUGIN_ROOT` (never set) instead of `CLAUDE_PLUGIN_ROOT`; dead branch masked by the os.Executable fallback. Fix while touching B3.
- **m2. `daemon-default-config-path-velsigner`** — vestigial `VELSIGNER_CONFIG` / `/etc/signer` / "signer user" naming from the vel→sshgate rename. Scrub to `SSHGATE_SIGNER_CONFIG` + `/var/lib/sshgatesigner/...`.
- **m3. `version-string-drift`** — plugin.json 0.1.0 / mcp 0.1.5 / signer 0.1.4. Unify (ldflags or shared const).
- **m4. `install-step-make-target-wrong`, `install-preamble-readonly-trust-vs-readme`, `stale-doc-telegram-not-implemented`** — doc accuracy: "all three binaries" miscount, README lists "systemd" unconditionally though Tier 1 needs none, a stale "not implemented" note. Fix in the docs pass.

## Refuted (no action)

- **`stale-unprefixed-binary-in-tree`** — the leftover `bin/gate-linux-amd64` in the working tree is just an un-rebuilt artifact, not a shipped issue (`bin/` is gitignored). Will disappear once the binary naming is unified.

---

## Fix sequencing (Tier 1 first, per Karthi)

1. **Plugin-load + build model** (B1, B2, M1, M2, m1, m3) — adopt c3 PATH-binary pattern; this is what makes *any* tool surface appear. Tier-1-critical.
2. **Tier 1 usage** (B3, M3, M4) — `/sshgate:add --read-only` → gate deploys → reads stream. Gate-binary naming + status correctness.
3. **Tier 2 signer** (B4, B5, B6, m2) — unify on the `sshgatesigner` layout so init → socket → pubkey → signed-write loop closes.
4. **Docs/README parity** (m4 + sweep) — make every documented step + expected output match reality.
5. **Verification** — trace/execute a fresh-clone Tier-1 walkthrough end-to-end (Docker SSH target), then Tier-2 where feasible.

Full per-finding detail (problem/evidence/repro/fix/verdict) is in the archived workflow output; this report is the consolidated, deduplicated, sequenced source of truth for the fix plan (`docs/plans/2026-06-03-install-flow-fix-plan.md`).
