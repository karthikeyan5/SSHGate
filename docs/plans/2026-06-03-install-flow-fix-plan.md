# SSHGate Install-Flow Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a fresh-clone user able to install and use SSHGate Tier 1 (read-only) and Tier 2 (Telegram signer) end-to-end, by adopting the proven c3 PATH-binary plugin pattern and unifying every path/name on the `sshgatesigner` layout.

**Architecture:** Claude Code's `/plugin install` strips `src/`, `scripts/`, `go.mod`, `Makefile`, `bin/` from the marketplace cache, so `${CLAUDE_PLUGIN_ROOT}/bin/...` and "build src/ in the plugin root" cannot work. We move the laptop binaries (`sshgate-mcp`, `sshgate-signer-telegram`) onto `$PATH` via `go install ./...` from the user's clone (which has `src/`), point `.mcp.json` at the bare command name, and build the remote gate cross-binary into a stable config location `~/.config/sshgate/bin/sshgate-gate-linux-amd64` that `add_server` resolves independently of the cache. Tier-2 paths are unified on the `sshgatesigner` state root everywhere (`/var/lib/sshgatesigner`, socket `/run/sshgatesigner/sock`).

**Tech Stack:** Go 1.25+ (modules), Claude Code MCP plugin (.mcp.json + commands + skills), bash install script, systemd unit, Telegram bot API, Docker Compose for the integration suite.

---

## Finding → Task coverage table

| Finding | Summary | Task(s) |
|---|---|---|
| **B1** | Marketplace cache strips source → `${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp` impossible | T1.1 (.mcp.json), T1.2 (mcp socket default), T4.2 (INSTALL.md), T4.4 (setup.md Step -1) |
| **B2** | `bin/` gitignored + no reload after build → MCP dead | T1.1 (.mcp.json PATH command), T1.3 (`make install-local`), T4.2 (INSTALL.md sequence), T4.4 (setup.md build steps) |
| **B3** | Gate-binary name drift → `/sshgate:add` dead both tiers | T2.1 (resolver + name + hint), T1.3 (`make install-local` builds gate to config), T4.4 (setup.md T1.2 build path) |
| **B4** | Signer-init hardcodes `/var/lib/signer` → Tier-2 abort | T3.1 (derive root from --config) |
| **B5** | Signer socket path mismatch → every Tier-2 write times out | T1.2 (mcp `defaultSignerSock`), T1.1 (.mcp.json env), T3.1 (init sockPath), T3.3 (status probed path) |
| **B6** | Gate pubkey path mismatch → crypto loop can't close | T3.1 (init writes to sshgatesigner/keys), T3.2 (install.sh auto-stage pubkey) |
| **M1** | `make build` omits the linux gate binary; bad hints | T1.3 (`make build` deps + `install-local`), T2.1 (hint string) |
| **M2** | go.mod requires 1.26.1, docs say 1.22+ | T1.4 (set go.mod to 1.25.0 floor + all docs) |
| **M3** | Tier-1 add without `--read-only` hard-fails | T2.2 (add.md auto-readonly fallback), T4.4 (setup.md T1.5 suggestion) |
| **M4** | `/sshgate:status` wrong socket + phantom-daemon debug for Tier 1 | T3.3 (tier-aware status + probed path), T4.2 (INSTALL.md §5 output) |
| **m1** | `add_server` reads `SSHGATE_PLUGIN_ROOT` not `CLAUDE_PLUGIN_ROOT` | T2.1 (resolver env fix) |
| **m2** | Vestigial `VELSIGNER_CONFIG` / `/etc/signer` / "signer user" naming | T3.4 (signer doc + defaultConfigPath scrub) |
| **m3** | Version-string drift (plugin 0.1.0 / mcp 0.1.5 / signer 0.1.4) | T1.5 (unify on shared const 0.2.0) |
| **m4** | Doc accuracy (binary miscount, README systemd-unconditional, stale notes) | T4.1 (README), T4.3 (step-by-step), T4.4 (setup.md) |
| Refuted | `stale-unprefixed-binary-in-tree` | No action (bin/ gitignored; disappears on rebuild) |

Every BLOCKER (B1–B6), MAJOR (M1–M4), and MINOR (m1–m4) maps to at least one task. The refuted finding requires no action.

---

## Empirical findings (read before starting)

**go.mod version (M2) — RESOLVED EMPIRICALLY.** On 2026-06-03 the plan author lowered the `go` directive to `1.22`, then `1.24`, and ran `go mod tidy` + `go build ./...` each time. Result: `go mod tidy` **forced the directive back up to `go 1.25.0`** every time, because these direct/indirect deps declare `go 1.25.0` in their own `go.mod`: `github.com/modelcontextprotocol/go-sdk v1.6.0`, `golang.org/x/crypto v0.51.0`, `golang.org/x/sys`, `golang.org/x/term`, `golang.org/x/sync`, and the `modernc.org/{libc,sqlite,cc/v4,ccgo/v4}` SQLite chain. At `go 1.25.0` the whole module builds clean (`go build ./...` exit 0). **Decision: set the floor to the real minimum `go 1.25.0`** (not 1.22) and raise every doc + preflight to `1.25`. The current `go 1.26.1` is both wrong (no deps need 1.26) and malformed (`1.26.1` is a patch/toolchain number, not a language-version floor; the language floor is `1.26`, but 1.25 is the true minimum that builds). Task T1.4 implements this.

**Working tree state.** The empirical test restored `go.mod`/`go.sum` to HEAD afterward; they are unchanged. Do not re-introduce temporary edits.

**c3 reference (B1/B2).** `~/arogara/c3/plugins/c3/.mcp.json` is exactly `{"mcpServers":{"c3":{"command":"c3-claude-adapter"}}}` — a bare PATH command, no `${CLAUDE_PLUGIN_ROOT}`. This is the pattern T1.1 adopts.

**gate read-only semantics (already correct).** `src/gate/keystore.go:24` — `LoadPubKey` returns `(nil, nil)` when `gate.pub` is missing; this is the Tier-1 read-only state. No gate-side change needed; Tier-1 add just omits the pubkey upload (already handled by `runAutoSetup`'s `gatePubBytes != nil` guard at `add_server.go:340`).

---

## File structure (what changes and why)

- `.mcp.json` — switch to bare PATH command + signer-sock env (B1/B2/B5).
- `src/mcp/cmd/sshgate-mcp/main.go` — `defaultSignerSock` → `/run/sshgatesigner/sock`; header comment (B5/m2-adjacent).
- `src/mcp/tools/add_server.go` — gate-binary resolver (4-tier), name fix, env fix, hint fix (B3/M1/m1).
- `src/mcp/tools/add_server_resolve_test.go` *(new)* — unit test for the resolver order.
- `src/signer/cmd/sshgate-signer-telegram/main.go` — extract pure `resolveInitPaths` (root derived from `--config`) consumed by `doInitFlow`; `defaultConfigPath` scrub; header comment; version const (B4/B5/B6/m2/m3).
- `src/signer/cmd/sshgate-signer-telegram/init_test.go` *(new)* — unit test for the pure `resolveInitPaths` resolver, no filesystem/root (it is `package main`, so the test lives beside it).
- `src/mcp/tools/status.go` + `src/mcp/server.go` — tier-aware status (M4).
- `src/mcp/tools/status_tier_test.go` *(new)* — unit test for tier-aware status.
- `src/mcp/server.go` + `src/mcp/cmd/sshgate-mcp` + signer cmd + plugin.json — version unification (m3).
- `Makefile` — `build` depends on `sshgate-gate-linux`; new `install-local` target (M1/B2/B3).
- `go.mod` — `go 1.25.0` (M2).
- `scripts/install.sh` — auto-stage `gate.pub` to the MCP distribution path; KEY_PATH guard already matches once B4 lands (B6).
- `commands/setup.md`, `commands/add.md`, `commands/status.md` — usage corrections (B1/B3/M3/M4).
- `INSTALL.md`, `README.md`, `docs/install-step-by-step.md` — doc/version parity (M2/M4/m4).

---

# PHASE 1 — Plugin-load + build model (B1, B2, M1, M2, m3)

This phase makes *any* SSHGate tool surface appear after install. Tier-1-critical.

## Task 1.1 — `.mcp.json` uses a bare PATH command + signer-sock env

**Files:**
- Modify: `.mcp.json` (whole file)

- [ ] **Step 1: Rewrite `.mcp.json`**

Current content:

```json
{
  "mcpServers": {
    "sshgate": {
      "command": "${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp",
      "env": {}
    }
  }
}
```

Replace the entire file with:

```json
{
  "mcpServers": {
    "sshgate": {
      "command": "sshgate-mcp",
      "env": {
        "SSHGATE_SIGNER_SOCK": "/run/sshgatesigner/sock"
      }
    }
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `python3 -m json.tool .mcp.json`
Expected: pretty-prints the object with no error, showing `"command": "sshgate-mcp"` and the `SSHGATE_SIGNER_SOCK` env key.

- [ ] **Step 3: Commit**

```bash
git add .mcp.json
git commit -m "fix(mcp): use bare PATH command + sshgatesigner sock (B1/B2/B5)"
```

## Task 1.2 — MCP `defaultSignerSock` → `/run/sshgatesigner/sock`

**Files:**
- Modify: `src/mcp/cmd/sshgate-mcp/main.go:42` (const) and `:15` (header comment)

- [ ] **Step 1: Fix the const default**

In `src/mcp/cmd/sshgate-mcp/main.go`, change line 42 from:

```go
	defaultSignerSock = "/run/signer/sock"
```

to:

```go
	defaultSignerSock = "/run/sshgatesigner/sock"
```

- [ ] **Step 2: Fix the header comment**

In the same file, change line 15 from:

```go
//	$SSHGATE_SIGNER_SOCK  — signer socket (default /run/signer/sock)
```

to:

```go
//	$SSHGATE_SIGNER_SOCK  — signer socket (default /run/sshgatesigner/sock)
```

- [ ] **Step 3: Build to confirm it compiles**

Run: `go build ./src/mcp/cmd/sshgate-mcp`
Expected: exit 0, no output.

- [ ] **Step 4: Run the mcp+tools tests**

Run: `go test -race ./src/mcp/...`
Expected: all `ok`, no `FAIL`.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/cmd/sshgate-mcp/main.go
git commit -m "fix(mcp): default signer socket to /run/sshgatesigner/sock (B5)"
```

## Task 1.3 — `make build` produces everything + `make install-local`

**Files:**
- Modify: `Makefile:1-2` (`.PHONY`), `:4` (`all`), `:6` (`build` deps), `:46` (`cross:` simplification)
- Add to `Makefile`: a new `install-local` target (depends on `build`)

The audit (M1) requires `make build` to be honest. We make `build` depend on `sshgate-gate-linux` so one `make build` always produces `bin/sshgate-gate-linux-amd64`, AND add `install-local` which is what the fresh-clone flow actually runs. Per Open-Q #6 (RESOLVED: install-local depends on build), `install-local: build` so a single `make install-local` produces EVERYTHING in one command: the `<clone>/bin/*` artifacts (for `scripts/install.sh`), the two laptop binaries `go install`ed onto `$PATH` (for `.mcp.json`), and the gate cross-binary staged into `~/.config/sshgate/bin/`.

- [ ] **Step 1: Add `install-local` to `.PHONY` and update `all`**

Change `Makefile` line 1-4 from:

```make
.PHONY: all build test test-integration vet clean sshgate-gate-linux \
	sshgate-mcp-darwin sshgate-signer-telegram-darwin darwin cross sshgate-signer-server

all: vet test build
```

to:

```make
.PHONY: all build install-local test test-integration vet clean sshgate-gate-linux \
	sshgate-mcp-darwin sshgate-signer-telegram-darwin darwin cross sshgate-signer-server

all: vet test build
```

- [ ] **Step 2: Make `build` depend on the linux gate binary**

Change `Makefile` line 6 from:

```make
build: sshgate-signer-server
```

to:

```make
build: sshgate-signer-server sshgate-gate-linux
```

(Leaving the recipe body unchanged — it still produces `bin/sshgate-mcp`, `bin/sshgate-signer-telegram`, `bin/sshgate-gate`; the new prerequisite adds `bin/sshgate-gate-linux-amd64`.)

- [ ] **Step 2b: Simplify the `cross:` target (now that `build` includes the linux gate)**

Now that `build` depends on `sshgate-gate-linux` (Step 2), the explicit `sshgate-gate-linux` prerequisite on `cross:` is redundant. Change `Makefile` line 46 from:

```make
cross: build sshgate-gate-linux darwin
```

to:

```make
cross: build darwin
```

(`build` already pulls in `sshgate-gate-linux`, so `cross` still produces the full matrix — linux laptop binaries + linux remote gate + darwin laptop binaries. Verify with `make -n cross` in Step 4: the `sshgate-gate-linux` recipe still appears, reached via the `build` prerequisite.)

- [ ] **Step 3: Add the `install-local` target (depends on `build` — one command produces EVERYTHING)**

Append to `Makefile` (after the `cross:` target, before `test:`). Per Open-Q #6 (RESOLVED: install-local depends on build), `install-local` depends on `build` so a single `make install-local` produces every artifact the fresh-clone flow needs: the `<clone>/bin/*` binaries (consumed by `scripts/install.sh`), the `$PATH` binaries in `~/go/bin` (consumed by `.mcp.json`'s bare command), and the staged gate cross-binary.

```make
# install-local is the fresh-clone laptop install used by /sshgate:setup
# and INSTALL.md. It depends on `build`, so ONE `make install-local`
# produces everything the install needs:
#   - <clone>/bin/*  (sshgate-mcp, sshgate-signer-telegram, sshgate-gate,
#                     sshgate-gate-linux-amd64) for scripts/install.sh
#   - $PATH binaries in $(go env GOPATH)/bin via `go install`
#                     (.mcp.json now references the bare `sshgate-mcp`)
#   - sshgate-gate-linux-amd64 staged into the STABLE config location the
#     MCP's add_server resolver checks (~/.config/sshgate/bin/), decoupled
#     from the plugin cache that `/plugin install` cannot keep src/ in.
# Run from the user's clone (it has src/). Honors $XDG_CONFIG_HOME.
install-local: build
	go install ./src/mcp/cmd/sshgate-mcp
	go install ./src/signer/cmd/sshgate-signer-telegram
	mkdir -p "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags='-s -w' \
		-o "$${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/sshgate-gate-linux-amd64" \
		./src/gate/cmd/sshgate-gate
	@echo "install-local done:"
	@echo "  <clone>/bin/* (incl. sshgate-gate-linux-amd64) -> for scripts/install.sh"
	@echo "  sshgate-mcp, sshgate-signer-telegram -> $$(go env GOPATH)/bin (must be on PATH)"
	@echo "  sshgate-gate-linux-amd64 -> $${XDG_CONFIG_HOME:-$$HOME/.config}/sshgate/bin/"
```

- [ ] **Step 4: Syntax-check the Makefile (dry-run the new target)**

Run: `make -n install-local`
Expected: prints the `build` prerequisite recipe (incl. the `sshgate-gate-linux` cross-build now that `build` depends on it — Step 2), then the four `install-local` commands (two `go install`, one `mkdir -p`, one cross `go build`) and the three `echo` lines, with no "No rule to make target" or syntax error.

- [ ] **Step 5: Actually run `make install-local` and verify outputs**

Run: `make install-local`
Then run: `ls -la bin/sshgate-mcp bin/sshgate-signer-telegram bin/sshgate-gate-linux-amd64 "$(go env GOPATH)/bin/sshgate-mcp" "$(go env GOPATH)/bin/sshgate-signer-telegram" "${XDG_CONFIG_HOME:-$HOME/.config}/sshgate/bin/sshgate-gate-linux-amd64"`
Expected: all files exist and are non-zero — the `<clone>/bin/*` artifacts from the `build` prerequisite (incl. `bin/sshgate-gate-linux-amd64` for install.sh), the two `$PATH` binaries, and the staged gate binary (executable).

- [ ] **Step 6: Verify `make build` now produces the gate cross-binary**

Run: `make clean && make build && ls -la bin/sshgate-gate-linux-amd64`
Expected: `bin/sshgate-gate-linux-amd64` exists (this is the M1 fix — `make build` alone now produces it).

- [ ] **Step 7: Commit**

```bash
git add Makefile
git commit -m "feat(make): build produces linux gate; add install-local target (M1/B2/B3)"
```

## Task 1.4 — go.mod floor → `go 1.25.0` (M2)

**Files:**
- Modify: `go.mod:3`

- [ ] **Step 1: Set the real minimum**

Change `go.mod` line 3 from:

```
go 1.26.1
```

to:

```
go 1.25.0
```

- [ ] **Step 2: Confirm it still builds and tidies cleanly**

Run: `go build ./... && go mod tidy && git diff --stat go.mod go.sum`
Expected: build exit 0; `git diff --stat` shows no further change to `go.mod` beyond the `1.25.0` edit (proving 1.25.0 is the stable floor `go mod tidy` agrees with) and no change to `go.sum`. If `go mod tidy` re-bumps the directive, STOP — re-read the empirical findings section; the floor must be whatever `go mod tidy` settles on.

- [ ] **Step 3: Run the full suite**

Run: `go test -race ./...`
Expected: every package `ok`, no `FAIL`. (Integration tests under `./tests/integration/...` need docker; they are excluded from `./...` plain — see Task 5.2.)

- [ ] **Step 4: Commit**

```bash
git add go.mod
git commit -m "fix(build): set go.mod floor to real minimum go 1.25.0 (M2)"
```

## Task 1.5 — Unify the version string (m3)

**Files:**
- Modify: `src/mcp/server.go:46` (`Version`)
- Modify: `src/signer/cmd/sshgate-signer-telegram/main.go:53` (`version`)
- Modify: `.claude-plugin/plugin.json:3` (`version`)

We unify all three on `0.2.0` (a single bump past the highest current value, mcp's 0.1.5, marking the install-flow fix release). No ldflags machinery — three string edits keep it simple (YAGNI).

- [ ] **Step 1: Bump the MCP version**

Change `src/mcp/server.go` line 46 from:

```go
const Version = "0.1.5"
```

to:

```go
const Version = "0.2.0"
```

- [ ] **Step 2: Bump the signer version**

Change `src/signer/cmd/sshgate-signer-telegram/main.go` line 53 from:

```go
const version = "0.1.4"
```

to:

```go
const version = "0.2.0"
```

- [ ] **Step 3: Bump the plugin manifest version**

Change `.claude-plugin/plugin.json` line 3 from:

```json
  "version": "0.1.0",
```

to:

```json
  "version": "0.2.0",
```

- [ ] **Step 4: Validate plugin.json + build**

Run: `python3 -m json.tool .claude-plugin/plugin.json && go build ./...`
Expected: JSON pretty-prints with `"version": "0.2.0"`; build exit 0.

- [ ] **Step 5: Confirm the binaries report 0.2.0**

Run: `go run ./src/mcp/cmd/sshgate-mcp --version && go run ./src/signer/cmd/sshgate-signer-telegram --version`
Expected: `sshgate-mcp 0.2.0` and `signer 0.2.0`.

- [ ] **Step 6: Commit**

```bash
git add src/mcp/server.go src/signer/cmd/sshgate-signer-telegram/main.go .claude-plugin/plugin.json
git commit -m "chore: unify version string on 0.2.0 (m3)"
```

---

# PHASE 2 — Tier-1 usage (B3, M3, m1)

`/sshgate:add --read-only` → gate deploys → reads stream. Gate-binary naming + resolver + Tier-1 add ergonomics.

## Task 2.1 — Gate-binary resolver: name, env, hint, 4-tier order (B3, M1, m1)

**Files:**
- Modify: `src/mcp/tools/add_server.go` — `addServerCfg.GateBinaryPath` doc comment (`:78-80`), the hint string (`:216-217`), `defaultGateBinaryPath` (`:521-549`)
- Test: `src/mcp/tools/add_server_resolve_test.go` (new)

The resolver must look for `sshgate-gate-linux-amd64` (was unprefixed `gate-linux-amd64`), read `CLAUDE_PLUGIN_ROOT` (was the dead `SSHGATE_PLUGIN_ROOT`), and resolve in this order: (a) `$SSHGATE_GATE_BIN` if set, (b) `<configRoot>/bin/sshgate-gate-linux-amd64`, (c) `os.Executable`-relative `sshgate-gate-linux-amd64` (covers `~/go/bin`), (d) `$CLAUDE_PLUGIN_ROOT/bin/sshgate-gate-linux-amd64`.

- [ ] **Step 1: Write the failing test**

Create `src/mcp/tools/add_server_resolve_test.go`:

```go
package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultGateBinaryPath_ConfigRootBin asserts the resolver finds
// sshgate-gate-linux-amd64 under <configRoot>/bin when SSHGATE_GATE_BIN
// is unset. This is the stable location `make install-local` writes to.
func TestDefaultGateBinaryPath_ConfigRootBin(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	t.Setenv("SSHGATE_GATE_BIN", "")
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	binDir := filepath.Join(cfgRoot, "sshgate", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(binDir, "sshgate-gate-linux-amd64")
	if err := os.WriteFile(want, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if got != want {
		t.Errorf("defaultGateBinaryPath() = %q; want %q (configRoot/bin)", got, want)
	}
}

// TestDefaultGateBinaryPath_EnvOverride asserts $SSHGATE_GATE_BIN wins.
func TestDefaultGateBinaryPath_EnvOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "custom-gate")
	t.Setenv("SSHGATE_GATE_BIN", override)
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if got != override {
		t.Errorf("defaultGateBinaryPath() = %q; want %q (env override)", got, override)
	}
}

// TestDefaultGateBinaryPath_UsesPrefixedName asserts the resolved
// basename is the prefixed sshgate-gate-linux-amd64, never the old
// unprefixed gate-linux-amd64 (the B3 name-drift bug).
func TestDefaultGateBinaryPath_UsesPrefixedName(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	t.Setenv("SSHGATE_GATE_BIN", "")
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")

	got, err := defaultGateBinaryPath()
	if err != nil {
		t.Fatalf("defaultGateBinaryPath: %v", err)
	}
	if filepath.Base(got) != "sshgate-gate-linux-amd64" {
		t.Errorf("resolved basename = %q; want sshgate-gate-linux-amd64", filepath.Base(got))
	}
}
```

- [ ] **Step 2: Run the test to confirm it fails**

Run: `go test ./src/mcp/tools/ -run TestDefaultGateBinaryPath -v`
Expected: FAIL — `TestDefaultGateBinaryPath_ConfigRootBin` and `_EnvOverride` fail (resolver doesn't check those locations yet), `_UsesPrefixedName` fails (old name is `gate-linux-amd64`).

- [ ] **Step 3: Rewrite `defaultGateBinaryPath`**

Replace `src/mcp/tools/add_server.go` lines 521-549 (the whole `defaultGateBinaryPath` function and its doc comment) from:

```go
// defaultGateBinaryPath resolves the bundled gate-linux-amd64
// binary. It checks $SSHGATE_PLUGIN_ROOT first (set by Claude Code at
// plugin load), then falls back to <dir(os.Executable())>/../bin.
func defaultGateBinaryPath() (string, error) {
	if root := os.Getenv("SSHGATE_PLUGIN_ROOT"); root != "" {
		return filepath.Join(root, "bin", "gate-linux-amd64"), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	// Two layouts we expect:
	//   <root>/bin/sshgate-mcp        (production plugin layout)
	//   <root>/.../sshgate-mcp        (go test / dev)
	// Try sibling first, then parent's bin dir.
	dir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(dir, "gate-linux-amd64"),
		filepath.Join(dir, "..", "bin", "gate-linux-amd64"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// Fall through with the first candidate; readLocalFile will
	// surface a clean error mentioning the build target.
	return candidates[0], nil
}
```

to:

```go
// gateBinaryName is the canonical basename of the cross-compiled
// remote gate binary (linux/amd64). It is the PREFIXED name produced
// by `make sshgate-gate-linux` and `make install-local`. The old
// unprefixed `gate-linux-amd64` is gone (audit B3).
const gateBinaryName = "sshgate-gate-linux-amd64"

// defaultGateBinaryPath resolves the cross-compiled gate binary. The
// /plugin install cache strips src/ and bin/, so we cannot rely on a
// path under the plugin cache. Resolution order (audit B3/M1/m1):
//
//  1. $SSHGATE_GATE_BIN — explicit operator override (absolute path).
//  2. <configRoot>/bin/sshgate-gate-linux-amd64 — the STABLE location
//     `make install-local` writes to (~/.config/sshgate/bin/).
//  3. <dir(os.Executable())>/sshgate-gate-linux-amd64 — covers the
//     `go install` layout where the gate sits beside sshgate-mcp in
//     $GOPATH/bin (dev / belt-and-braces).
//  4. $CLAUDE_PLUGIN_ROOT/bin/sshgate-gate-linux-amd64 — last-resort
//     legacy path for a clone-as-plugin-root install that still ships
//     a built bin/. (Note: this is CLAUDE_PLUGIN_ROOT, not the dead
//     SSHGATE_PLUGIN_ROOT that was never set — audit m1.)
//
// Each candidate is stat-checked; the first that exists wins. If none
// exists we return candidate (2) so readLocalFile surfaces a clean
// error naming the stable location and the build command.
func defaultGateBinaryPath() (string, error) {
	if env := os.Getenv("SSHGATE_GATE_BIN"); env != "" {
		return env, nil
	}

	root, err := configRoot()
	if err != nil {
		return "", err
	}
	configCandidate := filepath.Join(root, "bin", gateBinaryName)

	candidates := []string{configCandidate}

	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), gateBinaryName))
	}
	if pluginRoot := os.Getenv("CLAUDE_PLUGIN_ROOT"); pluginRoot != "" {
		candidates = append(candidates, filepath.Join(pluginRoot, "bin", gateBinaryName))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// None found: return the stable config-root candidate so the
	// missing-file error points the operator at the right place.
	return configCandidate, nil
}
```

- [ ] **Step 4: Fix the missing-file hint string**

In `src/mcp/tools/add_server.go`, change lines 216-217 from:

```go
	gateBin, err := readLocalFile(cfg.GateBinaryPath, "gate binary",
		"build it with `make gate-linux` first")
```

to:

```go
	gateBin, err := readLocalFile(cfg.GateBinaryPath, "gate binary",
		"run /sshgate:setup (or `make install-local`) to build sshgate-gate-linux-amd64 into ~/.config/sshgate/bin/")
```

- [ ] **Step 5: Fix the `GateBinaryPath` field doc comment**

In `src/mcp/tools/add_server.go`, change lines 78-80 from:

```go
	// GateBinaryPath is the local path to the cross-compiled
	// gate binary. Default: bin/gate-linux-amd64 next to the
	// running MCP binary.
	GateBinaryPath string
```

to:

```go
	// GateBinaryPath is the local path to the cross-compiled gate
	// binary (sshgate-gate-linux-amd64). Default: resolved by
	// defaultGateBinaryPath — $SSHGATE_GATE_BIN, then
	// <configRoot>/bin/, then os.Executable-relative, then
	// $CLAUDE_PLUGIN_ROOT/bin/.
	GateBinaryPath string
```

- [ ] **Step 6: Run the resolver test to confirm it passes**

Run: `go test ./src/mcp/tools/ -run TestDefaultGateBinaryPath -v`
Expected: PASS for all three subtests.

- [ ] **Step 7: Run the full mcp suite**

Run: `go test -race ./src/mcp/...`
Expected: all `ok`, no `FAIL`.

- [ ] **Step 8: Commit**

```bash
git add src/mcp/tools/add_server.go src/mcp/tools/add_server_resolve_test.go
git commit -m "fix(mcp): gate resolver uses sshgate-gate-linux-amd64, configRoot/bin, CLAUDE_PLUGIN_ROOT (B3/M1/m1)"
```

## Task 2.2 — `/sshgate:add` auto-falls back to read-only when no signer (M3)

**Files:**
- Modify: `commands/add.md` (argument parsing + `read_only` decision, lines 9-24)

The audit (M3) flags that Tier-1 users who omit `--read-only` hit a hard-fail (the gate pubkey was never created). The locked decision asks us to *propose* an auto-fallback and mark it optional. We implement it as a deterministic check in the slash command: before calling `add_server`, the command probes whether a local signing pubkey exists at `~/.config/sshgate/pubkey-distrib/gate.pub`; if absent AND the user did not pass `--read-only`, it defaults `read_only` to `true` and tells the user. This makes Tier-1 add work without the flag while staying explicit.

- [ ] **Step 1: Update the argument/flag parsing section**

In `commands/add.md`, replace lines 9-23 (from `Parse the arguments:` through the `bootstrap_key_path` bullet) with:

```markdown
Parse the arguments:
- `alias` — first positional. Must match `[a-z][a-z0-9-]{0,30}`. Reject otherwise with a clear error.
- `user@host[:port]` — second positional. Split on `@` and optional `:`. Port defaults to 22.
- `--read-only` (or `--ro`) — optional flag. If present, register the server in read-only mode (gate is deployed but `gate.pub` is NOT pushed; writes are denied locally at the gate).

If the required positional arguments are missing, print the argument-hint and stop. Do not prompt the user inline; this command is scriptable.

**Determine read_only.** Before calling the tool, decide whether this is a read-only deploy:

- If `--read-only`/`--ro` was passed → `read_only = true`.
- Otherwise, probe for a local signing pubkey:

```bash
test -f "${HOME}/.config/sshgate/pubkey-distrib/gate.pub" && echo "signer:yes" || echo "signer:no"
```

  - `signer:yes` → `read_only = false` (Tier-2 signed-write deploy).
  - `signer:no` → **auto-fall back to read-only.** Set `read_only = true` and tell the user verbatim:
    > "No local signer pubkey found (`~/.config/sshgate/pubkey-distrib/gate.pub` is absent), so '<alias>' is being deployed in read-only mode. Reads will work; writes are denied at the gate. Run /sshgate:setup to add a Telegram signer, then re-run /sshgate:add <alias> <user@host> to upgrade it to signed-write."

Then call the MCP tool `mcp__sshgate__add_server` with:
- `alias`: parsed alias
- `host`: parsed host
- `port`: parsed port (default 22)
- `user`: parsed user
- `read_only`: the value decided above
- `bootstrap_agent`: true (use the user's ssh-agent if `SSH_AUTH_SOCK` is set)
- `bootstrap_key_path`: empty (let the tool fall back if no agent)
```

- [ ] **Step 2: Confirm the file reads coherently**

Run: `grep -n "read_only\|signer:no\|pubkey-distrib" commands/add.md`
Expected: shows the new probe line, the `signer:no` fallback, and the `read_only:` argument all present and consistent.

- [ ] **Step 3: Commit**

```bash
git add commands/add.md
git commit -m "fix(add): auto-fall back to read-only when no local signer pubkey (M3)"
```

---

# PHASE 3 — Tier-2 signer (B4, B5, B6, m2)

Unify on the `sshgatesigner` layout so init → socket → pubkey → signed-write loop closes.

## Task 3.1 — Extract a PURE `resolveInitPaths` so init derives root from `--config` + correct socket (B4, B5, B6)

**Files:**
- Modify: `src/signer/cmd/sshgate-signer-telegram/main.go` — extract `resolveInitPaths` (new pure helper) from `doInitFlow`; `doInitFlow` calls it then performs side effects (`:474-553`)
- Test: `src/signer/cmd/sshgate-signer-telegram/init_test.go` (new)

The non-dev branch hardcodes `root="/var/lib/signer"` and `sockPath="/run/signer/sock"`, ignoring `--config`, and `doInitFlow` then `os.MkdirAll`s `filepath.Dir` of each — i.e. `mkdir /var/lib/signer/keys` and `mkdir /run/signer` — which fails for an unprivileged runner (permission denied on both). So `doInitFlow` is **not** unit-testable unprivileged.

**Decided fix (review option (c)): extract a PURE path-resolver and test it directly.** All the path *computation* moves into a no-I/O function `resolveInitPaths(configPath, dev) (initPaths, error)`; `doInitFlow` keeps the side effects (MkdirAll, keygen, config write) but now sources every path from the returned struct. The unit test calls `resolveInitPaths` directly — no `doInitFlow`, no filesystem, no root — so it is an honest TDD red (undefined function → compile error), not a permission error.

This fixes B4 (root derived from `--config`, no longer hardcoded `/var/lib/signer`), B5 (socket pinned to `/run/sshgatesigner/sock`), and B6 (keys land at `/var/lib/sshgatesigner/keys/gate.{key,pub}`, where setup.md T2.6 + install.sh copy from). The non-dev branch's real `os.MkdirAll("/run/sshgatesigner")` remains production behavior (install.sh's systemd `RuntimeDirectory=sshgatesigner` pre-creates `/run/sshgatesigner`; install.sh runs init as the `sshgatesigner` user against `/var/lib/sshgatesigner`) — it is simply never exercised by the unit test.

- [ ] **Step 1: Read the real `doInitFlow` and identify the path computation**

Read `doInitFlow` in `src/signer/cmd/sshgate-signer-telegram/main.go` (currently `:474-553`). Identify where it computes `root`, `keyPath`, `pubPath`, `auditPath`, `sockPath` for BOTH branches:
- **dev branch** (`:476-492`): `root` is `filepath.Dir(configPath)` when an absolute `--config` is given, else `$XDG_RUNTIME_DIR/signer-<pid>`; then keys/pub/audit/sock sit FLAT under root — `gate.key`, `gate.pub`, `approvals.log`, `sock` (NOT under `keys/`).
- **non-dev branch** (`:493-499`): currently hardcodes `root="/var/lib/signer"`, keys/pub/audit under `keys/`+`log/`, `sockPath="/run/signer/sock"`.

`configPath` is a function parameter; there is no `ConfigPath` struct field today. The new `initPaths` struct adds one (carrying `configPath` through) so callers and tests have the whole resolved layout in one place.

- [ ] **Step 2: Write the failing test (honest TDD red — undefined function)**

Create `src/signer/cmd/sshgate-signer-telegram/init_test.go`:

```go
package main

import (
	"path/filepath"
	"testing"
)

// TestResolveInitPaths_NonDev asserts the PRODUCTION layout: root is the
// config file's grandparent, keys/pub/audit live under <root>, and the
// socket is the fixed runtime path. No filesystem, no root needed — this
// is a pure function. Audit B4/B5/B6.
func TestResolveInitPaths_NonDev(t *testing.T) {
	got, err := resolveInitPaths("/var/lib/sshgatesigner/config/config.toml", false /* dev */)
	if err != nil {
		t.Fatalf("resolveInitPaths: %v", err)
	}
	want := initPaths{
		Root:       "/var/lib/sshgatesigner",
		KeyPath:    "/var/lib/sshgatesigner/keys/gate.key",
		PubPath:    "/var/lib/sshgatesigner/keys/gate.pub",
		AuditPath:  "/var/lib/sshgatesigner/log/approvals.log",
		SockPath:   "/run/sshgatesigner/sock",
		ConfigPath: "/var/lib/sshgatesigner/config/config.toml",
	}
	if got != want {
		t.Errorf("resolveInitPaths(non-dev) =\n  %+v\nwant\n  %+v", got, want)
	}
}

// TestResolveInitPaths_Dev asserts everything anchors under the config
// file's own directory when --dev is set with an absolute --config, so
// tests and local runs need no privileged /run or /var/lib access. The
// dev layout is FLAT (gate.key/gate.pub/approvals.log/sock under root),
// matching the existing dev branch — do not change that behavior.
func TestResolveInitPaths_Dev(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.toml")
	got, err := resolveInitPaths(configPath, true /* dev */)
	if err != nil {
		t.Fatalf("resolveInitPaths: %v", err)
	}
	want := initPaths{
		Root:       tmp,
		KeyPath:    filepath.Join(tmp, "gate.key"),
		PubPath:    filepath.Join(tmp, "gate.pub"),
		AuditPath:  filepath.Join(tmp, "approvals.log"),
		SockPath:   filepath.Join(tmp, "sock"),
		ConfigPath: configPath,
	}
	if got != want {
		t.Errorf("resolveInitPaths(dev) =\n  %+v\nwant\n  %+v", got, want)
	}
}

// TestResolveInitPaths_NonAbsoluteErrors asserts a non-absolute config
// path is rejected (production safety — the derivation is path-relative
// and a relative path would silently mis-root the state dir).
func TestResolveInitPaths_NonAbsoluteErrors(t *testing.T) {
	if _, err := resolveInitPaths("config/config.toml", false /* dev */); err == nil {
		t.Error("resolveInitPaths(relative path) = nil error; want non-nil")
	}
}
```

- [ ] **Step 2b: Run the test to confirm it fails as an honest TDD red**

Run: `go test ./src/signer/cmd/sshgate-signer-telegram/ -run TestResolveInitPaths -v`
Expected: **FAIL — compile error: `undefined: resolveInitPaths` / `undefined: initPaths`.** This is a genuine red (the function and struct do not exist yet), NOT a permission error. We are testing the pure resolver, so nothing touches the filesystem.

- [ ] **Step 3: Introduce the pure `resolveInitPaths` and rewire `doInitFlow`**

In `src/signer/cmd/sshgate-signer-telegram/main.go`, add the `initPaths` type and the pure `resolveInitPaths` function (no I/O), and refactor `doInitFlow` to call it then perform the side effects from the returned struct.

Add the type + resolver (e.g. just above `doInitFlow`):

```go
// initPaths holds the resolved on-disk locations for `--init`.
type initPaths struct {
	Root, KeyPath, PubPath, AuditPath, SockPath, ConfigPath string
}

// resolveInitPaths computes the init layout from the --config path. It
// performs NO I/O (so it is unit-testable unprivileged); doInitFlow does
// the MkdirAll/keygen/config-write using the result.
//
// Production (non-dev): root is the config file's GRANDPARENT
// (<root>/config/config.toml -> <root>), keys/pub/audit live under
// <root>/keys + <root>/log, and the socket is the fixed runtime path
// /run/sshgatesigner/sock provisioned by the systemd unit
// (RuntimeDirectory=sshgatesigner). A non-absolute configPath is rejected
// — the path-relative derivation would otherwise silently mis-root the
// state dir (audit B4/B5/B6).
//
// Dev (--init --dev): everything is anchored FLAT under the config file's
// own directory (or $XDG_RUNTIME_DIR/signer-<pid> when no absolute
// --config is given) so tests and local runs need no privileged /run or
// /var/lib access. This preserves the existing dev layout exactly.
func resolveInitPaths(configPath string, dev bool) (initPaths, error) {
	if dev {
		var root string
		if configPath != "" && filepath.IsAbs(configPath) {
			root = filepath.Dir(configPath)
		} else {
			runtime := os.Getenv("XDG_RUNTIME_DIR")
			if runtime == "" {
				runtime = filepath.Join(os.TempDir(), "signer-dev")
			}
			root = filepath.Join(runtime, "signer-"+strconv.Itoa(os.Getpid()))
		}
		return initPaths{
			Root:       root,
			KeyPath:    filepath.Join(root, "gate.key"),
			PubPath:    filepath.Join(root, "gate.pub"),
			AuditPath:  filepath.Join(root, "approvals.log"),
			SockPath:   filepath.Join(root, "sock"),
			ConfigPath: configPath,
		}, nil
	}

	// Production: derive the state root from the --config grandparent so
	// the operator controls the layout. install.sh passes
	// --config /var/lib/sshgatesigner/config/config.toml ->
	// root = /var/lib/sshgatesigner (audit B4 — previously hardcoded
	// /var/lib/signer, which the unprivileged sshgatesigner user could
	// not create).
	if configPath == "" || !filepath.IsAbs(configPath) {
		return initPaths{}, fmt.Errorf("non-dev --init requires an absolute --config path (e.g. /var/lib/sshgatesigner/config/config.toml); got %q", configPath)
	}
	root := filepath.Dir(filepath.Dir(configPath))
	return initPaths{
		Root:       root,
		KeyPath:    filepath.Join(root, "keys", "gate.key"),
		PubPath:    filepath.Join(root, "keys", "gate.pub"),
		AuditPath:  filepath.Join(root, "log", "approvals.log"),
		// Socket is a fixed runtime path provisioned by the systemd unit
		// (RuntimeDirectory=sshgatesigner) — audit B5.
		SockPath:   "/run/sshgatesigner/sock",
		ConfigPath: configPath,
	}, nil
}
```

Then rewrite the head of `doInitFlow` (currently `:474-499`, the `var root, keyPath, ... ` declaration through the dev/non-dev `if/else`) to call the resolver and bind locals from the struct — preserving the EXACT existing production behavior of the subsequent side-effect block (`:501-552`: the `dirs := []string{filepath.Dir(keyPath), filepath.Dir(auditPath), filepath.Dir(sockPath), filepath.Dir(configPath)}` MkdirAll loop, `signer.GenerateKeyPair(keyPath, pubPath)`, the overwrite guard, and the `body := fmt.Sprintf(...)` config write). For example:

```go
func doInitFlow(configPath string, dev bool) error {
	p, err := resolveInitPaths(configPath, dev)
	if err != nil {
		return err
	}
	root, keyPath, pubPath, auditPath, sockPath := p.Root, p.KeyPath, p.PubPath, p.AuditPath, p.SockPath
	_ = root // retained for parity with existing logf/dir usage

	// ... unchanged from here: the MkdirAll loop over
	// {dir(keyPath), dir(auditPath), dir(sockPath), dir(configPath)},
	// GenerateKeyPair(keyPath, pubPath), the overwrite guard, and the
	// config write using keyPath/pubPath/auditPath/sockPath. The
	// production MkdirAll of /run/sshgatesigner (dir(sockPath)) stays —
	// install.sh's systemd unit pre-creates it; it is just not exercised
	// by the unit test, which calls resolveInitPaths directly.
}
```

(Keep `root` only if the existing body references it; the real body uses `keyPath`/`auditPath`/`sockPath`/`configPath`, so drop the `_ = root` line if `root` is unused after the refactor to avoid an "unused variable" compile error.)

- [ ] **Step 4: Run the resolver test to confirm it passes**

Run: `go test ./src/signer/cmd/sshgate-signer-telegram/ -run TestResolveInitPaths -v`
Expected: PASS for all three subtests (`_NonDev`, `_Dev`, `_NonAbsoluteErrors`). No filesystem was touched.

- [ ] **Step 5: Run the signer package suite**

Run: `go test -race ./src/signer/...`
Expected: all `ok`, no `FAIL` (the refactor preserves `doInitFlow`'s production behavior; any existing dev-mode `doInitFlow` test still passes).

- [ ] **Step 6: Commit**

```bash
git add src/signer/cmd/sshgate-signer-telegram/main.go src/signer/cmd/sshgate-signer-telegram/init_test.go
git commit -m "fix(signer): pure resolveInitPaths derives root from --config, socket /run/sshgatesigner/sock (B4/B5/B6)"
```

## Task 3.2 — `install.sh` auto-stages `gate.pub` to the MCP distribution path (B6)

**Files:**
- Modify: `scripts/install.sh` — add a step after Step 9 (after the daemon-active assertion, `:254`)

B6's fix falls out of B4 (init now writes `gate.pub` to `/var/lib/sshgatesigner/keys/gate.pub`). To make the manual `cp` un-skippable, `install.sh` also stages the pubkey into `~/.config/sshgate/pubkey-distrib/gate.pub` (chowned to `$SUDO_USER`), which is exactly where `add_server`'s `resolveAddServerCfg` (`add_server.go:504`) reads it. This closes B6 even if the operator forgets setup.md T2.6.

- [ ] **Step 1: Add the pubkey-staging step**

In `scripts/install.sh`, after line 254 (`log "sshgate-signer-telegram is active"`) and before line 255 (`log "done"`), insert:

```bash
# Step 10: stage gate.pub into the invoking user's MCP distribution
# path so /sshgate:add (read-write) can find it without a manual copy.
# add_server reads ~/.config/sshgate/pubkey-distrib/gate.pub (audit B6).
PUBKEY_SRC="$SIGNER_HOME/keys/gate.pub"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -f "$PUBKEY_SRC" ]; then
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [ -n "$USER_HOME" ]; then
        DISTRIB_DIR="$USER_HOME/.config/sshgate/pubkey-distrib"
        log "staging gate.pub -> $DISTRIB_DIR/gate.pub (owner $SUDO_USER)"
        install -d -m 0755 -o "$SUDO_USER" -g "$SUDO_USER" "$DISTRIB_DIR"
        install -m 0644 -o "$SUDO_USER" -g "$SUDO_USER" "$PUBKEY_SRC" "$DISTRIB_DIR/gate.pub"
    fi
fi
```

- [ ] **Step 2: Syntax-check the script**

Run: `bash -n scripts/install.sh`
Expected: exit 0, no output (valid bash).

- [ ] **Step 3: Trace-verify the new block in isolation**

Run this self-contained trace (simulates the staging block with a fake source pubkey and a fake SUDO_USER home, proving the `install -d`/`install` path logic is sound without needing root or the real signer):

```bash
bash -x -c '
SIGNER_HOME=$(mktemp -d); mkdir -p "$SIGNER_HOME/keys"; echo "ssh-ed25519 AAAA test" > "$SIGNER_HOME/keys/gate.pub"
SUDO_USER="$USER"
PUBKEY_SRC="$SIGNER_HOME/keys/gate.pub"
USER_HOME=$(mktemp -d)
DISTRIB_DIR="$USER_HOME/.config/sshgate/pubkey-distrib"
install -d -m 0755 "$DISTRIB_DIR"
install -m 0644 "$PUBKEY_SRC" "$DISTRIB_DIR/gate.pub"
cat "$DISTRIB_DIR/gate.pub"
'
```

Expected: the trace ends by printing `ssh-ed25519 AAAA test`, proving the `install -d` + `install` sequence stages the file correctly. (The real block adds `-o/-g "$SUDO_USER"` which requires root; the trace drops those flags since the test runs unprivileged.)

- [ ] **Step 4: Commit**

```bash
git add scripts/install.sh
git commit -m "fix(install): auto-stage gate.pub to MCP pubkey-distrib path (B6)"
```

## Task 3.3 — Tier-aware `/sshgate:status` (M4)

**Files:**
- Modify: `src/mcp/tools/status.go` — `SignerStatus` (add `Configured` field, `:22-26`), `probeSignerSocket` (`:170-187`)
- Modify: `src/mcp/server.go` — `formatStatusSummary` (`:338-353`)
- Modify: `commands/status.md` — Tier-1 expected output (lines 20-28)
- Test: `src/mcp/tools/status_tier_test.go` (new)

The audit (M4) says status must print the actually-probed path (already does — `status.go:79` uses `r.SignerSockPath`, which now defaults to `/run/sshgatesigner/sock` via Task 1.2) AND be tier-aware: an unreachable signer is NORMAL on Tier 1. We add a `Configured` signal — on Tier 1 the socket simply doesn't exist (a daemon was never installed), which dial reports as `connect: no such file or directory` / `connect: connection refused`. We classify that as "not configured (read-only / Tier 1)" rather than a failure to debug. The probed path is already correct; we make the *interpretation* tier-aware.

- [ ] **Step 1: Write the failing test**

Create `src/mcp/tools/status_tier_test.go`:

```go
package tools_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestStatus_Tier1SignerNotConfigured asserts that when the signer
// socket does not exist (Tier 1: no daemon installed), status reports
// Configured=false rather than presenting it as a failure. Audit M4.
func TestStatus_Tier1SignerNotConfigured(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: filepath.Join(dir, "nonexistent.sock"),
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.SignerSocket.Reachable {
		t.Error("Reachable = true; want false (socket absent)")
	}
	if out.SignerSocket.Configured {
		t.Error("Configured = true; want false (Tier 1: socket file absent)")
	}
	// The probed path must be reported verbatim.
	if out.SignerSocket.Path != runner.SignerSockPath {
		t.Errorf("Path = %q; want %q", out.SignerSocket.Path, runner.SignerSockPath)
	}
}

// TestStatus_Tier2SignerConfiguredAndReachable asserts that when the
// socket exists and dials, both Configured and Reachable are true.
func TestStatus_Tier2SignerConfiguredAndReachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "signer.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: sockPath,
	}
	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !out.SignerSocket.Reachable {
		t.Errorf("Reachable = false; want true (err=%q)", out.SignerSocket.Error)
	}
	if !out.SignerSocket.Configured {
		t.Error("Configured = false; want true (socket present and dialable)")
	}
}
```

- [ ] **Step 2: Run the test to confirm it fails**

Run: `go test ./src/mcp/tools/ -run TestStatus_Tier -v`
Expected: FAIL — `out.SignerSocket.Configured` does not compile (field does not exist yet).

- [ ] **Step 3: Add the `Configured` field to `SignerStatus`**

In `src/mcp/tools/status.go`, replace lines 22-26 from:

```go
type SignerStatus struct {
	Path      string `json:"path"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}
```

to:

```go
type SignerStatus struct {
	Path      string `json:"path"`
	Reachable bool   `json:"reachable"`
	// Configured is true when the socket file EXISTS (a signer daemon
	// is installed), regardless of whether the dial succeeded. On Tier 1
	// (read-only, no signer) the socket file is absent, so Configured is
	// false and an unreachable signer is the NORMAL, expected state —
	// not something to debug. Audit M4.
	Configured bool   `json:"configured"`
	Error      string `json:"error,omitempty"`
}
```

- [ ] **Step 4: Set `Configured` in `probeSignerSocket`**

In `src/mcp/tools/status.go`, replace `probeSignerSocket` (lines 170-187) from:

```go
func probeSignerSocket(ctx context.Context, path string) SignerStatus {
	s := SignerStatus{Path: path}
	if path == "" {
		s.Error = "signer socket path not configured"
		return s
	}
	dialCtx, cancel := context.WithTimeout(ctx, statusSignerDialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", path)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	_ = conn.Close()
	s.Reachable = true
	return s
}
```

to:

```go
func probeSignerSocket(ctx context.Context, path string) SignerStatus {
	s := SignerStatus{Path: path}
	if path == "" {
		s.Error = "signer socket path not configured"
		return s
	}
	// Configured iff the socket file exists. Absent = Tier 1 (no signer
	// daemon installed); that is normal, not a failure. Audit M4.
	if _, err := os.Stat(path); err == nil {
		s.Configured = true
	}
	dialCtx, cancel := context.WithTimeout(ctx, statusSignerDialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", path)
	if err != nil {
		s.Error = err.Error()
		return s
	}
	_ = conn.Close()
	s.Reachable = true
	return s
}
```

- [ ] **Step 5: Add the `os` import to status.go**

In `src/mcp/tools/status.go`, change the import block (lines 3-11) from:

```go
import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)
```

to:

```go
import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)
```

- [ ] **Step 6: Make `formatStatusSummary` tier-aware**

In `src/mcp/server.go`, replace `formatStatusSummary` (lines 338-353) from:

```go
func formatStatusSummary(out tools.StatusOutput) string {
	var b strings.Builder
	if out.SignerSocket.Reachable {
		fmt.Fprintf(&b, "signer: reachable (%s)", out.SignerSocket.Path)
	} else {
		fmt.Fprintf(&b, "signer: UNREACHABLE (%s): %s", out.SignerSocket.Path, out.SignerSocket.Error)
	}
	for _, sv := range out.Servers {
		if sv.Reachable {
			fmt.Fprintf(&b, "\n  %s: ok %dms", sv.Alias, sv.PingMS)
		} else {
			fmt.Fprintf(&b, "\n  %s: DOWN %s", sv.Alias, sv.Error)
		}
	}
	return b.String()
}
```

to:

```go
func formatStatusSummary(out tools.StatusOutput) string {
	var b strings.Builder
	switch {
	case out.SignerSocket.Reachable:
		fmt.Fprintf(&b, "signer: reachable (%s)", out.SignerSocket.Path)
	case !out.SignerSocket.Configured:
		// Tier 1: no signer daemon installed. This is the expected
		// read-only state, not a failure to debug (audit M4).
		fmt.Fprintf(&b, "signer: not configured (%s) — read-only / Tier 1; writes are denied at the gate. Run /sshgate:setup to add a Telegram signer.", out.SignerSocket.Path)
	default:
		// Configured (socket file present) but the dial failed — a real
		// Tier-2 daemon problem worth surfacing.
		fmt.Fprintf(&b, "signer: UNREACHABLE (%s): %s", out.SignerSocket.Path, out.SignerSocket.Error)
	}
	for _, sv := range out.Servers {
		if sv.Reachable {
			fmt.Fprintf(&b, "\n  %s: ok %dms", sv.Alias, sv.PingMS)
		} else {
			fmt.Fprintf(&b, "\n  %s: DOWN %s", sv.Alias, sv.Error)
		}
	}
	return b.String()
}
```

- [ ] **Step 7: Update `commands/status.md` Tier-1 guidance**

In `commands/status.md`, replace lines 20-28 from:

```markdown
```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: yes
```

If unreachable, surface the error verbatim and suggest
`systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 30 --no-pager`
as next steps. Do not run them yourself unless the user asks.
```

with:

```markdown
```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: yes
```

Branch on `signer_socket.configured` before deciding what to print:

- `configured: false` → this is a **Tier-1 (read-only)** install: no
  signer daemon exists, so an unreachable socket is EXPECTED. Print it
  as normal, e.g.:

  ```
  Signer
    socket:    /run/sshgatesigner/sock
    status:    not configured (read-only / Tier 1) — writes denied at the gate
  ```

  Do NOT suggest debugging the daemon; suggest `/sshgate:setup` to add a
  signer instead.
- `configured: true` AND `reachable: false` → a real Tier-2 daemon
  problem. Surface the error verbatim and suggest
  `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 30 --no-pager`. Do not run
  them yourself unless the user asks.
```

- [ ] **Step 8: Run the tier-status test to confirm it passes**

Run: `go test ./src/mcp/tools/ -run TestStatus_Tier -v`
Expected: PASS for both subtests.

- [ ] **Step 9: Run the full mcp suite (existing status tests must still pass)**

Run: `go test -race ./src/mcp/...`
Expected: all `ok` (the pre-existing `TestStatus_SignerMissing` still passes — `Reachable` is still false for an absent socket; we only added a field).

- [ ] **Step 10: Commit**

```bash
git add src/mcp/tools/status.go src/mcp/server.go commands/status.md src/mcp/tools/status_tier_test.go
git commit -m "fix(status): tier-aware signer reporting; absent socket is normal on Tier 1 (M4)"
```

## Task 3.4 — Scrub vestigial vel/signer naming (m2)

**Files:**
- Modify: `src/signer/cmd/sshgate-signer-telegram/main.go` — header comment (`:1-9`), hosted-config doc comment (`:71`), `defaultConfigPath` (`:416-423`), the inline comment at `:148-150`

The audit (m2) flags `VELSIGNER_CONFIG`, `/etc/signer`, and "signer user" naming left over from the vel→sshgate rename. We rename the env var to `SSHGATE_SIGNER_CONFIG`, set the default config path to the canonical `/var/lib/sshgatesigner/config/config.toml`, and fix the stale comments. (No production code reads `VELSIGNER_CONFIG`; the systemd unit passes `--config` explicitly, so this default is only hit by hand-runs — but it should be correct.)

- [ ] **Step 1: Fix `defaultConfigPath`**

In `src/signer/cmd/sshgate-signer-telegram/main.go`, replace lines 416-423 from:

```go
// defaultConfigPath returns the value of $VELSIGNER_CONFIG if set,
// otherwise /etc/signer/config.toml.
func defaultConfigPath() string {
	if p := os.Getenv("VELSIGNER_CONFIG"); p != "" {
		return p
	}
	return "/etc/signer/config.toml"
}
```

to:

```go
// defaultConfigPath returns the value of $SSHGATE_SIGNER_CONFIG if set,
// otherwise the canonical /var/lib/sshgatesigner/config/config.toml.
// The systemd unit always passes --config explicitly; this default is
// only used for hand-runs.
func defaultConfigPath() string {
	if p := os.Getenv("SSHGATE_SIGNER_CONFIG"); p != "" {
		return p
	}
	return "/var/lib/sshgatesigner/config/config.toml"
}
```

- [ ] **Step 2: Fix the file header comment (lines 1-9)**

In `src/signer/cmd/sshgate-signer-telegram/main.go`, replace lines 1-9 from:

```go
// Command signer is the local approval daemon for SSHGate. It runs
// as a dedicated OS user (`signer`) on Karthi's laptop, owns the
// master Ed25519 signing key, and signs commands only after the
// configured Backend returns Approved.
//
// Flags:
//
//	--config <path>   TOML config (default: /etc/signer/config.toml or
//	                  $VELSIGNER_CONFIG)
```

to:

```go
// Command sshgate-signer-telegram is the local approval daemon for
// SSHGate. It runs as a dedicated OS user (`sshgatesigner`) on the
// operator's laptop, owns the master Ed25519 signing key, and signs
// commands only after the configured Backend returns Approved.
//
// Flags:
//
//	--config <path>   TOML config (default:
//	                  /var/lib/sshgatesigner/config/config.toml or
//	                  $SSHGATE_SIGNER_CONFIG)
```

- [ ] **Step 3: Fix the hosted-config doc comment (line 71)**

In `src/signer/cmd/sshgate-signer-telegram/main.go`, change line 71 (inside the `hostedConfig` doc comment — the `/etc/signer/config.toml` reference the Step-5 grep backstop would otherwise catch) from:

```go
// /etc/signer/config.toml redirects approval traffic from the
```

to:

```go
// /var/lib/sshgatesigner/config/config.toml redirects approval traffic from the
```

- [ ] **Step 4: Fix the stale "signer user" inline comment (lines 148-150)**

In `src/signer/cmd/sshgate-signer-telegram/main.go`, change lines 148-150 from:

```go
	// Note: assertion that we're running as the `signer` user
	// (production) vs any user (--dev) is omitted from v1.4. The
	// install script creates the sshgatesigner user and the systemd unit
```

to:

```go
	// Note: assertion that we're running as the `sshgatesigner` user
	// (production) vs any user (--dev) is omitted from v1.4. The
	// install script creates the sshgatesigner user and the systemd unit
```

- [ ] **Step 5: Confirm no stale tokens remain**

Run: `grep -rn "VELSIGNER\|/etc/signer\|/var/lib/signer\|/run/signer/sock" src/`
Expected: no matches (empty output). If any line matches, fix it the same way before committing.

- [ ] **Step 6: Build + signer tests**

Run: `go build ./... && go test -race ./src/signer/...`
Expected: build exit 0; all `ok`.

- [ ] **Step 7: Commit**

```bash
git add src/signer/cmd/sshgate-signer-telegram/main.go
git commit -m "chore(signer): scrub vel/etc-signer naming -> sshgatesigner (m2)"
```

---

# PHASE 4 — Docs / README parity (M2 docs, M4 docs, m4)

Make every documented step + expected output match reality.

## Task 4.1 — README parity (M2 docs, m4)

**Files:**
- Modify: `README.md` — Go version (`:90`), install snippet (`:77-90`), the "systemd unconditional" requirement line

- [ ] **Step 1: Fix the Go version + systemd-conditional requirement line**

In `README.md`, change line 90 from:

```markdown
Requirements: Linux with systemd, Go 1.22+, sudo (for Tier 2 only), a Telegram account (for Tier 2 only). Remote servers must be reachable over SSH and run Linux.
```

to:

```markdown
Requirements: Go 1.25+; Linux with systemd (Tier 2 only — Tier 1 needs no systemd), sudo (Tier 2 only), a Telegram account (Tier 2 only). Remote servers must be reachable over SSH and run Linux.
```

- [ ] **Step 2: Fix the manual-install snippet to use the clone + install-local flow**

In `README.md`, change lines 77-84 from:

```markdown
**Manual install.** Clone the repo, then in Claude Code:

```
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
/reload-plugins
/sshgate:setup
```
```

to:

```markdown
**Manual install.** Clone the repo, build the binaries onto your `$PATH`, then add the plugin:

```
git clone https://github.com/karthikeyan5/SSHGate ~/src/SSHGate
cd ~/src/SSHGate && make install-local      # sshgate-mcp + sshgate-signer-telegram -> ~/go/bin; gate -> ~/.config/sshgate/bin
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
/reload-plugins
/sshgate:setup
```

(`make install-local` is required because Claude Code's `/plugin install` copies only the plugin subtree into its cache — not `src/`, `Makefile`, or `bin/` — so the MCP binary must be on your `$PATH`, not under the cache. Ensure `~/go/bin` is on `$PATH`.)
```

- [ ] **Step 3: Confirm no remaining "Go 1.22" in README**

Run: `grep -n "1.22\|1\.26" README.md`
Expected: no matches (empty output).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): Go 1.25 floor, install-local flow, systemd is Tier-2-only (M2/m4)"
```

## Task 4.2 — INSTALL.md parity: install-local flow, step-3 probe, Tier-1 status output (B1, B2, M4, M2)

**Files:**
- Modify: `INSTALL.md` — prereq Go version (`:84,87`), build claim (`:55`), step 2 (`:97-123`), step 3 (`:126-152`), step 4 build claim (`:182`), step 5 expected output (`:202-218`)

- [ ] **Step 1: Fix the prerequisite Go version**

In `INSTALL.md`, change lines 84-87 from:

```markdown
If "command not found": tell the user to install Go ≥1.22 from
https://go.dev/dl/, then re-run this install. Stop.

If the printed version is older than 1.22: tell the user to upgrade Go and
re-run. Stop.
```

to:

```markdown
If "command not found": tell the user to install Go ≥1.25 from
https://go.dev/dl/, then re-run this install. Stop.

If the printed version is older than 1.25: tell the user to upgrade Go and
re-run. Stop.
```

- [ ] **Step 2: Fix the "binaries built via make build" claim**

In `INSTALL.md`, change line 55 from:

```markdown
5. SSHGate binaries — built from source via `make build` on your machine.
   No remote dependencies fetched at runtime.
```

to:

```markdown
5. SSHGate binaries — built from your clone via `make install-local`
   (puts `sshgate-mcp` + `sshgate-signer-telegram` on your `$PATH` and
   the remote `sshgate-gate-linux-amd64` under `~/.config/sshgate/bin/`).
   No remote dependencies fetched at runtime.
```

- [ ] **Step 3: Rewrite step 2 (clone → install-local → marketplace → install → reload)**

In `INSTALL.md`, replace lines 97-123 (the whole "## 2. Clone the repo and add as a local marketplace" section body) from:

```markdown
`/sshgate:setup` needs access to the full Go source tree (`src/`, `scripts/`,
`Makefile`). Claude Code's marketplace cache from a remote GitHub source only
ships the plugin subtree, not the build inputs. So the canonical install is:
clone the repo first, then point Claude Code at the local clone as a
marketplace.

Tell the user:

> "Pick a directory to keep the SSHGate source (e.g. `~/src`), then run:
>
>     mkdir -p ~/src && cd ~/src && git clone https://github.com/karthikeyan5/SSHGate
>
> Then in this Claude Code session, run these three slash commands and tell
> me when they're done:
>
>     /plugin marketplace add ~/src/SSHGate
>     /plugin install sshgate@sshgate
>     /reload-plugins
>
> Replace `~/src/SSHGate` with wherever you cloned. The `git clone` location
> is permanent — the plugin's `/sshgate:setup` reads source from there to
> compile binaries."

Wait for the user to confirm completion and capture the clone path (we'll
need it in step 3).
```

to:

```markdown
Claude Code's `/plugin install` copies ONLY the plugin subtree
(`.claude-plugin/`, `commands/`, `skills/`, `.mcp.json`) into a versioned
cache — it strips `src/`, `scripts/`, `Makefile`, and `bin/`. So the MCP
binary cannot live under the cache; it must be on your `$PATH`. The
canonical install: clone the repo, build the binaries onto `$PATH` with
`make install-local`, then register the clone as a local marketplace.

Tell the user:

> "Pick a directory to keep the SSHGate source (e.g. `~/src`), clone it, and
> build the binaries onto your PATH:
>
>     mkdir -p ~/src && cd ~/src && git clone https://github.com/karthikeyan5/SSHGate
>     cd ~/src/SSHGate && make install-local
>
> `make install-local` puts `sshgate-mcp` and `sshgate-signer-telegram` in
> `~/go/bin` and the remote gate binary in `~/.config/sshgate/bin/`. Confirm
> `~/go/bin` is on your PATH:
>
>     command -v sshgate-mcp || echo 'NOT ON PATH — add ~/go/bin (or `go env GOPATH`/bin) to your PATH and re-open the shell'
>
> Then in this Claude Code session, run these three slash commands and tell
> me when they're done:
>
>     /plugin marketplace add ~/src/SSHGate
>     /plugin install sshgate@sshgate
>     /reload-plugins
>
> Replace `~/src/SSHGate` with wherever you cloned. The `/reload-plugins`
> AFTER `make install-local` is what makes the MCP tool surface appear (the
> server spawns the now-on-PATH `sshgate-mcp` binary)."

Wait for the user to confirm completion and capture the clone path (we'll
need it in step 3).
```

- [ ] **Step 4: Replace the broken step-3 cache-depth probe**

In `INSTALL.md`, replace lines 126-152 (the whole "## 3. Verify the plugin loaded" section body, the bash block included) from:

```markdown
After step 2's `/reload-plugins`, the SSHGate slash commands should be
available. Probe:

```bash
PLUGIN_ROOT=$(ls -d ~/.claude/plugins/cache/*/sshgate 2>/dev/null | head -1)
if [ -z "$PLUGIN_ROOT" ]; then
  echo "ERROR: sshgate plugin not found in ~/.claude/plugins/cache — did step 2 complete?"
  exit 1
fi
SRC_ROOT=$(cd "$PLUGIN_ROOT/../.." 2>/dev/null && pwd)
if [ -z "$SRC_ROOT" ] || [ ! -f "$SRC_ROOT/go.mod" ]; then
  # The marketplace.json points "source" at "." so PLUGIN_ROOT itself may be
  # the repo root. Try that.
  if [ -f "$PLUGIN_ROOT/go.mod" ]; then
    SRC_ROOT="$PLUGIN_ROOT"
  else
    echo "ERROR: no go.mod near $PLUGIN_ROOT — looks like the marketplace points at a remote GitHub source, not a local clone. Go back to step 2 and 'git clone' first, then 'marketplace add' the clone path."
    exit 1
  fi
fi
echo "Plugin source root: $SRC_ROOT"
```

If `go.mod` is missing, the marketplace was added with a remote source
rather than a local clone path. Stop and send the user back to step 2.
```

to:

```markdown
After step 2's `/reload-plugins`, the SSHGate slash commands should be
available and the MCP binary should be on `$PATH`. The cache does NOT
contain `src/` or `go.mod` (that is expected and correct — the binaries
live on `$PATH`, not under the cache). Probe the two things that actually
matter:

```bash
command -v sshgate-mcp >/dev/null 2>&1 && echo "mcp-bin: ok ($(command -v sshgate-mcp))" || echo "mcp-bin: MISSING — re-run 'make install-local' in your clone and ensure ~/go/bin is on PATH"
command -v sshgate-signer-telegram >/dev/null 2>&1 && echo "signer-bin: ok" || echo "signer-bin: MISSING (only needed for Tier 2) — re-run 'make install-local'"
```

If `sshgate-mcp` is MISSING, the binary is not on `$PATH`: send the user
back to step 2's `make install-local` and the PATH check. The MCP tool
surface will be dead until `sshgate-mcp` resolves on `$PATH` and the
session is reloaded.
```

- [ ] **Step 5: Fix the step-4 "build all three" claim**

In `INSTALL.md`, change line 182 from:

```markdown
- Build `bin/sshgate-mcp`, `bin/sshgate-gate-linux-amd64`, `bin/sshgate-signer-telegram`.
```

to:

```markdown
- Confirm the binaries from `make install-local` are on `$PATH`
  (`sshgate-mcp`, `sshgate-signer-telegram`) and the gate cross-binary is
  staged at `~/.config/sshgate/bin/sshgate-gate-linux-amd64`.
```

- [ ] **Step 6: Fix the step-5 Tier-1 expected status output (M4)**

In `INSTALL.md`, replace lines 202-218 (from "For a Tier 1 install" through the Tier-2 daemon-debug paragraph) from:

```markdown
For a Tier 1 install with no servers yet registered, expect:

```
Signer
  socket:    /run/sshgatesigner/sock
  reachable: no   (signer not configured for tier 1 — expected)

No servers registered. Add one with /sshgate:add <alias> <user@host>.
```

For a Tier 2 install with no servers yet, expect the signer socket
reachable. Either case is healthy at this point.

If `signer_socket.reachable: no` AND the user picked Tier 2, the daemon
didn't come up. Run `systemctl status sshgate-signer-telegram` and
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`, surface the
output, and ask the user whether to keep debugging or roll back.
```

to:

```markdown
For a Tier 1 install with no servers yet registered, expect (note the
`status: not configured` line — the signer socket is absent on Tier 1,
which is the normal read-only state, NOT an error):

```
Signer
  socket:    /run/sshgatesigner/sock
  status:    not configured (read-only / Tier 1) — writes denied at the gate

No servers registered. Add one with /sshgate:add <alias> <user@host>.
```

For a Tier 2 install with no servers yet, expect the signer socket
reachable. Either case is healthy at this point.

If status reports `configured: true` AND `reachable: no` (Tier 2 only — the
socket file exists but the dial failed), the daemon didn't come up. Run
`systemctl status sshgate-signer-telegram` and
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`, surface the
output, and ask the user whether to keep debugging or roll back. On Tier 1
a `not configured` signer is expected — do NOT debug a daemon that was
never installed.
```

- [ ] **Step 7: Confirm no stale Go-version or "make build" miscount remains**

Run two checks (the previous single-grep form had unescaped backticks inside double quotes, which the shell tried to command-substitute — these avoid backticks entirely; note `1.25` since the floor moved):

```bash
grep -n '1\.25' INSTALL.md
grep -nF 'bin/sshgate-mcp' INSTALL.md
```

Expected: the first shows only the updated `1.25` Go-floor lines (no `1.22` anywhere — verify separately with `grep -n '1\.22' INSTALL.md` returning empty); the second returns empty (the "build all three `bin/sshgate-mcp`, `bin/sshgate-gate-linux-amd64`, `bin/sshgate-signer-telegram`" miscount line is gone — INSTALL.md now refers to `$PATH` binaries + the staged gate, not `bin/` paths).

- [ ] **Step 8: Commit**

```bash
git add INSTALL.md
git commit -m "docs(install): install-local flow, PATH probe, tier-aware status output (B1/B2/M4/M2)"
```

## Task 4.3 — docs/install-step-by-step.md parity (M2, m4, B3)

**Files:**
- Modify: `docs/install-step-by-step.md` — Go version (`:77,121`), Tier-1 build block (`:124-130`), Tier-2 build line (`:180-183`), macOS line, the `make build` mention

- [ ] **Step 1: Fix the prerequisite Go version**

In `docs/install-step-by-step.md`, change line 77 from:

```markdown
- Go 1.22 or newer on `$PATH` (https://go.dev/dl/).
```

to:

```markdown
- Go 1.25 or newer on `$PATH` (https://go.dev/dl/).
```

- [ ] **Step 2: Fix the Tier-1 manual Go-version line**

In `docs/install-step-by-step.md`, change line 121 from:

```markdown
You need 1.22 or newer. If missing, install from https://go.dev/dl/.
```

to:

```markdown
You need 1.25 or newer. If missing, install from https://go.dev/dl/.
```

- [ ] **Step 3: Replace the Tier-1 build block with `make install-local`**

In `docs/install-step-by-step.md`, replace lines 124-133 (from "### 2. Build the binaries" through the `(signer is **not** needed for tier 1.)` line) from:

```markdown
### 2. Build the binaries

```bash
go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' \
    -o bin/sshgate-gate-linux-amd64 ./src/gate/cmd/sshgate-gate
```

(signer is **not** needed for tier 1.)
```

to:

```markdown
### 2. Build the binaries onto your PATH

```bash
make install-local
```

This puts `sshgate-mcp` (and `sshgate-signer-telegram`, unused in Tier 1)
in `~/go/bin` and the remote gate binary at
`~/.config/sshgate/bin/sshgate-gate-linux-amd64`. The MCP server is spawned
from your `$PATH`, so confirm it resolves:

```bash
command -v sshgate-mcp || echo "NOT ON PATH — add ~/go/bin (or \`go env GOPATH\`/bin) to PATH"
```

`make install-local` is required because Claude Code's `/plugin install`
strips `src/` and `bin/` from the plugin cache.
```

- [ ] **Step 4: Fix the Tier-2 "Build signer" block's stale make hint (M1/B3)**

In `docs/install-step-by-step.md`, replace lines 177-183 (from "### 1. Build signer" through the `(Or use \`make build sshgate-gate-linux\`...)` line) from:

```markdown
### 1. Build signer

```bash
go build -o bin/sshgate-signer-telegram ./src/signer/cmd/sshgate-signer-telegram
```

(Or use `make build sshgate-gate-linux` to build all three binaries.)
```

to:

```markdown
### 1. Build the binaries

`make install-local` is the single build command — it depends on
`make build`, so it produces the clone's `bin/*` artifacts (including
`bin/sshgate-signer-telegram` and `bin/sshgate-gate-linux-amd64`, which
`scripts/install.sh` copies in step 2) AND puts the laptop binaries on
your `$PATH` and stages the gate. If you already ran it for Tier 1, the
artifacts are present — skip to step 2. Otherwise:

```bash
make install-local
```

There is no separate `make build` to run: `install-local` already covers
it.
```

- [ ] **Step 5: Confirm no stale Go-version or `make gate-linux` text remains**

Run: `grep -n "1.22\|make gate-linux\|go build -o bin/sshgate-mcp" docs/install-step-by-step.md`
Expected: no matches.

- [ ] **Step 6: Commit**

```bash
git add docs/install-step-by-step.md
git commit -m "docs(step-by-step): Go 1.25, install-local build flow, fix make hints (M2/m4/B3)"
```

## Task 4.4 — commands/setup.md parity: Step -1 probe, build steps, Tier-1 add, Go version (B1, B2, B3, M3, M2)

**Files:**
- Modify: `commands/setup.md` — Step -1 (`:73-100`), T1.1 Go version (`:213-218`), T1.2 build (`:220-234`), T1.5 add suggestion (`:289-291`), T2.1 build (`:309-313`)

- [ ] **Step 1: Rewrite Step -1 (plugin-load preflight) to probe the PATH binary, not source-in-cache**

In `commands/setup.md`, replace lines 73-100 (the whole "## Step -1 — Plugin-load preflight" section) from:

```markdown
## Step -1 — Plugin-load preflight

Before probing on-disk state, verify the plugin is loaded from a local
clone (not a remote-marketplace cache that ships only the plugin subtree
without the build inputs). `${CLAUDE_PLUGIN_ROOT}` should resolve to a
directory containing `go.mod` and `scripts/install.sh`.

```bash
test -f "${CLAUDE_PLUGIN_ROOT}/go.mod" && echo "src:ok" || echo "src:missing"
```

```bash
test -x "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh" && echo "scripts:ok" || echo "scripts:missing"
```

If either is missing, tell the user verbatim:

> "SSHGate's plugin cache is missing the build inputs (`go.mod` or
> `scripts/install.sh`). This usually means the marketplace was added
> from a remote GitHub source rather than a local clone, which ships
> only the plugin subtree. Fix it:
>
> 1. Clone the repo: `git clone https://github.com/karthikeyan5/SSHGate ~/src/SSHGate`
> 2. Re-add the marketplace from the clone: `/plugin marketplace add ~/src/SSHGate`
> 3. Reinstall: `/plugin uninstall sshgate@sshgate && /plugin install sshgate@sshgate && /reload-plugins`
> 4. Re-run `/sshgate:setup`."

Stop on either failure. Do not silently proceed.
```

to:

```markdown
## Step -1 — Plugin-load preflight

The MCP binary is on the user's `$PATH` (Claude Code's `/plugin install`
strips `src/`/`bin/` from the cache, so it cannot live there). Verify the
binary resolves AND locate the user's clone (which has `src/` for builds).

```bash
command -v sshgate-mcp >/dev/null 2>&1 && echo "mcp-bin:ok ($(command -v sshgate-mcp))" || echo "mcp-bin:missing"
```

Ask the user for their clone path if you don't already have it (it is where
they ran `git clone` / `make install-local` — typically `~/src/SSHGate`).
Verify the clone has the build inputs:

```bash
CLONE="${SSHGATE_CLONE:-$HOME/src/SSHGate}"
test -f "$CLONE/go.mod" && echo "clone:ok ($CLONE)" || echo "clone:missing"
```

If `mcp-bin:missing`, tell the user verbatim:

> "The `sshgate-mcp` binary is not on your `$PATH`. Claude Code's
> `/plugin install` only copies the plugin subtree — it does not build or
> ship binaries. Build them from your clone:
>
> 1. Clone if you haven't: `git clone https://github.com/karthikeyan5/SSHGate ~/src/SSHGate`
> 2. Build onto PATH: `cd ~/src/SSHGate && make install-local`
> 3. Ensure `~/go/bin` (or `\`go env GOPATH\`/bin`) is on your PATH.
> 4. `/reload-plugins`, then re-run `/sshgate:setup`."

If `clone:missing`, ask the user for the actual clone path and re-probe.
Stop on either failure. Do not silently proceed. Remember the clone path as
`$CLONE` — the build steps below run there, NOT in `${CLAUDE_PLUGIN_ROOT}`.
```

- [ ] **Step 2: Fix T1.1 Go version**

In `commands/setup.md`, change lines 216-218 from:

```markdown
If not 1.22 or newer, tell the user to install Go from
https://go.dev/dl/ and stop.
```

to:

```markdown
If not 1.25 or newer, tell the user to install Go from
https://go.dev/dl/ and stop.
```

- [ ] **Step 3: Rewrite T1.2 build steps to build in the clone via install-local**

In `commands/setup.md`, replace lines 220-234 (the whole "### T1.2 — Build binaries" section) from:

```markdown
### T1.2 — Build binaries

Build `sshgate-mcp` and `sshgate-gate-linux-amd64`. sshgate-signer-telegram is NOT needed
in tier 1; skip it.

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/sshgate-mcp ./src/mcp/cmd/sshgate-mcp
```

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/sshgate-gate-linux-amd64 ./src/gate/cmd/sshgate-gate
```

After each build, run `ls -la ${CLAUDE_PLUGIN_ROOT}/bin/<name>` and
report the size.
```

to:

```markdown
### T1.2 — Build binaries (in the user's clone, NOT the plugin cache)

Build runs in `$CLONE` (the git clone, which has `src/`), never in
`${CLAUDE_PLUGIN_ROOT}` (the cache has no `src/`). `make install-local`
puts `sshgate-mcp` on `$PATH` and stages the remote gate binary at
`~/.config/sshgate/bin/sshgate-gate-linux-amd64`. (`sshgate-signer-telegram`
is also built but unused in Tier 1.)

```bash
cd "$CLONE" && make install-local
```

Confirm the gate cross-binary was staged and the MCP binary is on PATH:

```bash
ls -la "${HOME}/.config/sshgate/bin/sshgate-gate-linux-amd64" && command -v sshgate-mcp
```

Report both. If `sshgate-mcp` does not resolve, tell the user to add
`~/go/bin` (or `` `go env GOPATH`/bin ``) to their `$PATH` and re-open the
shell, then re-run.
```

- [ ] **Step 4: Fix T1.5 add suggestion to use `--read-only` (M3)**

In `commands/setup.md`, replace lines 287-291 (the gate-binary path bullet through the add command) from:

```markdown
> - gate binary: <PLUGIN_ROOT>/bin/sshgate-gate-linux-amd64
>
> Add a server:
>
>     /sshgate:add <alias> <user@host>
```

to:

```markdown
> - gate binary: ~/.config/sshgate/bin/sshgate-gate-linux-amd64
>
> Add a server (read-only — no signer yet on Tier 1):
>
>     /sshgate:add <alias> <user@host> --read-only
```

- [ ] **Step 5: Rewrite T2.1 to confirm install-local already produced the bin/ artifacts (no separate `make build`)**

`make install-local` depends on `build` (Task 1.3), so the T1.2 run already
produced the clone's `bin/*` artifacts that `scripts/install.sh` consumes.
There is NO separate `make build` step for Tier 2 — `install-local` is the
single build command.

In `commands/setup.md`, replace lines 309-313 (the whole "### T2.1 — Build sshgate-signer-telegram" section) from:

```markdown
### T2.1 — Build sshgate-signer-telegram

```bash
cd "${CLAUDE_PLUGIN_ROOT}" && go build -o bin/sshgate-signer-telegram ./src/signer/cmd/sshgate-signer-telegram
```
```

to:

```markdown
### T2.1 — Confirm the signer binary + bin/ artifacts (already built by install-local)

`make install-local` (run in T1.2) depends on `make build`, so it already
produced the clone's `bin/*` artifacts — including `bin/sshgate-signer-telegram`
and `bin/sshgate-gate-linux-amd64` — that `scripts/install.sh` (T2.2)
consumes from `$CLONE/bin/`. Do NOT run a separate `make build`;
`install-local` is the single build command.

Just confirm the artifacts install.sh needs are present:

```bash
ls -la "$CLONE/bin/sshgate-signer-telegram" "$CLONE/bin/sshgate-gate-linux-amd64"
```

If either is missing (e.g. T1.2 was skipped), run `cd "$CLONE" && make install-local`.
```

- [ ] **Step 6: Fix the T2.2 / T2.4 install.sh path references to use `$CLONE`**

In `commands/setup.md`, the T2.2 PAUSE block (around line 325) and T2.4 PAUSE block (around line 421) tell the user to run `sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh`. The cache has no `scripts/`. Change BOTH occurrences of:

```
>     sudo ${CLAUDE_PLUGIN_ROOT}/scripts/install.sh
```

to:

```
>     sudo $CLONE/scripts/install.sh
```

And change the path-echo at line 335 from:

```bash
echo "${CLAUDE_PLUGIN_ROOT}/scripts/install.sh"
```

to:

```bash
echo "$CLONE/scripts/install.sh"
```

- [ ] **Step 7: Confirm no stale references remain**

Run: `grep -n "1.22\|CLAUDE_PLUGIN_ROOT}/scripts\|CLAUDE_PLUGIN_ROOT}\" && go build\|/sshgate:add <alias> <user@host>$" commands/setup.md`
Expected: no matches for `1.22` or `${CLAUDE_PLUGIN_ROOT}/scripts`; the bare `/sshgate:add <alias> <user@host>` (without `--read-only`) in the T1.5 summary is gone.

- [ ] **Step 8: Commit**

```bash
git add commands/setup.md
git commit -m "docs(setup): PATH-binary preflight, build in clone, Tier-1 --read-only, Go 1.25 (B1/B2/B3/M3/M2)"
```

---

# PHASE 5 — End-to-end verification

## Task 5.1 — Full unit suite + vet green

**Files:**
- Test only.

- [ ] **Step 1: Run vet**

Run: `make vet`
Expected: no errors (either "vet: no packages yet, skipping" — not expected here — or clean `go vet ./...`).

- [ ] **Step 2: Run the full race suite**

Run: `go test -race ./...`
Expected: every package `ok`, including the new `add_server_resolve_test`, `init_test`, `status_tier_test`. No `FAIL`.

- [ ] **Step 3: Confirm `go mod tidy` is a no-op (floor is stable)**

Run: `go mod tidy && git diff --stat go.mod go.sum`
Expected: no diff.

- [ ] **Step 4: Confirm the tree builds clean and binaries report 0.2.0**

Run: `make build && ./bin/sshgate-mcp --version && ./bin/sshgate-signer-telegram --version && ls -la bin/sshgate-gate-linux-amd64`
Expected: `sshgate-mcp 0.2.0`, `signer 0.2.0`, and `bin/sshgate-gate-linux-amd64` present.

## Task 5.2 — Integration suite (Docker)

**Files:**
- Test only. REQUIRES `docker compose` available.

- [ ] **Step 1: Confirm docker compose is available**

Run: `docker compose version`
Expected: prints a version. If not installed, SKIP this task and note it for the coordinator — the integration suite cannot run without Docker.

- [ ] **Step 2: Run the integration suite**

Run: `go test -race -tags=integration ./tests/integration/... -timeout=180s -v`
Expected: PASS (the suite stands up a Docker SSH target and exercises the gate end-to-end). If it fails, capture the failing test name and the gate/SSH error verbatim before proposing a fix.

## Task 5.3 — Fresh-clone Tier-1 walkthrough (the exact commands a new user runs)

**Files:**
- Verification only. This is a manual trace + automatable prefix. Run from a scratch HOME to avoid clobbering the developer's real `~/.config/sshgate`.

This proves every previously-broken Tier-1 step now works. Use a throwaway `$HOME` and a throwaway `GOBIN` so the walkthrough is hermetic.

- [ ] **Step 1: Set up a hermetic scratch environment**

```bash
export WALK=$(mktemp -d)
export HOME="$WALK/home"; mkdir -p "$HOME"
export GOBIN="$WALK/gobin"; mkdir -p "$GOBIN"
export PATH="$GOBIN:$PATH"
echo "scratch HOME=$HOME GOBIN=$GOBIN"
```

- [ ] **Step 2: Build onto PATH from the clone (the B1/B2 fix)**

```bash
cd /home/karthi/arogara/SSHGate && make install-local
command -v sshgate-mcp && command -v sshgate-signer-telegram
ls -la "$HOME/.config/sshgate/bin/sshgate-gate-linux-amd64"
```

Expected: `sshgate-mcp` resolves under `$GOBIN`; the gate cross-binary exists under the scratch `~/.config/sshgate/bin/`. (Checklist: B1/B2 — binary on PATH, gate in stable location.)

- [ ] **Step 3: Confirm `.mcp.json` points at the bare command (B1)**

```bash
python3 -c "import json;d=json.load(open('/home/karthi/arogara/SSHGate/.mcp.json'));print(d['mcpServers']['sshgate']['command'], d['mcpServers']['sshgate']['env'].get('SSHGATE_SIGNER_SOCK'))"
```

Expected: `sshgate-mcp /run/sshgatesigner/sock`. (Checklist: B1 — no `${CLAUDE_PLUGIN_ROOT}`; B5 — sock env set.)

- [ ] **Step 4: Create the Tier-1 SSH key + registry (mirrors setup.md T1.3/T1.4)**

```bash
mkdir -p "$HOME/.config/sshgate/ssh" && chmod 700 "$HOME/.config/sshgate/ssh"
ssh-keygen -t ed25519 -N '' -C 'sshgate-dedicated' -f "$HOME/.config/sshgate/ssh/sshgate_ed25519"
echo '{"servers":{}}' > "$HOME/.config/sshgate/servers.json"
stat -c '%a' "$HOME/.config/sshgate/ssh/sshgate_ed25519"
```

Expected: ends with `600`.

- [ ] **Step 5: Confirm the MCP server starts and registers tools (fail-fast key check passes)**

```bash
printf '' | timeout 5 sshgate-mcp 2>&1 | head -5
```

Expected: a `sshgate-mcp: ... ready (registry=<cfg>/servers.json key=<cfg>/ssh/<ed25519-keyfile> signer=/run/sshgatesigner/sock)` line on stderr, then clean shutdown on stdin EOF. Critically, the `signer=` path is `/run/sshgatesigner/sock` (B5) and the server does NOT fail-fast (the SSH key exists). (Checklist: B1/B2 — server actually runs; B5 — correct sock path.)

- [ ] **Step 6: Confirm the gate-binary resolver finds the staged binary (B3/m1)**

```bash
cd /home/karthi/arogara/SSHGate && cat > "$WALK/resolve_check_test.go" <<'EOF'
package tools
import ("testing";"path/filepath";"os")
func TestWalkthroughResolve(t *testing.T){
  got,err:=defaultGateBinaryPath()
  if err!=nil{t.Fatal(err)}
  want:=filepath.Join(os.Getenv("HOME"),".config","sshgate","bin","sshgate-gate-linux-amd64")
  if got!=want{t.Fatalf("resolver=%q want=%q",got,want)}
}
EOF
cp "$WALK/resolve_check_test.go" src/mcp/tools/zz_walkthrough_test.go
go test ./src/mcp/tools/ -run TestWalkthroughResolve -v; rm -f src/mcp/tools/zz_walkthrough_test.go
```

Expected: PASS — the resolver returns the scratch `~/.config/sshgate/bin/sshgate-gate-linux-amd64` (prefixed name, configRoot/bin location). (Checklist: B3 — correct name + location; m1 — no dependence on `SSHGATE_PLUGIN_ROOT`.) The temp test file is removed at the end; confirm `git status --short src/mcp/tools/` shows nothing new.

- [ ] **Step 7: Tear down the scratch environment**

```bash
rm -rf "$WALK"; unset WALK HOME GOBIN
# Re-open a fresh shell or re-export your real HOME before continuing.
```

Expected: scratch dir gone. (Note: `add_server` against a real remote and the actual `/sshgate:add` slash-command round-trip need a reachable SSH target — covered by the integration suite in Task 5.2 and the manual checklist below.)

- [ ] **Step 8: Tier-1 checklist — confirm each previously-broken step now works**

Confirm and check off each row (evidence from Steps 2-6 above + Task 5.2):

  - [ ] B1 — `.mcp.json` is a bare PATH command; no `${CLAUDE_PLUGIN_ROOT}/bin` (Step 3).
  - [ ] B2 — `sshgate-mcp` resolves on `$PATH` and the server starts + registers tools (Steps 2, 5).
  - [ ] B3 — gate binary is named `sshgate-gate-linux-amd64` and resolves from `configRoot/bin` (Step 6).
  - [ ] M1 — `make build` produces `bin/sshgate-gate-linux-amd64` (Task 5.1 Step 4).
  - [ ] M2 — `go.mod` floor is `go 1.25.0`; docs say 1.25 (Task 1.4, 4.1-4.4).
  - [ ] M3 — Tier-1 `/sshgate:add` defaults to read-only when no signer pubkey (Task 2.2).
  - [ ] M4 — `/sshgate:status` reports a Tier-1 absent signer as `not configured`, not a failure (Task 3.3 tests).
  - [ ] m1 — resolver reads `CLAUDE_PLUGIN_ROOT`, not the dead `SSHGATE_PLUGIN_ROOT` (Step 6 + Task 2.1).
  - [ ] m3 — all binaries report `0.2.0` (Task 5.1 Step 4).

## Task 5.4 — Tier-2 verification plan

**Files:**
- Verification only. Parts need a real systemd host + Telegram; parts are unit/trace-verifiable here.

- [ ] **Step 1: (Unit, runs here) Confirm init derives the sshgatesigner root**

Run: `go test ./src/signer/cmd/sshgate-signer-telegram/ -run TestResolveInitPaths -v`
Expected: PASS — non-dev resolves `Root=/var/lib/sshgatesigner`, keys at `<root>/keys/gate.{key,pub}`, `SockPath=/run/sshgatesigner/sock`; dev anchors under the temp dir; a relative config path errors. (Checklist: B4 — no `/var/lib/signer`; B6 — gate.pub at the sshgatesigner keys path.)

- [ ] **Step 2: (Trace, runs here) Confirm install.sh references and pubkey-staging are sound**

Run: `bash -n scripts/install.sh && grep -n "var/lib/sshgatesigner\|run/sshgatesigner\|pubkey-distrib\|--config" scripts/install.sh`
Expected: `bash -n` exit 0; grep shows the `--init --config /var/lib/sshgatesigner/config/config.toml` call, the `RuntimeDirectory`-provisioned `/run/sshgatesigner`, the `KEY_PATH=/var/lib/sshgatesigner/keys/gate.key` guard (which now MATCHES what init writes, since B4 derives that root), and the new `pubkey-distrib` staging step (B6).

- [ ] **Step 3: (Trace, runs here) Confirm the systemd unit ↔ socket path agreement (B5)**

Run: `grep -n "RuntimeDirectory\|ReadWritePaths\|ExecStart" scripts/install.sh`
Expected: `RuntimeDirectory=sshgatesigner` and `ReadWritePaths=/var/lib/sshgatesigner /run/sshgatesigner` are present, and `ExecStart` passes `--config /var/lib/sshgatesigner/config/config.toml`. Since init now sets `socket = "/run/sshgatesigner/sock"` (Task 3.1) and the unit provisions `/run/sshgatesigner` with `ProtectSystem=strict`, the daemon can bind the socket and the MCP (default `/run/sshgatesigner/sock`, Task 1.2) dials the same path. (Checklist: B5 — socket paths agree end to end.)

- [ ] **Step 4: (Requires a real systemd host — MANUAL) Full Tier-2 install run**

On a real Linux systemd machine with the clone present, run the documented Tier-2 flow and confirm each:

  - [ ] `make build` then `sudo ./scripts/install.sh` exits 0 (B4 — `--init` no longer permission-denies as the `sshgatesigner` user).
  - [ ] `sudo test -f /var/lib/sshgatesigner/keys/gate.pub` succeeds (B4/B6 — init wrote keys to the right root).
  - [ ] `test -f ~/.config/sshgate/pubkey-distrib/gate.pub` succeeds (B6 — install.sh auto-staged it).
  - [ ] `systemctl is-active sshgate-signer-telegram` → `active`.
  - [ ] `sudo ls -l /run/sshgatesigner/sock` shows the socket exists (B5).
  - [ ] After Telegram config + token (setup.md T2.3/T2.4) and a `/start`, `/sshgate:status` reports `signer: reachable (/run/sshgatesigner/sock)` (B5/M4).

- [ ] **Step 5: (Requires a real remote + Telegram — MANUAL) Signed-write loop**

  - [ ] `/sshgate:add prod ubuntu@<host>` (no `--read-only`, with the pubkey staged) registers and verifies SSHGATE_OK.
  - [ ] A write command (`sshgate.run prod "systemctl restart nginx"`) buzzes the phone, and tapping Approve runs it; tapping Deny stops it. (Closes B6 — the gate has the pubkey and verifies the signature.)

## Task 5.5 — Final review + finish

**Files:**
- None (review + optional branch finish).

- [ ] **Step 1: Confirm the whole tree is committed and clean**

Run: `git status --short`
Expected: empty (all changes committed across the per-task commits).

- [ ] **Step 2: Re-run the full suite one last time**

Run: `go test -race ./... && make vet`
Expected: all green.

- [ ] **Step 3: Use superpowers:finishing-a-development-branch**

Decide merge/PR/cleanup with the coordinator per that skill.

---

## Open questions for the coordinator

These involve real trade-offs or are explicitly flagged "optional/uncertain" in the spec — surfacing rather than silently deciding:

1. **Polluting `~/go/bin` (Task 1.3).** `make install-local` does `go install` into `$GOPATH/bin`, which the spec endorses (c3 pattern). The cost: SSHGate binaries land in the user's shared Go bin, and the flow REQUIRES `~/go/bin` on `$PATH` (we warn if absent, but cannot fix the user's shell). Acceptable? Or should we instead install into a dedicated `~/.config/sshgate/bin/` for ALL three binaries and have `.mcp.json` reference an absolute path there? (That breaks the "bare command" c3 parity but avoids PATH dependence and go/bin pollution.) I went with the c3-parity `go install` approach per the locked decisions; confirm.

2. **Auto-readonly fallback in `/sshgate:add` (Task 2.2).** Spec marks this OPTIONAL. I implemented it as a pubkey-presence probe in the slash command (not in Go), so a Tier-1 user who omits `--read-only` succeeds in read-only mode with a clear notice rather than hard-failing. Trade-off: a Tier-2 user whose pubkey staging failed would silently get a read-only deploy instead of a loud error. Keep the auto-fallback, or revert to requiring the explicit flag and just fixing the docs (M3 doc-only)?

3. **Version bump target (Task 1.5).** I unified on `0.2.0` (one minor past mcp's 0.1.5, signaling the install-flow-fix release). If you'd rather keep 0.1.x (e.g. `0.1.6`) or jump to `1.0.0` for "first actually-installable" framing, say so — it is a single three-line change.

4. **Keep the marketplace dance at all?** The spec asks whether to keep the `/plugin marketplace add` + `/plugin install` flow. I kept it (the slash commands + skills still need to be a real plugin, and `make install-local` only handles binaries). The marketplace `source: "."` plus a clone is still the delivery vehicle for the non-binary components. If you want to drop the marketplace and ship commands/skills some other way, that is a larger redesign out of this plan's scope — flagging only.

5. **`go.mod` go-directive form (Task 1.4).** I set `go 1.25.0` (the exact floor `go mod tidy` settles on, matching the deps' own directives). Some teams prefer the two-segment `go 1.25` language form plus a separate `toolchain` line. `go mod tidy` produced `go 1.25.0`, so I matched it to keep tidy a no-op. Confirm that form is acceptable for your CI.

6. **`scripts/install.sh` still reads binaries from the clone's `bin/` (Task 3.2/4.4). RESOLVED: install-local depends on build.** `install.sh` resolves `$REPO_ROOT/bin/...` from `$0`, so it needs the clone's `bin/` populated. Rather than a separate `make build`, `make install-local` now depends on `build` (Task 1.3: `install-local: build`), so ONE `make install-local` produces the `<clone>/bin/*` artifacts (for install.sh), the `$PATH` binaries (for `.mcp.json`), and the staged gate. setup.md T2.1 (Task 4.4 Step 5) and the step-by-step Tier-2 build (Task 4.3 Step 4) no longer run a separate `make build` — they just confirm the artifacts `install-local` already produced. (The deeper install.sh decoupling — prefer on-PATH binary, fall back to `bin/` — remains a larger change left out of scope.)
