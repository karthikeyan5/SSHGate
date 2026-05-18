# SSHGate v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> Each task is sized for one subagent dispatch (≤ 4h focused work). The subagent is expected to apply strict TDD inside each task: write failing test → confirm red → minimal code → confirm green → refactor → commit. The subagent reports back with a ≤200-word summary and the commit SHA.

**Goal:** Ship SSHGate v1 — a Claude Code plugin that lets Claude SSH into Karthi's servers; read commands run freely, write commands require a single Telegram-button approval from Karthi. Master signing key isolated under a separate Unix user so Claude cannot bypass.

**Architecture:** Three Unix trust domains — karthi (MCP + SSH client), velsigner (separate user owning master Ed25519 signing key + Telegram bot token), Telegram (Karthi's phone for `from.id`-authenticated approval). MCP↔velsigner over Unix socket; velsigner↔Telegram via direct bot API DM. velgate binary on each remote server enforces the gate via OpenSSH `command="..."` forcing and Ed25519 signature verification. Backend interface in velsigner is swappable (Telegram now, hosted server in v2).

**Tech Stack:** Go 1.22+ end-to-end; `golang.org/x/crypto/ssh` for SSH client; `crypto/ed25519` stdlib for signing; `github.com/modelcontextprotocol/go-sdk` v1.6+ for MCP; `github.com/go-telegram-bot-api/telegram-bot-api/v5` for Telegram; `github.com/google/go-cmp/cmp` + stdlib `testing` for tests; `go.uber.org/goleak` for goroutine leak checks; Docker for ephemeral remote-server testing.

**Spec reference:** `docs/specs/2026-05-19-sshgate-design.md` — every task in this plan implements a section of that spec. Subagents MUST read the relevant spec section before starting.

**Code quality rubric:** `~/arogara/code-review/guidelines/{general,go,cli,daemon,plugin}.md`. Subagents implement to this standard; deviations get flagged in the commit message.

---

## File structure (locked before task execution)

```
SSHGate/
├── .claude-plugin/plugin.json    # Plugin manifest (kebab-case name, semver version)
├── .mcp.json                     # Registers sshgate-mcp binary
├── .gitignore                    # bin/, *.tmp, /tmp/*, audit logs
├── README.md                     # User-facing install + usage
├── Makefile                      # build/test/install targets
├── go.mod / go.sum               # one module, module path: github.com/karthikeyan5/sshgate
├── src/
│   ├── common/                    # Shared types, no inbound dependencies
│   │   ├── doc.go                 # Package doc
│   │   ├── classifier.go          # Classify(cmd string) Kind { Read, Write, Unknown }
│   │   ├── classifier_test.go     # Table-driven against testdata/classifier-corpus.txt
│   │   ├── payload.go             # SigPayload struct + Marshal/Unmarshal/Encode/Decode
│   │   ├── payload_test.go        # Round-trip + tamper detection
│   │   └── audit.go               # AuditEvent struct (shared between velsigner + MCP)
│   ├── velgate/
│   │   ├── cmd/velgate/main.go    # Entry point; reads SSH_ORIGINAL_COMMAND
│   │   ├── verify.go              # ParseSignedCommand + VerifyEd25519
│   │   ├── verify_test.go         # Valid sig, expired sig, tampered cmd, wrong key
│   │   ├── executor.go            # Exec(cmd) with stdout/stderr passthrough; SIGTERM forward
│   │   ├── executor_test.go       # Real subprocess (echo, false, sleep + interrupt)
│   │   └── doc.go
│   ├── velsigner/
│   │   ├── cmd/velsigner/main.go  # Entry; loads config, builds backend, runs daemon
│   │   ├── daemon.go              # Daemon{KeyStore, Backend, Socket, Audit}; Serve loop
│   │   ├── daemon_test.go         # End-to-end with MockBackend
│   │   ├── keystore.go            # LoadKey(path) (*ed25519.PrivateKey, error); strict 0600 check
│   │   ├── keystore_test.go       # OK, wrong mode, missing file, malformed
│   │   ├── socket.go              # Unix socket listener; one-line-JSON protocol
│   │   ├── socket_test.go         # Connect, send, receive; concurrent clients
│   │   ├── audit.go               # AuditLog{file *os.File}; append JSON-Lines; fsync per record
│   │   ├── audit_test.go          # Write, reopen, verify lines; survives kill
│   │   └── backend/
│   │       ├── doc.go             # Backend interface contract
│   │       ├── backend.go         # interface Backend { Request(...) (<-chan Result, error) }
│   │       ├── stub.go            # StubBackend (always denies; used by phase-1 e2e)
│   │       ├── stub_test.go
│   │       ├── mock.go            # MockBackend (auto-approves on .Approve()); test helper
│   │       ├── telegram.go        # TelegramBackend (real Telegram bot client)
│   │       └── telegram_test.go   # Against a httptest-based fake Telegram API
│   ├── mcp/
│   │   ├── cmd/sshgate-mcp/main.go  # Entry; reads stdin/stdout (stdio transport)
│   │   ├── server.go              # Server struct; RegisterTools; Run(ctx); stderr-only logging
│   │   ├── server_test.go         # initialize handshake; tools/list shape
│   │   ├── tools/
│   │   │   ├── run.go             # sshgate.run; one server + one command; sync wait
│   │   │   ├── run_test.go        # Read direct; write goes through sign
│   │   │   ├── run_batch.go       # sshgate.run_batch; one approval covers all
│   │   │   ├── run_batch_test.go
│   │   │   ├── list_servers.go
│   │   │   ├── list_servers_test.go
│   │   │   ├── add_server.go      # Auto-setup flow
│   │   │   ├── add_server_test.go
│   │   │   ├── revoke_server.go
│   │   │   ├── revoke_server_test.go
│   │   │   ├── status.go
│   │   │   └── status_test.go
│   │   ├── ssh/
│   │   │   ├── client.go          # ssh.Dial wrapper; host-key checking; one command per session
│   │   │   └── client_test.go     # Against Docker sshd container
│   │   ├── sign/
│   │   │   ├── client.go          # Talks to velsigner socket; encodes/decodes JSON-Lines
│   │   │   └── client_test.go     # Against a fake velsigner socket
│   │   ├── registry/
│   │   │   ├── servers.go         # Servers{}; Load/Save; atomic write (tmp+rename+fsync)
│   │   │   └── servers_test.go
│   │   └── doc.go
├── commands/
│   ├── setup.md                   # /sshgate:setup
│   ├── add.md                     # /sshgate:add
│   ├── status.md                  # /sshgate:status
│   ├── revoke.md                  # /sshgate:revoke
│   └── run.md                     # /sshgate:run (rare; Claude usually calls the tool directly)
├── skills/
│   └── debugging-remote-servers/
│       └── SKILL.md
├── scripts/
│   ├── install.sh                 # Called by /sshgate:setup; creates velsigner user, writes systemd unit
│   ├── uninstall.sh
│   └── create-velsigner-user.sh
├── tests/
│   ├── integration/
│   │   ├── docker-compose.yml      # linuxserver/openssh-server target
│   │   ├── e2e_test.go             # Build-time: compose up, deploy velgate, run end-to-end
│   │   └── helpers_test.go
│   └── testdata/
│       └── classifier-corpus.txt   # ~200 commands, one per line, prefixed READ / WRITE / UNKNOWN
└── docs/
    ├── specs/2026-05-19-sshgate-design.md       # The design (already written)
    ├── plans/2026-05-19-sshgate-v1-implementation.md  # This file
    ├── install-step-by-step.md                   # For Karthi when he wakes up
    ├── audits/                                    # Populated by review/audit gates
    └── decisions/                                 # Material in-flight tradeoffs
```

**Why this decomposition:**
- `common/` has zero inbound deps — both velgate and velsigner+MCP import it; classifier + payload format live here so there is exactly one source of truth.
- `velgate/` is a single tiny binary; flat structure.
- `velsigner/` has a `backend/` sub-package because the Backend interface is the swap-point for v2; isolating it makes the interface obvious.
- `mcp/` has sub-packages by concern (tools, ssh, sign, registry) because the MCP entry point is small but the components are independent; flat would force one giant file.
- `tests/integration/` is separate from per-package `*_test.go` because integration tests need Docker and a longer setup; CI splits the two.
- `scripts/` holds shell scripts called from the plugin (setup, uninstall) — Karthi's existing pattern with c3.

---

## Subagent dispatch protocol (read once)

Each task below is one subagent dispatch.

**Prompt template for every dispatch:**

> You are implementing one task from the SSHGate v1 plan. Read first:
> 1. `docs/specs/2026-05-19-sshgate-design.md` — section(s): [pointer]
> 2. `docs/plans/2026-05-19-sshgate-v1-implementation.md` — your task: [task ID]
> 3. `~/arogara/code-review/guidelines/{general,go,daemon,plugin}.md` — apply these standards.
>
> Apply strict TDD: failing test → red → minimal code → green → refactor → commit with conventional-commit message that names the task ID. Run `go test -race ./<package>/...` and `go vet ./<package>/...` before claiming completion. If you discover a design issue, STOP and report — don't paper over.
>
> Report back in ≤200 words: what shipped, test counts, commit SHA, any deviations from the plan with rationale.

**Verification between tasks (main session, lightweight):**
- `git log --oneline -3` — confirm the commit landed
- `go test -race ./src/<package>/...` — re-run from main to confirm green
- `git diff <prev>..HEAD --stat` — sanity-check the diff scope
- If anything is off, dispatch a follow-up subagent to fix specifically that issue; don't fix in main.

**Parallelism:** tasks within a phase are sequential by default unless explicitly marked `[parallel]`. Phase 1's `common/`, Phase 1's velgate, and Phase 1's velsigner can be parallelized once common/ ships.

---

## Phase 0 — Repository scaffolding

Goal: empty repo → buildable empty Go module + plugin manifest. No functionality yet.

### Task 0.1: Initialize Go module and base files

**Files:**
- Create: `SSHGate/go.mod`, `SSHGate/.gitignore`, `SSHGate/README.md`, `SSHGate/Makefile`, `SSHGate/.claude-plugin/plugin.json`, `SSHGate/.mcp.json`

- [ ] **Step 1:** `cd SSHGate && go mod init github.com/karthikeyan5/sshgate`
- [ ] **Step 2:** Write `.gitignore`: `bin/`, `*.tmp`, `/tmp/`, `**/.DS_Store`, `audits/*.log`, `docs/audits/*-report.md`
- [ ] **Step 3:** Write `README.md` — stub with one-liner from spec, install pointer to `docs/install-step-by-step.md`, link to spec
- [ ] **Step 4:** Write `Makefile` with targets: `build` (`go build ./cmd/...`), `test` (`go test -race ./...`), `vet` (`go vet ./...`), `clean` (`rm -rf bin/`), `velgate-linux` (cross-compile for remote deploy)
- [ ] **Step 5:** Write `.claude-plugin/plugin.json` per plugin.md §1: name `sshgate`, semver `0.1.0`, description ≤120 chars, keywords array
- [ ] **Step 6:** Write `.mcp.json` referencing `${CLAUDE_PLUGIN_ROOT}/bin/sshgate-mcp`
- [ ] **Step 7:** Verify: `go build ./... && go vet ./...` — both clean (no Go files yet, should be no-op success)
- [ ] **Step 8:** Commit: `chore: scaffold SSHGate plugin (task 0.1)`

### Task 0.2: Set up integration-test Docker target

**Files:**
- Create: `tests/integration/docker-compose.yml`, `tests/integration/README.md`

- [ ] **Step 1:** `docker-compose.yml` with `linuxserver/openssh-server` service:
  ```yaml
  services:
    sshd:
      image: linuxserver/openssh-server:latest
      environment:
        - PUID=1000
        - PGID=1000
        - USER_NAME=testuser
        - PUBLIC_KEY_FILE=/keys/sshgate_ed25519.pub
      volumes:
        - ./fixtures/keys:/keys:ro
      ports:
        - "2222:2222"
  ```
- [ ] **Step 2:** Verify `docker compose -f tests/integration/docker-compose.yml config` parses cleanly
- [ ] **Step 3:** Document in `README.md`: `cd tests/integration && docker compose up -d` boots the test server
- [ ] **Step 4:** Commit: `test: add Docker openssh-server target for integration (task 0.2)`

---

## Phase 1 — Cryptographic loop end-to-end (reads work, writes stub-denied)

Goal: end-to-end SSH→velgate→exec for read commands. velsigner uses StubBackend (always denies); MCP wires SSH client + sign client + classifier. By end of phase: `sshgate.run("test-server", "df -h")` returns disk usage; `sshgate.run("test-server", "rm /tmp/x")` returns "denied by operator."

### Task 1.1: common/classifier — read/write command classification

**Spec:** §"Command Classification"
**Files:** `src/common/classifier.go`, `src/common/classifier_test.go`, `src/common/doc.go`, `tests/testdata/classifier-corpus.txt`

**Interface contract:**
```go
package common

type Kind int

const (
    KindUnknown Kind = iota
    KindRead
    KindWrite
)

// Classify returns the kind of the command string. Pipes, redirects, sudo,
// command substitution, and unknown binaries all default to KindWrite per
// the spec's fail-safe rule.
func Classify(cmd string) Kind
```

- [ ] **Step 1:** Write `classifier-corpus.txt` with ~200 lines, each `READ\t<cmd>` or `WRITE\t<cmd>`. Cover read list (cat, ls, grep, ps, journalctl status, docker ps, …) and write list (rm, systemctl restart, apt install, sudo …, |, &&, >, etc.) verbatim from spec §"Command Classification."
- [ ] **Step 2:** Write `classifier_test.go` table-driven from corpus; each row is `t.Run(cmd, …)`. Failing on first run.
- [ ] **Step 3:** Verify RED: `go test ./src/common -run TestClassify` fails.
- [ ] **Step 4:** Implement `Classify` with: tokenize at top level (respecting quotes), check head against read-allowlist, then check for pipes/redirects/`&&`/`;`/`||` → write if any segment is write, sudo prefix → write, unknown bin → write.
- [ ] **Step 5:** Verify GREEN: corpus passes 100%.
- [ ] **Step 6:** Write `doc.go` package comment (per go.md §5.3) — explains the classifier's role, fail-safe-as-write invariant.
- [ ] **Step 7:** Commit: `feat(common): read/write classifier with spec corpus (task 1.1)`

### Task 1.2: common/payload — VELGATE_SIG payload format

**Spec:** §"Signature Scheme"
**Files:** `src/common/payload.go`, `src/common/payload_test.go`

**Interface contract:**
```go
// SigPayload is what's signed; round-trips through Encode/Decode as the
// VELGATE_SIG:<sig>:<payload-b64> wire format defined in the spec.
type SigPayload struct {
    Cmd   string `json:"cmd"`
    TS    int64  `json:"ts"`
    Exp   int64  `json:"exp"`
    Nonce string `json:"nonce"`
}

// EncodeSigned returns "VELGATE_SIG:<sigB64>:<payloadB64>"
func EncodeSigned(sig []byte, payload SigPayload) (string, error)

// DecodeSigned splits the wire format back into (sig, payload, error)
func DecodeSigned(s string) (sig []byte, payload SigPayload, err error)

// IsSigned reports whether s starts with the VELGATE_SIG: prefix
func IsSigned(s string) bool
```

- [ ] **Step 1:** Write `payload_test.go` covering: round-trip, IsSigned true/false, decode bad prefix, decode bad base64, decode bad JSON, decode truncated.
- [ ] **Step 2:** Verify RED.
- [ ] **Step 3:** Implement payload using stdlib `encoding/json` + `encoding/base64`. Use URL-safe base64 (no padding) for SSH-command safety.
- [ ] **Step 4:** Verify GREEN.
- [ ] **Step 5:** Commit: `feat(common): SigPayload wire format (task 1.2)`

### Task 1.3 [parallel with 1.4, 1.5]: velgate binary

**Spec:** §"Command Classification" §"Signature Scheme" §"Transport"
**Files:** `src/velgate/cmd/velgate/main.go`, `src/velgate/verify.go`, `src/velgate/verify_test.go`, `src/velgate/executor.go`, `src/velgate/executor_test.go`, `src/velgate/doc.go`

**Interface contracts:**
```go
// In src/velgate/verify.go:
// VerifySigned checks the VELGATE_SIG prefix matches the inner cmd,
// uses pubkey to verify the signature, checks now < exp, exp-ts < 300.
// Returns the inner cmd string for execution, or an error.
func VerifySigned(line string, pubkey ed25519.PublicKey, now time.Time) (innerCmd string, err error)

// In src/velgate/executor.go:
// Exec runs cmd via "/bin/sh -c cmd", piping stdout/stderr to the caller's
// stdout/stderr. Returns the exit code. Forwards SIGTERM if received.
func Exec(ctx context.Context, cmd string) (exitCode int, err error)
```

**main.go logic (paraphrasing — subagent expands):**
1. Read `SSH_ORIGINAL_COMMAND` from env. If empty → exit 0 with "VELGATE_OK" (the test-setup probe per spec §"Installation" step 6).
2. Load `~/.velgate/velgate.pub` (mode check: 0644 expected, refuse if more permissive).
3. If `IsSigned(cmd)`: `VerifySigned`, get inner cmd. Else inner cmd = the raw cmd.
4. `Classify(innerCmd)`:
   - Read → `Exec(innerCmd)`
   - Write → only if it came from a verified signature → `Exec(innerCmd)`; else log to stderr, exit 1 with "denied: write requires signature"
5. If `innerCmd == "VELGATE_REVOKE"` and signed → run revoke (defer to phase 4); for phase 1 stub it.
6. If `innerCmd == "VELGATE_UPDATE …"` and signed → deferred to v1.1; stub.

- [ ] **Step 1:** Write `verify_test.go` with cases: valid signed read, valid signed write, expired sig, exp-ts too large, tampered cmd, bad signature bytes, no prefix (raw cmd passthrough).
- [ ] **Step 2:** RED.
- [ ] **Step 3:** Implement `verify.go` using `crypto/ed25519.Verify` + `common.DecodeSigned`.
- [ ] **Step 4:** GREEN.
- [ ] **Step 5:** Write `executor_test.go` with cases: simple echo returns 0 and "hello\n", failing `false` returns 1, sleep + ctx-cancel returns non-zero, large stdout streams (don't buffer).
- [ ] **Step 6:** RED → implement → GREEN.
- [ ] **Step 7:** Wire `main.go` per logic above. Stderr is the operator channel; stdout is the executed command's stdout (per daemon.md §6.3 and cli.md §3 — though velgate is sub-binary, the stdio discipline applies).
- [ ] **Step 8:** Build + smoke: `go build -o /tmp/velgate ./src/velgate/cmd/velgate && SSH_ORIGINAL_COMMAND="ls /" /tmp/velgate` lists root.
- [ ] **Step 9:** Run `go test -race ./src/velgate/...` clean.
- [ ] **Step 10:** Commit: `feat(velgate): SSH command gate with read/write classification and Ed25519 verify (task 1.3)`

### Task 1.4 [parallel with 1.3, 1.5]: velsigner — keystore, socket, daemon core (StubBackend phase)

**Spec:** §"Components — velsigner daemon"
**Files:** `src/velsigner/keystore.go`, `keystore_test.go`, `src/velsigner/socket.go`, `socket_test.go`, `src/velsigner/audit.go`, `audit_test.go`, `src/velsigner/daemon.go`, `daemon_test.go`, `src/velsigner/backend/backend.go`, `backend/stub.go`, `backend/stub_test.go`, `backend/mock.go`, `backend/doc.go`, `src/velsigner/cmd/velsigner/main.go`, `src/velsigner/doc.go`

**Interface contracts:**
```go
// src/velsigner/backend/backend.go
package backend

type ApprovalRequest struct {
    RequestID string
    Commands  []CommandReq
    Submitted time.Time
}
type CommandReq struct {
    Server string
    Cmd    string
    TTLSec int64
}
type Result struct {
    Status     ResultStatus  // Approved | Denied | Timeout
    ApprovedBy string         // for audit; populated by Telegram backend
}
type ResultStatus int
const (
    StatusApproved ResultStatus = iota
    StatusDenied
    StatusTimeout
)
type Backend interface {
    // Request submits the approval request and returns a channel that yields
    // exactly one Result (or is closed on error). The channel must be readable
    // even if ctx is canceled — implementations send StatusTimeout in that case.
    Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error)
}

// src/velsigner/daemon.go
type Daemon struct {
    Key     ed25519.PrivateKey
    Backend backend.Backend
    Audit   *AuditLog
}
// HandleSignRequest reads one JSON request from r, sends approval via
// backend, signs each command on approval, writes the response to w.
func (d *Daemon) HandleSignRequest(ctx context.Context, r io.Reader, w io.Writer) error
```

**Socket protocol (JSON-Lines):**
- Request: `{"kind":"sign","request_id":"r_xxx","commands":[{"server":"a","cmd":"b","ttl_seconds":60}]}\n`
- Response: `{"request_id":"r_xxx","status":"approved","signatures":[{"cmd":"b","sig":"VELGATE_SIG:..."}]}\n` or `{"request_id":"r_xxx","status":"denied"}\n` or `{"request_id":"r_xxx","status":"timeout"}\n`

**keystore.go contract:**
```go
// LoadKey reads an Ed25519 private key from a binary file. Refuses to load
// if the file mode is more permissive than 0600. Returns an error wrapped
// with %w on every failure.
func LoadKey(path string) (ed25519.PrivateKey, error)

// GenerateKeyPair generates a new Ed25519 keypair and writes the private
// to privPath (mode 0600) and public to pubPath (mode 0644). Refuses to
// overwrite existing files.
func GenerateKeyPair(privPath, pubPath string) error
```

**Audit log format (daemon.md §5):**
- JSON-Lines, one record per request: `{"ts":"...","request_id":"...","status":"...","commands":[...],"approved_by":"..."}`
- fsync after each line (daemon.md §5.1).
- Lives at `/var/lib/velsigner/log/approvals.log` in production; configurable.

**main.go logic:**
1. Parse `--config` flag (default `/etc/velsigner/config.toml`).
2. Validate: running as the `velsigner` user; refuse to start otherwise (per daemon.md §1.2 fail-fast).
3. Acquire `flock` on `/run/velsigner/sock.lock` (daemon.md §3.1 — singleton). Fail fast if held.
4. Load private key via `LoadKey`. Fail fast if perms wrong.
5. Build backend per config (`stub` for phase 1, `telegram` for phase 2).
6. Open audit log (append mode).
7. Bind Unix socket at `/run/velsigner/sock` mode 0660, group `velsigner` (so karthi user in `velsigner` group can connect).
8. Run accept loop with per-conn timeouts (daemon.md §4.2). Stop on SIGTERM/SIGINT — drain in-flight (daemon.md §1.3).

- [ ] **Step 1:** Write `backend/backend.go` (interface only) and `backend/doc.go`. No tests yet — interface.
- [ ] **Step 2:** Write `backend/stub.go` (StubBackend.Request always returns Denied immediately) and `backend/stub_test.go`. TDD as usual.
- [ ] **Step 3:** Write `backend/mock.go` (MockBackend lets test code call .Approve(reqID) / .Deny(reqID) / .Timeout(reqID) to control results — used heavily by daemon and integration tests). No tests for the helper itself; it's a test fixture.
- [ ] **Step 4:** Write `keystore_test.go` cases: load valid, wrong mode 0644 refused, missing file errored, malformed key errored, generate creates files with right modes, generate refuses overwrite.
- [ ] **Step 5:** RED → implement `keystore.go` → GREEN.
- [ ] **Step 6:** Write `audit_test.go`: append + reopen + parse, fsync survives kill, malformed line is reported but doesn't crash.
- [ ] **Step 7:** RED → implement `audit.go` → GREEN.
- [ ] **Step 8:** Write `socket_test.go`: bind + accept + roundtrip JSON line, multiple sequential clients, concurrent clients, socket file mode is 0660.
- [ ] **Step 9:** RED → implement `socket.go` → GREEN.
- [ ] **Step 10:** Write `daemon_test.go` with MockBackend: full sign request → approve → response carries signatures verifiable by velgate; deny path; timeout path; concurrent requests don't cross results (one channel per request_id).
- [ ] **Step 11:** RED → implement `daemon.go` → GREEN.
- [ ] **Step 12:** Wire `cmd/velsigner/main.go` per logic above. Use `signal.NotifyContext` for graceful shutdown (daemon.md §2.6).
- [ ] **Step 13:** `go test -race ./src/velsigner/...` clean.
- [ ] **Step 14:** Add `goleak.VerifyTestMain` to `velsigner/daemon_test.go` (go.md §4.11).
- [ ] **Step 15:** Commit: `feat(velsigner): daemon, socket, keystore, audit, stub backend (task 1.4)`

### Task 1.5 [parallel with 1.3, 1.4]: MCP — SSH client, sign client, run tool, server scaffold

**Spec:** §"Components — SSHGate MCP server"
**Files:** `src/mcp/ssh/client.go`, `client_test.go`, `src/mcp/sign/client.go`, `client_test.go`, `src/mcp/tools/run.go`, `run_test.go`, `src/mcp/registry/servers.go`, `servers_test.go`, `src/mcp/server.go`, `server_test.go`, `src/mcp/cmd/sshgate-mcp/main.go`, `src/mcp/doc.go`

**Interface contracts:**
```go
// src/mcp/ssh/client.go
type Client struct {
    KeyPath        string         // ~/.config/sshgate/ssh/sshgate_ed25519
    KnownHostsPath string         // ~/.config/sshgate/known_hosts
    Timeout        time.Duration  // dial+exec total budget
}
// Run dials sshUser@sshHost:port using KeyPath, executes cmd (passed as the
// single command in the SSH session), and returns combined stdout, stderr,
// and the remote exit code.
func (c *Client) Run(ctx context.Context, host, user string, port int, cmd string) (stdout, stderr []byte, exit int, err error)

// src/mcp/sign/client.go
type Client struct { SocketPath string }
// Sign sends an approval request to velsigner and returns the signed wire
// strings on approval, or an error matching one of:
//   - ErrDenied      (operator denied)
//   - ErrTimeout     (no response within ttl)
//   - ErrUnreachable (socket missing or refused)
func (c *Client) Sign(ctx context.Context, reqID string, cmds []signreq.Cmd) ([]string, error)

// src/mcp/registry/servers.go
type Servers struct {
    Path string  // ~/.config/sshgate/servers.json
    mu   sync.Mutex
    data map[string]Entry
}
type Entry struct { Host string; Port int; User string; AddedAt time.Time }
func (s *Servers) Load() error
func (s *Servers) Get(alias string) (Entry, bool)
func (s *Servers) AddAtomic(alias string, e Entry) error  // tmp+rename+fsync per daemon.md §5.1
```

**run tool semantics:**
- Input: `{ alias: "prod-db", command: "df -h" }`
- Local classify:
  - Read → SSH directly using the registered server's host/port/user with the dedicated key; return output.
  - Write → call `sign.Client.Sign` for a single-cmd request; on approval, SSH with the signed `VELGATE_SIG:...:... <inner-cmd>` prefix; return output. On denial/timeout → return a structured MCP tool error with the reason.

**MCP server bootstrap (per plugin.md §3):**
- Use `github.com/modelcontextprotocol/go-sdk/mcp` (v1.6+).
- `serverInfo.name` MUST be exactly `"sshgate"` (matches the .mcp.json key per plugin.md §3.1).
- Tools registered with description + JSON schema (plugin.md §3.6).
- All logs to stderr; stdout reserved for JSON-RPC frames (plugin.md §3.2).
- Treat stdin EOF as clean shutdown (plugin.md §3.8).

- [ ] **Step 1:** Write `registry/servers_test.go`: load empty, add, save+reload, atomic write doesn't leave partials on crash (simulated by killing mid-write).
- [ ] **Step 2:** RED → implement `registry/servers.go` → GREEN.
- [ ] **Step 3:** Write `ssh/client_test.go` against the Docker openssh-server: dial, run `echo hello`, captures stdout; bad host fails with err; bad key fails with err; cancelled ctx aborts.
- [ ] **Step 4:** RED → implement `ssh/client.go` using `golang.org/x/crypto/ssh`. Host-key check uses a per-server fingerprint stored in `known_hosts`-style file; for v1, on first connection accept-and-pin (TOFU); subsequent mismatches refuse.
- [ ] **Step 5:** GREEN.
- [ ] **Step 6:** Write `sign/client_test.go` against an in-process fake velsigner socket (use `net.Pipe()` or a real Unix socket in `t.TempDir()`): approval path, denial path, timeout path, unreachable path.
- [ ] **Step 7:** RED → implement `sign/client.go` → GREEN.
- [ ] **Step 8:** Write `tools/run_test.go`: read command goes direct (no sign call); write command calls sign; sign success → SSH with signed prefix; sign denial → structured error result.
- [ ] **Step 9:** RED → implement `tools/run.go` → GREEN.
- [ ] **Step 10:** Write `server_test.go`: initialize handshake against go-sdk's test client; tools/list shape; run tool dispatchable.
- [ ] **Step 11:** RED → implement `server.go` → GREEN.
- [ ] **Step 12:** Wire `cmd/sshgate-mcp/main.go` — stdio transport, signal handling, EOF-on-stdin clean shutdown.
- [ ] **Step 13:** `go test -race ./src/mcp/...` clean.
- [ ] **Step 14:** Commit: `feat(mcp): server scaffold + run tool with SSH, sign, registry (task 1.5)`

### Task 1.6: Phase-1 integration test (e2e)

**Files:** `tests/integration/e2e_test.go`, `tests/integration/helpers_test.go`, `tests/integration/fixtures/keys/` (gitignored — generated by test)

**Test scenarios (each is a separate `t.Run` subtest):**
1. **Read path** — boot Docker sshd, generate fresh sshgate_ed25519 key, generate fresh velgate signing key, copy velgate binary into the container's user home, install authorized_keys with `command="..."` forcing, start velsigner with StubBackend in a goroutine, start MCP, call `sshgate.run("test", "df -h")` → expect 0 exit + non-empty stdout.
2. **Write denied** — same setup; call `sshgate.run("test", "rm /tmp/x")` → expect tool error with "denied by operator" (StubBackend denies).
3. **Direct SSH bypass attempt** — try to SSH into the container WITH the dedicated key but WITHOUT the velgate signature prefix → confirm classifier on the remote denies writes.
4. **goleak verify** — no goroutine leaks across the test run.

- [ ] **Step 1:** Write `helpers_test.go`: `bootContainer(t)`, `stopContainer(t)`, `generateKeys(t)`, `installAuthorizedKeys(t)`.
- [ ] **Step 2:** Write `e2e_test.go` per scenarios.
- [ ] **Step 3:** Run: `cd tests/integration && docker compose up -d && go test -race ./... -tags=integration -timeout=90s`. All four scenarios pass.
- [ ] **Step 4:** Commit: `test(integration): phase-1 e2e — read works, writes denied (task 1.6)`

**Phase 1 lock criteria:**
- All package tests green with `-race`.
- Integration test green.
- `go vet ./...` clean.
- `git log --oneline` shows tasks 0.1, 0.2, 1.1–1.6 in order.

---

## Phase 2 — Real Telegram approval + bulk approval

Goal: replace StubBackend with TelegramBackend; add `sshgate.run_batch`. By end of phase: a write triggers a Telegram DM to Karthi; tap Approve → cmd runs; tap Deny → cmd doesn't run; bulk = one tap for N cmds.

### Task 2.1: TelegramBackend — request lifecycle, callback handling

**Spec:** §"Components — velsigner-bot (Telegram bot, DM-only)"
**Files:** `src/velsigner/backend/telegram.go`, `telegram_test.go`

**Interface implementation:**
```go
type TelegramBackend struct {
    Bot          *tgbotapi.BotAPI  // wraps the bot token
    AllowedUserID int64             // 12345678
    ChatID       int64              // captured on first /start
    ChatStore    ChatStore          // persists ChatID across restarts
    pending      sync.Map           // requestID → chan Result
}

// Request implements backend.Backend. Posts approval message with inline
// keyboard, registers pending channel, returns the channel. Callback handler
// (running in a goroutine started by NewTelegramBackend) resolves the channel.
func (t *TelegramBackend) Request(ctx context.Context, req backend.ApprovalRequest) (<-chan backend.Result, error)

// Run starts the Telegram polling loop in a goroutine. Returns immediately.
// Stop the loop by cancelling the ctx passed to Run.
func (t *TelegramBackend) Run(ctx context.Context) error
```

**Callback `data` format:** `approve:r_a1b2c3` or `deny:r_a1b2c3`. Callback `from.id` MUST match `AllowedUserID`; reject with "not authorized" toast otherwise. Request must be in `pending` map; reject "expired or already resolved" otherwise.

**Approval message text:** see spec §"velsigner-bot — Approval message shape".

- [ ] **Step 1:** Write `telegram_test.go` using a `httptest.NewServer` that mimics Telegram's bot API endpoints (`/sendMessage`, `/answerCallbackQuery`, `/getUpdates`). Override `tgbotapi.BotAPI.Endpoint`.
  - Scenario: request → message posted → simulated callback approve → result Approved
  - Scenario: callback with wrong from.id → ignored, request stays pending
  - Scenario: callback with unknown request_id → answer-callback "expired"; no result change
  - Scenario: ctx cancel during pending → Result{Timeout}
- [ ] **Step 2:** RED → implement → GREEN.
- [ ] **Step 3:** Goroutine cleanup: ensure cancelling Run drains and closes properly; verify with `goleak`.
- [ ] **Step 4:** Commit: `feat(velsigner/backend): TelegramBackend with inline-keyboard approvals (task 2.1)`

### Task 2.2: ChatStore — persistent capture of Karthi's DM chat_id

**Files:** `src/velsigner/backend/chatstore.go`, `chatstore_test.go`

```go
type ChatStore interface {
    Load() (chatID int64, ok bool, err error)
    Save(chatID int64) error
}
type FileChatStore struct { Path string }  // JSON file at /var/lib/velsigner/config/peer.json
```

On first `/start` to the bot, TelegramBackend captures `msg.Chat.ID` and `msg.From.ID`, verifies `from.id == AllowedUserID`, and Save()s. From then on, every DM goes to the saved chat_id.

- [ ] **Step 1:** Write `chatstore_test.go`: empty file load → ok=false; save then load roundtrips; mode 0600 enforced; atomic write.
- [ ] **Step 2:** RED → implement → GREEN.
- [ ] **Step 3:** Update TelegramBackend.Run to wait for /start before accepting requests; reject Request() with `ErrNoChat` if ChatStore empty.
- [ ] **Step 4:** Commit: `feat(velsigner/backend): ChatStore for DM capture (task 2.2)`

### Task 2.3: sshgate.run_batch tool — bulk approval

**Files:** `src/mcp/tools/run_batch.go`, `run_batch_test.go`

**Tool semantics:**
- Input: `{ alias: "...", commands: ["cmd1","cmd2",...], stop_on_error: bool }`
- Classify each command locally. If ALL reads → execute directly, no approval. If ANY write → single sign request with all N commands → on approval, run them in order; on denial, run none.
- `stop_on_error: true` (default) aborts the sequence at first non-zero exit; `false` runs all regardless.

- [ ] **Step 1:** Write `run_batch_test.go`: all-reads direct, mixed bulk-approve, all-writes bulk-approve, denial blocks all, stop_on_error semantics.
- [ ] **Step 2:** RED → implement → GREEN.
- [ ] **Step 3:** Commit: `feat(mcp/tools): run_batch with bulk approval (task 2.3)`

### Task 2.4: /sshgate:setup slash command + install script

**Files:** `commands/setup.md`, `scripts/install.sh`, `scripts/create-velsigner-user.sh`, `docs/install-step-by-step.md`

**Setup command semantics (per plugin.md §4):**
- Body is a prompt to Claude: walk Karthi through these steps interactively.
- Steps it walks:
  1. Probe Go toolchain (`go version`); error with install instructions if missing.
  2. `go build ./cmd/...` to produce `bin/sshgate-mcp`, `bin/velsigner`, `bin/velgate-linux-amd64`.
  3. Prompt Karthi to run `sudo scripts/create-velsigner-user.sh` (one-time, interactive).
  4. Generate keys (`bin/velsigner --init`) — writes `/var/lib/velsigner/keys/velgate.{key,pub}` (mode 0600/0644) and `~/.config/sshgate/ssh/sshgate_ed25519` (mode 0600). Refuse to overwrite existing.
  5. Prompt Karthi: paste your @BotFather bot token. Save to `/var/lib/velsigner/tokens/telegram.token`.
  6. Install systemd unit (`scripts/install.sh`) — `User=velsigner`, `ExecStart=/usr/local/bin/velsigner`, `Restart=always`, `RestartSec=10`.
  7. Start velsigner: `sudo systemctl enable --now velsigner`.
  8. Prompt Karthi: open Telegram, find your bot, send `/start`. Wait for ChatStore to populate (poll its file). Confirm "captured chat_id".
- All MUST gracefully handle re-runs (idempotency per daemon.md §1.5).

- [ ] **Step 1:** Write `docs/install-step-by-step.md` — the user-facing version Karthi follows when he wakes up.
- [ ] **Step 2:** Write `scripts/create-velsigner-user.sh` — `useradd -r -s /usr/sbin/nologin velsigner && usermod -a -G velsigner $SUDO_USER && mkdir -p /var/lib/velsigner/{keys,tokens,config,log} && chown -R velsigner:velsigner /var/lib/velsigner && chmod 0750 /var/lib/velsigner`.
- [ ] **Step 3:** Write `scripts/install.sh` — copies binaries to `/usr/local/bin/`, writes systemd unit at `/etc/systemd/system/velsigner.service`, `systemctl daemon-reload`.
- [ ] **Step 4:** Write `commands/setup.md` — slash command body prompts Claude to orchestrate.
- [ ] **Step 5:** Test the setup script inside a Docker container running Ubuntu (since live execution on Karthi's box needs his sudo). Verify idempotency.
- [ ] **Step 6:** Commit: `feat(setup): /sshgate:setup command + install scripts (task 2.4)`

### Task 2.5: Phase-2 integration test (real-ish Telegram)

**Files:** `tests/integration/phase2_test.go`

Uses a fake Telegram server (httptest) and asserts the full path: MCP receives `run_batch` → calls sign client → velsigner (with TelegramBackend pointed at fake Telegram) → fake Telegram delivers a programmatic "approve" callback → velsigner signs → MCP SSH-executes → outputs collected.

- [ ] **Step 1:** Write `phase2_test.go` with the fake Telegram + Docker sshd.
- [ ] **Step 2:** Run + verify green.
- [ ] **Step 3:** Commit: `test(integration): phase-2 e2e with fake Telegram + bulk approval (task 2.5)`

**Phase 2 lock criteria:**
- All tests green.
- Manual readiness: install-step-by-step.md is testable when Karthi wakes (no missing instructions).

---

## Phase 3 — Auto-setup flow

Goal: `/sshgate:add prod-db karthi@example.com` (or via tool call) Just Works.

### Task 3.1: sshgate.add_server tool

**Spec:** §"Installation (Auto-Setup)" of VelGate spec carried into SSHGate
**Files:** `src/mcp/tools/add_server.go`, `add_server_test.go`

**Logic:**
1. Validate inputs (alias regex `[a-z][a-z0-9-]{1,30}`, user@host parsing, port default 22).
2. Read or generate `~/.config/sshgate/ssh/sshgate_ed25519{,.pub}`.
3. Connect to the remote using Karthi's normal SSH key (interactive — assumes `~/.ssh/id_ed25519` works, or uses ssh-agent). This is the bootstrap leg; once velgate is installed, future connections use the dedicated key.
4. `mkdir -p ~/.velgate && chmod 700 ~/.velgate`
5. SCP-equivalent: upload `bin/velgate-linux-amd64` → `~/.velgate/velgate`, `chmod 755`.
6. Upload `velgate.pub` (the signing public key) → `~/.velgate/velgate.pub`, `chmod 644`.
7. Rewrite `~/.ssh/authorized_keys`: locate any existing line for the SSHGate pubkey (by comment `sshgate@laptop`), replace with the restricted line `command="~/.velgate/velgate",no-port-forwarding,no-X11-forwarding,no-agent-forwarding <key>`. If no existing line, append.
8. Verify by reconnecting with the SSHGate key + sending `echo VELGATE_OK` → expect that string back.
9. On success, `registry.Servers.AddAtomic(alias, ...)`.
10. On any failure: rollback (delete uploaded files, restore authorized_keys from backup made in step 7).

- [ ] **Step 1:** Write `add_server_test.go` against Docker sshd: success path; rollback on velgate copy fail; rollback on authorized_keys verify fail; idempotency (re-add same alias should NOT duplicate authorized_keys lines).
- [ ] **Step 2:** RED → implement → GREEN.
- [ ] **Step 3:** Commit: `feat(mcp/tools): add_server auto-setup with rollback (task 3.1)`

### Task 3.2: velgate cross-compile target + Makefile

- [ ] **Step 1:** Makefile target `velgate-linux-amd64`: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o bin/velgate-linux-amd64 ./src/velgate/cmd/velgate`
- [ ] **Step 2:** Verify the binary is statically linked: `file bin/velgate-linux-amd64` shows "statically linked" / "no shared libs".
- [ ] **Step 3:** Add to `make build` umbrella target.
- [ ] **Step 4:** Commit: `build: cross-compile velgate for linux/amd64 (task 3.2)`

### Task 3.3: /sshgate:add command

**Files:** `commands/add.md`

Slash command body prompts Claude to call `sshgate.add_server` with provided args.

- [ ] **Step 1:** Write `commands/add.md` per plugin.md §4. Frontmatter `argument-hint` describes `<alias> <user@host>[:port]`.
- [ ] **Step 2:** Commit: `feat(commands): /sshgate:add (task 3.3)`

### Task 3.4: Phase-3 integration test

**Files:** `tests/integration/phase3_test.go`

Boots a FRESH container (no authorized_keys preinstalled), calls `sshgate.add_server`, verifies the auto-setup worked end-to-end including reconnect and `echo VELGATE_OK`.

- [ ] **Step 1:** Test + verify.
- [ ] **Step 2:** Commit: `test(integration): phase-3 e2e auto-setup (task 3.4)`

**Phase 3 lock:** add_server is idempotent, has rollback, integration green.

---

## Phase 4 — Multi-server polish, revoke, skill, README

### Task 4.1: list_servers + status tools

**Files:** `src/mcp/tools/list_servers.go`, `list_servers_test.go`, `src/mcp/tools/status.go`, `status_test.go`

- [ ] **Step 1:** `list_servers` returns the registry as a list of `{alias, host, user, added_at, last_seen}`.
- [ ] **Step 2:** `status` returns a health object: `{velsigner_socket_reachable: bool, servers: [{alias, reachable: bool, ping_ms}]}`.
- [ ] **Step 3:** Tests + impl + commit per pattern.

### Task 4.2: revoke_server tool + VELGATE_REVOKE handler in velgate

**Files:** `src/mcp/tools/revoke_server.go`, `revoke_server_test.go`, update `src/velgate/cmd/velgate/main.go` to handle `VELGATE_REVOKE` (signed).

revoke flow:
1. MCP signs a `VELGATE_REVOKE` command via velsigner.
2. SSH into remote with signed command.
3. velgate handles VELGATE_REVOKE: deletes its own authorized_keys line, removes `~/.velgate/`, exits 0.
4. MCP removes alias from `registry.Servers`.

- [ ] **Step 1:** Write test + impl + commit.

### Task 4.3: /sshgate:status, /sshgate:revoke, /sshgate:run commands

**Files:** `commands/status.md`, `commands/revoke.md`, `commands/run.md`

- [ ] Slash commands per plugin.md §4.

### Task 4.4: Debugging-remote-servers skill

**Files:** `skills/debugging-remote-servers/SKILL.md`

Per plugin.md §5: third-person description; concrete trigger phrases ("This skill should be used when the user asks to debug a remote server"). Body is imperative; tells Claude: use sshgate.list_servers to enumerate, then sshgate.run for diagnostics (df, top, journalctl), then sshgate.run_batch for fixes.

- [ ] Write SKILL.md (≤1500 words); commit.

### Task 4.5: README polish + install-step-by-step finalization

- [ ] Update top-level README.md to be the marketplace-facing one-pager.
- [ ] Verify install-step-by-step.md walks Karthi through everything from `/plugin install` to first successful `sshgate.run`.
- [ ] Commit.

**Phase 4 lock:** v1 feature-complete. All slash commands present. Skill present.

---

## v1 completion — audits

### Audit 1: Code review

- [ ] **Dispatch a code-review subagent** with prompt: "Run a code review on `/home/karthi/arogara/SSHGate`. Apply guidelines from `~/arogara/code-review/guidelines/{general,go,cli,daemon,plugin}.md`. Use the severity rubric in `~/arogara/code-review/README.md`. Write report to `~/arogara/code-review/reports/sshgate-2026-05-19.md`. Cite findings with `file:line`. Don't fix anything; just report."
- [ ] Read the report.
- [ ] Per METHODOLOGY.md: triage each finding (real issue / wrong rule / mitigated). Dispatch fix subagents for confirmed BLOCKERs and MAJORs (one subagent per fix or per area). MINOR/NIT batch-sweep at the end.
- [ ] After fixes: re-run `go test -race ./...` + `go vet`. Update report with FIXED markers.
- [ ] Commit fixes referencing the report file.

### Audit 2: PII / secrets

- [ ] **Run** `~/arogara/pii-audit/scan.sh ~/arogara/SSHGate`.
- [ ] Report → `~/arogara/pii-audit/reports/sshgate-2026-05-19.md`.
- [ ] Address MUST-FIX findings. The Telegram user_id `12345678` is the primary risk — ensure it's only ever in env-loaded config, never in source.
- [ ] Update `pii-wordlist.txt` if SSHGate introduces project-specific terms.
- [ ] Commit.

### Audit 3: Security audit (self)

- [ ] Run each scenario from spec §"Review & audit gates → Security audit." Document outcomes in `docs/audits/security-2026-05-19.md`. Each scenario is either PASS (matches expected behavior) or FAIL (with remediation).
- [ ] Commit the audit doc.

**v1 done criteria:**
- All four phases locked.
- Three audits clean.
- `go test -race ./...` clean from cold.
- `git log --oneline` tells the story end to end.

---

## v1.1 cascade tasks (only if v1 done with time remaining)

- LLM command explainer: velsigner posts a short "what does each command do" message alongside the approval prompt. Implementation: optional `LLMExplainer` field on `TelegramBackend`; when set, call it before sending the message; include explanation as a separate line per command.
- macOS desktop support: add `darwin/amd64` and `darwin/arm64` targets in Makefile; ensure no Linux-specific syscalls in non-velgate code (velgate stays Linux-only since remotes are Linux); cross-build the MCP and velsigner; integration test runs in CI on macOS image (defer — we can't test without a Mac, but we can confirm build).
- Automated velsigner user provisioning: `scripts/install.sh` handles `useradd` automatically rather than asking Karthi to run a separate script. Idempotent: skip if user exists.
- Pipe/chain classification refinement: rather than "any pipe → write," tokenize the pipe chain and check each segment; if all are reads, the chain is a read. Same for `&&` / `||` / `;`.

---

## v2 cascade tasks (only if v1.1 done with time remaining)

Per spec §"v2 vision." Scaffold only — full v2 may not finish in this session.

- `src/velsigner-server/` directory + go module entry point.
- HTTP API: POST /v1/sign, GET /v1/poll/{id}, GET /v1/audit. Use stdlib `net/http`.
- Postgres or SQLite state store (decide based on deploy target).
- WebAuthn passkey login (`github.com/go-webauthn/webauthn`) + TOTP (`github.com/pquerna/otp`).
- HostedServerBackend implementation in velsigner so the swap is one-line.
- Web UI: minimal — static HTML + a couple of htmx endpoints. No React.
- Deploy script: `cmd/velsigner-server/deploy.sh` with documented VPS setup.

---

## Self-review checklist (run after writing this plan)

1. **Spec coverage** — every spec section maps to at least one task above. ✓ (threat model→audits, architecture→phases 1-4, components→tasks 1.3-1.5+2.1+3.1+4.1-2, ssh keys→tasks 1.5+3.1, approval flows→tasks 1.4+2.1, bulk approval→task 2.3, v2→cascade)
2. **Placeholder scan** — no "TBD" / "TODO" / "implement later" left. ✓
3. **Type consistency** — `Classify` returns `Kind` across 1.1, 1.3; `SigPayload` field names consistent across 1.2, 1.3, 1.4; `Backend` interface returns `<-chan Result` consistently across stub/mock/telegram. ✓
4. **Subagent self-sufficiency** — each task names files, contracts, test scenarios, commit message, and points to spec+code-review guidelines. ✓
