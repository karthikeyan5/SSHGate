# SSHGate output redactor — design proposal — 2026-05-19

> **SUPERSEDED by `secrets-redaction-architecture-2026-05-19.md`.** This proposal was written before the industry research (`secrets-redaction-research-2026-05-19.md`) was conducted. The unified architecture document integrates and revises the decisions below. Retained as historical record of the pre-research design.

## Summary

This proposal designs a secret-redaction layer for SSHGate's READ-path output. Today, when the agent runs a read command (`cat /etc/nginx/sites-enabled/foo`, `journalctl -u myapp`, `env`), the gate executes `/bin/sh -c <cmd>` and pipes stdout/stderr verbatim to the SSH client (`src/gate/executor.go`). The agent sees whatever the file or program emitted. This is the threat surface: an agent that can read can transitively exfiltrate any secret on disk that the operating user can read.

The proposal adds a **streaming scrubber inside the `gate` binary**, sitting between the child process's stdout/stderr and the SSH pipe back to the MCP. It ships with an embedded curated subset of gitleaks rules, a file-mode heuristic (`mode & 0o077 == 0` → treat content as opaque), and a per-host append-only `redactlist` for operator-specific patterns. Detected secrets are replaced with stable `[SSHGATE_REDACTED key=<8-hex>]` markers derived from a per-session HMAC key, so the agent can correlate occurrences within a session but cannot recover the plaintext and cannot bridge sessions.

What this proposal does **not** do:
- It does not catch every secret. High-entropy strings that match no rule slip through. False negatives are the headline risk.
- It does not redact the WRITE path. Writes are signed and human-approved at the laptop; redaction would obscure what Karthi just approved.
- It does not store secrets. The redactlist holds patterns and hash anchors, never plaintext.
- It does not protect against a malicious gate binary — the gate itself is the trust anchor; if it's compromised, redaction is moot.

---

## Operator's ideas — per-item evaluation

### 1. Pattern-match like gitleaks
**Pros:** Gitleaks rules are a community-maintained corpus of ~800 secret patterns (AWS, GitHub PATs, Stripe, JWT, private keys, etc.); reusing the format means we inherit that work plus future updates. The TOML rule format is small and well-documented.
**Cons:** Gitleaks is tuned for git history (mostly source files, not log/config output); false-positive rate on logs is higher. We can't import the gitleaks binary (~30MB Go binary) into the gate binary path without bloat.
**Verdict:** Keep (modified).
**Reasoning:** Embed a **curated subset** of gitleaks rules compiled into the gate binary as Go regex literals — not the full corpus, not the gitleaks runtime. The rule format is conceptually shared but the implementation is a small in-tree scanner.

### 2. Ask the user during install where they keep API keys
**Pros:** Per-installation seeding gives much higher precision than a generic ruleset; the operator knows their own config paths (`/etc/myapp/secrets.env`, `~/.aws/credentials`).
**Cons:** Asking at install time invites either skipping (user types Enter) or hallucinated answers (user can't remember every secret file). Interactive prompts inside `/sshgate:add` are awkward from a Claude Code session.
**Verdict:** Modify — combine with idea #7.
**Reasoning:** Don't ask "where are your keys" cold. Run service-detection (#7) first, present a concrete list ("we see nginx + postgres — these files will be opaque-mode"), and let Karthi accept or edit. Concrete > open-ended.

### 3. Maintain a key-value list of literal values + partial patterns
**Pros:** Highest-precision redaction — exact literal match never false-positives. Useful for known long-lived secrets (root DB password, master AWS key) that the operator wants guaranteed scrubbing for.
**Cons:** Storing literal secrets is the exact attack surface we want to avoid (#5 contradicts #3 in spirit). Also fragile to rotation.
**Verdict:** Modify — store HMAC of the literal, not the literal itself.
**Reasoning:** When the operator adds a literal, gate stores `hmac(session-independent-anchor-key, literal)`; at scan time, compute the same HMAC over rolling windows and match. Plaintext never lives on disk. (This is the right marriage of #3 and #5.)

### 4. Replace each secret with a stable identifier (numbered vs. hashed)
**Pros:** Stable IDs let the agent reason about "the same secret appeared in three places" without seeing the secret. Numbering is human-friendly; hashing avoids a counter file with state.
**Cons:** Sequential numbering requires a counter file (state, race conditions, persistence across sessions). Hashing is deterministic but cross-session correlation might itself be a leak vector (over many sessions the agent learns "key a1b2c3d4 is always the prod DB password").
**Verdict:** Keep — use **per-session HMAC**, truncated to 8 hex chars.
**Reasoning:** Per-session HMAC key gives in-session stability (the agent sees the same value for the same secret within one SSH connection / one session) but resets across sessions. No counter file, no persistent state. Cross-session correlation is intentionally lost.

### 5. Don't store the secret — hash on the fly
**Pros:** No vault-of-secrets to compromise; if the redactlist file leaks, attacker gets patterns and anchor-HMACs but no plaintext.
**Cons:** Cannot redact secrets we've never seen; the rule-based scanner (idea #1) has to carry the load.
**Verdict:** Keep, as a design principle.
**Reasoning:** Combined with #3 (HMAC anchors) and #1 (rules), we get coverage without storing plaintext. This is the right default.

### 6. Detect via file permissions (0600/0400)
**Pros:** Cheap, high-precision signal. If a file is mode 0600/0400, the *operator* has already declared it sensitive. Avoids byte-level scanning entirely for the "cat /etc/ssh/ssh_host_ed25519_key" case.
**Cons:** Only works for `cat <single-file>`-style commands; doesn't help with `journalctl`, `env`, `grep -r`, pipelines, or any program that synthesizes output. Many config files with secrets are 0644 (e.g. `/etc/nginx/conf.d/site.conf` containing a DB password).
**Verdict:** Keep — implement narrowly.
**Reasoning:** When the inbound command is `cat <path>` or `head <path>` and the file's mode has no group/other read bits, replace the entire output with `[SSHGATE_REDACTED_FILE path=<path> sha256=<8hex>]`. Narrow scope, big wins on private-key-file reads.

### 7. Service-aware first-run probe
**Pros:** "We see nginx + postgres + redis — install default redaction for their config files? [Y/n]" is excellent UX. Concrete and actionable, not abstract.
**Cons:** Service detection is fragile (`systemctl list-units` vs `docker ps` vs `rc-service` vs custom inits); maintaining service→files mappings is ongoing work.
**Verdict:** Keep — ship a small initial list (nginx, postgres, redis, mysql, docker, k8s, env-files), accept that it'll grow.
**Reasoning:** Even a small starter set covers 80% of common cases. Don't gold-plate; start with five services and let real usage reveal gaps.

### 8. Append-only list of patterns/literals
**Pros:** Prevents an agent that finds a way to write to the file from silently removing a pattern. `chattr +a` on Linux ext4/xfs makes the file kernel-enforced append-only.
**Cons:** `chattr +a` requires CAP_LINUX_IMMUTABLE (root) to set; only root can remove the attribute or rewrite the file. Means **gate** can't even rotate or compact the file. Some filesystems don't support it.
**Verdict:** Keep — with caveat.
**Reasoning:** Use `chattr +a` if supported (best-effort during `/sshgate:setup` via the install probe; the install needs root anyway to deploy gate's `command=` line). If unsupported, fall back to cryptographic enforcement: each line is a signed record `(timestamp, pattern, sig)`, gate refuses to load lines without a valid sig from the signer's key. Removal is detected because the file's commitment hash changes.

### 9. Updates require Telegram approval
**Pros:** Forces every redactlist update through the same human-in-the-loop SSHGate already has. Symmetric with how writes work. Cannot be silently weaponized by a compromised agent.
**Cons:** Adds friction. If the agent finds 30 new secrets in one session and wants to add patterns for all of them, that's 30 Telegram taps (or a bulk approval, which still requires care to ensure each pattern is sensible).
**Verdict:** Keep.
**Reasoning:** This is the right symmetric trust boundary. Treat redactlist updates as a signed `SSHGATE_REDACT_ADD <pattern>` command in the existing wire protocol — same signing path, same audit log, same bulk-approval mechanism for multi-pattern adds.

### 10. Common cases work out of the box
**Pros:** Zero-config wins are the most-used wins. If the operator has to read docs to get redaction working, most won't.
**Cons:** "Common cases" is a moving target; what's common in 2026 isn't what was common in 2024.
**Verdict:** Keep — ship a curated rule pack, version it.
**Reasoning:** Ship gitleaks-subset rules + file-mode heuristic enabled by default. Updates flow through `SSHGATE_UPDATE` (already-stubbed).

### 11. Standing instruction to flag unredacted keys
**Pros:** Self-improving system: every miss becomes a new pattern. Aligned with how humans actually deal with this — "oh, here's a new secret format we don't know yet."
**Cons:** Implementing this as a *skill* (Claude flags via prompt) is easy; making it reliable depends on the agent actually noticing and on the operator approving the pattern. The agent has already seen the secret at the point of detection — closing the barn door after the horse.
**Verdict:** Keep — as a skill/standing instruction.
**Reasoning:** Add a clause to `skills/debugging-remote-servers/SKILL.md`: "If you see anything that looks like a secret in command output, stop, report to the operator, and propose adding a redactlist pattern via `SSHGATE_REDACT_ADD`." It's defense-in-depth, not a primary control.

### 12. Warn the user this is not 100% foolproof
**Pros:** Karthi's "honesty above polish" preference. Lying about coverage breeds false confidence, which is worse than no redaction.
**Cons:** None.
**Verdict:** Keep — explicit warnings in the install prompt, README, and skill.
**Reasoning:** See §"UX warnings" below.

### 13. Hash whole files when sensitive
**Pros:** For private keys, certs, and `.env`-style files, byte-level redaction is pointless — the whole content is sensitive and the agent should get a single opaque marker. Simpler than partial scanning.
**Cons:** Only viable when we can identify the read is "whole-file" (i.e., `cat <single-file>`). Doesn't help with `grep` over the same file (returns partial lines).
**Verdict:** Keep — implement as the action of the file-mode heuristic (#6).
**Reasoning:** This *is* what #6 does in practice. Don't treat them as separate features.

---

## Proposed architecture

### Where it lives

**Inside the gate binary, on the remote host.** Specifically: between the child process's stdout/stderr pipes and the SSH stdout/stderr that flows back to the MCP.

Currently `src/gate/executor.go` does:
```go
c.Stdout = os.Stdout
c.Stderr = os.Stderr
```
which is direct kernel-pipe pass-through. The new design replaces `os.Stdout`/`os.Stderr` with a `redact.Writer` wrapper that buffers a sliding window, runs the rule scanner, emits scrubbed bytes downstream.

**Why the gate binary, not the MCP:**
- The gate is the security boundary anyway (signs, verifies, classifies). Adding redaction here keeps trust concentrated.
- The MCP runs as user `karthi` on the laptop — same user as Claude. A redactor there is bypassable by reading the SSH session's raw output (e.g., by patching the MCP, or by an alternate SSH client). Inside the gate, the agent sees only post-scrub bytes; there is no raw-output channel.
- A separate process would have to sit in the SSH pipe, which means wrapping `command="...gate"` with `command="...gate | redactor"`. That's brittle (signal handling, exit-code propagation, error-on-pipe-write), and the redactor would still have to live on the remote host anyway.

**Why not the MCP:**
- The MCP cannot enforce that bytes flow through it. The signer's key isolation depends on Claude being unable to forge signed writes; redaction doesn't have that crypto guarantee, so it has to be where the bytes physically exit Claude's reach. That's the remote-side gate.

### How it scans

**Streaming with a sliding window.**

- Bounded buffer: 4 KiB ring buffer per stream (stdout, stderr each have their own).
- Each chunk read from the child is appended to the ring, scanned for rule hits, and the safe prefix is flushed downstream.
- "Safe prefix" = bytes far enough from the buffer tail that no rule pattern could still match across the boundary. With the longest rule pattern bounded to 256 bytes, the safe prefix is `len(ring) - 256` bytes.
- On child EOF, flush the whole remaining buffer through the scanner one last time.

Why streaming, not batched:
- Reads can be unbounded: `cat /var/log/syslog`, `journalctl --no-pager`, `find /`. Slurping all output costs RAM and adds latency.
- The current `executor.go` already streams via pipe pass-through. Drop-in replacement preserves the latency profile.

Buffer-boundary correctness: a secret spanning a buffer write doesn't matter because we only flush the safe prefix; the suffix stays in the ring until the next read coalesces it. Confirmed safe as long as no rule pattern exceeds 256 bytes (currently true for all gitleaks rules — longest is ~140 bytes for some PEM headers).

### What patterns ship

Three layers, all run in sequence on each window:

**Layer 1 — Built-in rule pack** (compiled into the gate binary)
- Curated ~30 high-precision gitleaks rules: AWS access/secret, GitHub PAT, GitLab token, Stripe, Slack, JWT, generic private-key PEM block, generic high-entropy bearer token, common database connection-string passwords.
- Stored as `var builtinRules = []Rule{ {ID: "aws-access-key", Regex: ..., Min: ..., Max: ...}, ... }`
- Compiled regexes are constructed once at gate startup and reused.

**Layer 2 — File-mode heuristic** (only when the command is recognizably a single-file read)
- Parse the command: if it matches `^(cat|head|tail|less|more) (\S+)$` and that path is a file with `mode & 0o077 == 0`, replace the entire output with one marker: `[SSHGATE_REDACTED_FILE path=<path> mode=<octal> sha256=<8hex>]`
- The 8-hex SHA-256 prefix is *of the file content* and lets the agent recognize "same file as before."

**Layer 3 — Operator redactlist** (per-host append-only file at `~/.sshgate-gate/redactlist.append-only`)
- Each line is one of:
  - `pattern: <regex>` — same scanner pass as Layer 1
  - `anchor: <hmac-hex>` — HMAC-SHA256 of a literal secret with the host-anchor key; gate computes HMAC over each 32/64/128-byte sliding window of output and matches.
  - `file: <path>` — explicit whole-file redaction regardless of mode
- File is `chattr +a` if the FS supports it; each line is signed by the master signing key (the existing one) so additions cannot be forged even on filesystems without immutable bit support.

### How is the redact list updated

The agent cannot update the redactlist directly. The update flow:

1. Agent (or operator) decides to add a pattern (e.g. via the standing instruction in #11).
2. MCP issues a sign request to the signer just like any write: `commands: [{"server": "prod-db", "cmd": "SSHGATE_REDACT_ADD pattern=\"<regex>\"", ttl: 60}]`
3. Karthi gets a Telegram DM showing the proposed pattern, taps approve.
4. Signer signs; MCP SSHes the signed command; gate's `main.go` recognizes `SSHGATE_REDACT_ADD` (alongside the existing `SSHGATE_REVOKE` and stubbed `SSHGATE_UPDATE`), appends the signed line to `redactlist.append-only`.
5. New pattern is in effect for the next read.

**Removal is not supported by this flow.** If Karthi wants to remove a pattern, he SSHes in as root manually, runs `chattr -a redactlist.append-only`, edits, restores `chattr +a`. The agent has no path to this.

### Stable identifier format

`[SSHGATE_REDACTED key=<8hex>]` for inline patterns; `[SSHGATE_REDACTED_FILE path=<p> sha256=<8hex>]` for whole-file.

Key derivation:
- At gate startup (per SSH connection, i.e. per `gate` process invocation since SSH spawns a fresh process per command-with-forced-command), gate generates a random 32-byte session key. Never persisted.
- For a matched secret bytes `s`, the marker key is `HMAC-SHA256(session_key, s)[:4]` formatted as 8 hex chars.
- Same secret in the same SSH session → same marker key. Different session → different key.
- 8 hex chars = 32 bits = collision-resistant within a session (you'd need to see ~65k distinct secrets to get a 50% collision chance, and a single command's output won't have that many).

### First-run UX

During `/sshgate:add <alias> <user@host>`:

1. After successful setup (gate deployed, `command=` line added, ping passes), MCP runs `gate --service-probe` over SSH.
2. `--service-probe` runs `systemctl list-units --type=service --state=active --no-pager --plain` + `command -v docker && docker ps --format '{{.Image}}'` (read-only, no signature needed; classifier already allows these).
3. Returns a JSON list of detected services.
4. MCP looks up each against a built-in service→files map (`nginx → /etc/nginx/, /var/log/nginx/`, `postgres → /etc/postgresql/, /var/lib/postgresql/`, etc.).
5. Shows the operator:
   ```
   I detected these services on prod-db:
     - nginx     → redact: /etc/nginx/* (mode-sensitive)
     - postgres  → redact: /etc/postgresql/*/pg_hba.conf, ~postgres/.pgpass
     - docker    → redact: docker inspect output for env vars
   Install these default redaction patterns? [Y/n]
   ```
6. On Y, MCP queues a single bulk `SSHGATE_REDACT_ADD ...` for each pattern; one Telegram tap approves all.
7. On N, install proceeds with empty redactlist (rules + file-mode heuristic still active).

### Bootstrapping with append-only

During gate install (`/sshgate:add`):

1. `redactlist.append-only` is created empty (touch).
2. `chattr +a redactlist.append-only` is attempted (best-effort; ignored on filesystems that don't support it — gate is told via a sibling marker file `redactlist.append-only.mode = chattr|signed-only`).
3. Subsequent writes go through `SSHGATE_REDACT_ADD` only, which appends signed lines.
4. Gate refuses to read the file if (a) its `chattr +a` was removed (when the FS supports it), AND (b) any line lacks a valid sig from the master key. Either condition fails closed → all reads redacted to opaque markers as a safety degraded mode.

### What about gate's own code updates

Built-in pattern updates ship via `SSHGATE_UPDATE` — already a stubbed signed command in `src/gate/cmd/sshgate-gate/main.go:117`. v1.1 implementation fetches, verifies signature, swaps binary. New rules are part of the binary, so they get updated with the binary.

---

## Implementation plan

### Task R1 — Built-in pattern library + streaming scrubber

- **Files added:** `src/redact/scanner.go`, `src/redact/rules.go`, `src/redact/writer.go`, `src/redact/{scanner,rules,writer}_test.go`.
- **Files changed:** `src/gate/executor.go` (replace `os.Stdout`/`os.Stderr` assignment with `redact.Writer` wrapping them; thread session key in).
- **Contract:** `redact.NewWriter(downstream io.Writer, sessionKey [32]byte, rules []Rule) io.WriteCloser` — Write() scans incoming bytes against compiled rules, emits redacted bytes downstream; Close() flushes remaining buffer through one final scan.
- **Complexity:** M. Streaming-window scanner with the safe-prefix invariant is the load-bearing piece; rest is plumbing. ~400 LOC + ~600 LOC tests (golden-file driven, table-tested per rule).

### Task R2 — Append-only redactlist + SSHGATE_REDACT_ADD signed command

- **Files added:** `src/redact/redactlist.go`, `src/redact/redactlist_test.go`.
- **Files changed:** `src/gate/cmd/sshgate-gate/main.go` (new branch for `SSHGATE_REDACT_ADD`); `src/redact/scanner.go` (load redactlist at scanner init, merge into rule set); `src/mcp/sshgate/redact.go` (new MCP tool `sshgate.add_redact_pattern`).
- **Contract:** redactlist file format is line-oriented: `<base64-payload> <base64-sig>` where payload is JSON `{"kind":"pattern|anchor|file", "value":"...", "added_at":"..."}`. Loader validates each sig with the same master pubkey gate already loads. Failed sigs → reject load, fail closed.
- **Complexity:** M-L. Wire format + signing reuse is straightforward; the `chattr +a` install-time best-effort plus "fail closed if tampered" logic is the careful part. ~300 LOC + ~400 LOC tests.

### Task R3 — File-mode heuristic

- **Files added:** `src/redact/filemode.go`, `src/redact/filemode_test.go`.
- **Files changed:** `src/gate/cmd/sshgate-gate/main.go` (before running the child, parse the command; if it's a single-file read of a mode-sensitive file, short-circuit to `[SSHGATE_REDACTED_FILE …]` output, do not exec the child).
- **Contract:** `redact.MatchSingleFileRead(cmd string) (path string, ok bool)` recognizes `cat|head|tail|less|more <single-quoted-or-bare-path>`. `redact.IsSensitiveByMode(path string) (bool, os.FileInfo)` stats the file, returns true for mode & 0o077 == 0. On hit, replace the whole `execChild` call with a print of the marker.
- **Complexity:** S. ~150 LOC + ~300 LOC tests.

### Task R4 — First-run UX (service probe + default-pattern prompt)

- **Files added:** `src/redact/services.go` (service→files map), `src/redact/services_test.go`; `src/mcp/sshgate/service_probe.go`.
- **Files changed:** `src/mcp/sshgate/add_server.go` (after install verify, run probe + prompt + bulk add); `commands/add.md` (document the prompt step in the slash command).
- **Contract:** `services.DetectAndSuggest(probeOutput []byte) []SuggestedRedact` returns a list of patterns to add. MCP wraps in a bulk sign request.
- **Complexity:** M. The map of services is a flat table; the awkward part is the cross-platform-ish service detection on the remote (`systemctl` vs `rc-service` vs nothing). ~250 LOC + ~250 LOC tests.

### Task R5 — Tests + integration with phase 5 e2e

- **Files added:** `tests/integration/redact_e2e_test.go`; golden fixtures under `testdata/redact/` (samples of nginx config with embedded secrets, postgres pg_hba, AWS credentials file, JWT in log line, etc.).
- **Files changed:** `tests/integration/sshgate_e2e_test.go` (add a "read a config file containing a secret, verify marker in output" scenario).
- **Contract:** integration test spins up the Dockerized openssh-server container (already used per `docs/specs/2026-05-19-sshgate-design.md` testing approach), deploys gate, copies a fixture file with secrets, runs `cat <fixture>` over SSHGate, asserts the secret is replaced with the marker.
- **Complexity:** M. Mostly fixture data + a few new test scenarios in the existing harness. ~200 LOC + ~30 fixture files.

**Total estimate:** ~1,300 LOC of production code, ~1,800 LOC of tests, ~30 fixture files. 5-8 day project for one focused developer.

---

## Open questions

1. **Regex performance on streaming output.** A handful of regexes is fine, but ~30 rules running on every 4 KiB chunk for a 10 GB log dump (`journalctl --no-pager` on a busy host) means ~2.5M scanner invocations. Benchmark needed; consider Aho-Corasick or hyperscan for the literal-prefix sub-patterns. Mitigation: rules have a `minPrefix` field used for a fast literal-search prefilter before running the regex.
2. **False-positive rate on log content.** Gitleaks rules were tuned for source code; log files have UUIDs, request IDs, base64-encoded payloads that look like secrets to the heuristic-entropy rules. Likely need to disable the "generic high-entropy" rule by default and rely on named rules. Acceptance: ship without entropy rule, add it as opt-in via redactlist.
3. **File-mode heuristic: feature or setting?** Currently proposed as default-on. Question: should `cat /etc/passwd` (mode 0644, but world-readable so unlikely to contain secrets) ever be redacted? Probably no — file mode IS the discriminator. But what about `cat /etc/shadow` (mode 0640 root:shadow on most distros)? The gate runs as the SSH user, can't read 0640 root:shadow anyway. Mostly self-resolving but worth documenting.
4. **Secrets spanning a buffer boundary.** Resolved in design (safe-prefix invariant). Still: what if a single line is longer than the 4 KiB ring? E.g. a base64-encoded 16 KB binary blob. Mitigation: dynamic ring growth up to 64 KiB cap; beyond that, flush whatever's in the ring (accepting that an unusually long secret straddling 64 KiB *might* slip if it ends in a 256-byte tail spanning the flush — extremely unlikely for real secrets, which are typically <128 bytes).
5. **Interaction with the wire-signing format.** Read commands aren't signed, so the redactor lives entirely on the read path. There's no impact on the sigwire format or on write-command verification. ✓ Confirmed orthogonal.
6. **Performance of HMAC anchors.** N anchor entries means N HMAC computations per sliding window. At N=100, this is fine; at N=10,000 (someone obsessively adds every literal), this becomes a problem. Soft cap on redactlist size: 1,000 entries, warn at 500.
7. **What if the agent legitimately needs to see a secret?** Pathological case: Karthi asks "what's the current value of /etc/myapp/api_key so I can update it elsewhere?" The redactor will hide it. Fix: a `[REDACTED]`-piercing tool is a write — Karthi has to explicitly `cat | tee /tmp/cleartext-copy` and approve, knowing the agent will see it. This is intentional and aligns with the threat model.

---

## UX warnings

These warnings appear in the install prompt, in `README.md`, in the `debugging-remote-servers` skill, and in the Telegram approval message when a redactlist update is proposed.

1. **"This is not 100% foolproof."** Detection has false negatives — high-entropy strings (random 64-byte hex tokens, base64 blobs) that don't match a known pattern will slip through. Treat redaction as defense-in-depth, not a perimeter.
2. **"Custom-format secrets are invisible to the default rules."** If your team uses a proprietary token format (`MYCO_TOKEN_v3_<32hex>`), the default ruleset doesn't know about it. Add it via `SSHGATE_REDACT_ADD`.
3. **"False positives mean the agent sees `[REDACTED]` where there's no real secret."** Some legitimate strings will match (UUIDs that look like high-entropy tokens). This is the safe side of the trade-off — the agent gets less information, but it never gets the wrong information. If a false positive is breaking your workflow, manually `cat | sed 's/marker/real-value/'` after reading.
4. **"Custom-pattern updates need Telegram approval."** Adding a pattern is a write. Don't expect to bulk-add 50 patterns without 50 Telegram-equivalent taps (use bulk approval to batch them). Karthi should review each addition — a maliciously crafted regex can cause ReDoS.
5. **"File-mode heuristic only works for `cat`-style single-file reads."** Pipelines (`cat /etc/shadow | head -1`) bypass it. `journalctl`, `dmesg`, `env`, anything that synthesizes output is scanned via Layer 1+3 only.
6. **"Per-session HMAC means the agent loses correlation across sessions."** This is intentional. If the same secret appears in two SSH sessions, the agent sees different markers. The agent cannot build a cross-session map of "key a1b2c3d4 = prod DB password."
7. **"The gate binary is the trust anchor."** If the gate binary is compromised (e.g., replaced via a non-SSHGate channel), redaction is moot. The same defense applies as for signed-write verification: `command="..."` forcing, key isolation, manual binary integrity checks during install.
8. **"Removing a pattern requires manual root access."** The redactlist is append-only by design. If you add a pattern that breaks something, you cannot remove it via the agent — only by SSHing in as root and rewriting the file.

---

## Estimated complexity / scope

- **LOC estimate:** ~1,300 production + ~1,800 test = ~3,100 total. Sits between the gate binary (~900 LOC today) and the MCP server (estimated ~900 LOC).
- **Test scope:** Unit tests per package (scanner, rules, writer, redactlist, filemode, services). Integration tests in `tests/integration/redact_e2e_test.go` covering: AWS key detected, PEM block detected, file-mode triggers whole-file redaction, redactlist signature mismatch rejects load, `SSHGATE_REDACT_ADD` end-to-end via signer. Golden fixtures under `testdata/redact/` for ~30 secret samples (one per built-in rule).
- **Documentation scope:** New `docs/specs/2026-05-XX-redaction-design.md` (this proposal, finalized after review); update `docs/specs/2026-05-19-sshgate-design.md` MCP tool surface with `sshgate.add_redact_pattern`; new `skills/redaction-aware-debugging.md` skill for Claude; update `commands/add.md` for the first-run prompt; update `README.md` with the UX warnings; new `docs/decisions/2026-05-XX-redaction-architecture.md`.
- **Timeline as a v1.2 feature:** 5-8 days of focused work for one developer.
  - Day 1: R1 scanner + rule pack, basic streaming writer with tests.
  - Day 2: R1 finish, integrate into executor.go, golden tests.
  - Day 3: R2 redactlist + signed-update wire format + tests.
  - Day 4: R3 file-mode heuristic + tests; R4 service probe map.
  - Day 5: R4 MCP integration + first-run prompt + bulk-approval flow.
  - Day 6: R5 e2e tests, fixture corpus, integration with phase 5 harness.
  - Day 7-8: Buffer for benchmarking (open question 1), false-positive tuning (open question 2), code review fixes, doc polish.
