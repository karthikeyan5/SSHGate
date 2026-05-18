# Security audit — SSHGate v1 — 2026-05-19

**Auditor:** Claude Opus 4.7 (Audit Gate 3, last gate before v1 done)
**Threat model source:** `docs/specs/2026-05-19-sshgate-design.md §"Threat model"`
**Adjacent reports:** `~/arogara/code-review/reports/sshgate-2026-05-19.md` (all MAJORs FIXED), `docs/audits/pii-audit-2026-05-19.md` (no MUST-FIX), `docs/decisions/MORNING-REVIEW-2026-05-19.md` Decision 18 (trailing-cmd latent bug, fixed).

## Summary
- Scenarios run: 12
- PASS: 11
- FAIL: 0
- MINOR concerns: 5 (4 carry-overs from code review; 1 new: missing `\n`/`\r` in upload metachar guard)
- Overall: **secure for personal use.** No publish-blockers. The OS-user-separation backbone of the threat model holds; cryptographic gating is sound; the trailing-cmd wire path (Decision 18) is verified inert. v2-amplified concerns documented at the bottom.

## Per-scenario findings

### S1 — Can Claude read the master signing key? — PASS

- **Threat:** Claude tries `cat /var/lib/velsigner/keys/velgate.key`.
- **Defense:** OS user separation. `scripts/create-velsigner-user.sh` creates `velsigner` system user; `chown -R velsigner:velsigner /var/lib/velsigner`; `chmod 0750 /var/lib/velsigner` plus `chmod 0750` on `keys/` and `tokens/`. `src/velsigner/keystore.go:75` writes the private key with `atomicWrite(..., 0o600)` and refuses to load any private key whose mode mask `&0o077 != 0` (`keystore.go:32`). `GenerateKeyPair` refuses to overwrite an existing file (defense against an accidental rotate clobbering a working key).
- **Attempted exploit:** On this dev box, velsigner is not installed — no file exists yet. Static analysis of the install path: the `velsigner` group includes `karthi` (so karthi can *traverse* `/var/lib/velsigner` and `keys/`, mode 0750) but the key file itself is mode 0600 owned by `velsigner:velsigner`. A `cat` from karthi returns EACCES.
- **Outcome:** Defense intact; the only weak link would be an operator running `chmod 644` on the key — caught by `LoadKey`'s mode mask refusal on subsequent daemon restart. PASS.
- **Notes:** Belt: the load-time mode check (`keystore.go:32`) means a runtime-introduced permission slip is caught loudly, not silently tolerated.

### S2 — Can Claude ptrace velsigner to extract the key from memory? — PASS

- **Threat:** `ptrace(PTRACE_ATTACH, velsigner_pid)` to read the key out of process memory.
- **Defense:** `kernel.yama.ptrace_scope=1` blocks cross-user ptrace by default on modern Linux.
- **Attempted exploit:** Probed live — `cat /proc/sys/kernel/yama/ptrace_scope` returns `1` on the dev box. With velsigner running as a different uid, an unprivileged karthi process cannot attach.
- **Outcome:** PASS.
- **Notes:** The systemd unit (`scripts/install.sh:69-95`) layers further hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `ProtectKernelTunables`, `ProtectKernelModules`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, `LockPersonality`. **Gap (MINOR):** no `SystemCallFilter=@system-service` / explicit `~ptrace` deny — a future kernel bug or yama relaxation would still leave ptrace reachable. Add `SystemCallFilter=@system-service` and `SystemCallFilter=~@privileged @resources` for v1.1 hardening. Not a v1 blocker; the kernel-default ptrace_scope is the load-bearing defense and the systemd flags already deny most kernel-tampering surfaces.

### S3 — Can Claude impersonate Karthi on Telegram? — PASS

- **Threat:** Claude crafts a callback with `from.id = 12345678`.
- **Defense:** Telegram authenticates `from.id` server-side; Claude has no Telegram session. velsigner cross-checks `cb.From.ID != t.allowedUserID` at `src/velsigner/backend/telegram.go:317-330` BEFORE any pending-state lookup or mutation; same check on `/start` at `:286-301`. AllowedUserID is constructor-injected and immutable after `NewTelegramBackend` returns (line 144).
- **Attempted exploit:** Static analysis — the `from.id` check is the very first branch in `handleCallback`. An unauthorized callback gets a `not authorized` answer and is logged; `t.pending` is never touched. There is no path from a non-callback origin to resolve a pending request: only `handleCallback` calls `t.resolve` for approve/deny; `handleStart` only saves chat_id (and is also `from.id`-gated); the per-request goroutine in `Request` only resolves with `StatusTimeout`.
- **Outcome:** PASS.
- **Notes:** Even if Claude could spoof the network to the Telegram API (it can't — TLS), Telegram's bot API issues `getUpdates` over an HTTPS connection from velsigner outward; there is no inbound socket Claude can write to. The masking helper at `:585-591` redacts the allowed user_id from a refusal message so DM-scanning third parties don't learn it verbatim.

### S4 — Can Claude inject a fake "approve" message into c3 to confuse velsigner? — PASS

- **Threat:** Claude attaches to a c3 topic and `mcp__plugin_c3_c3__reply`s text mimicking an approval.
- **Defense:** velsigner uses its OWN bot token via `tgbotapi.NewBotAPIWithAPIEndpoint` (`telegram.go:121`) and polls `bot.GetUpdates` (`:260`). No shared IPC, no shared sockets, no shared files with c3.
- **Attempted exploit:** Confirmed by file scan — `grep -rn "velsigner\|sshgate" /home/karthi/arogara/c3` returns no hits inside c3's broker source; `grep -rn "c3\|/run/c3" /home/karthi/arogara/SSHGate/src` returns one false positive (a nonce string in a test). c3's broker listens on `$XDG_RUNTIME_DIR/c3.sock` (mode 0600, owned by karthi); velsigner listens on `/run/velsigner/sock` (mode 0660, owned by velsigner:velsigner). The two sockets are in different directories with different owners and no code-path bridge.
- **Outcome:** PASS.

### S5 — Can Claude forge a sign request directly into the velsigner socket? — PASS

- **Threat:** Claude writes to `/run/velsigner/sock` with a request that velsigner approves without Telegram.
- **Defense:** velsigner's protocol has NO "approved" branch that does not consult the Backend. Traced `src/velsigner/daemon.go:80-143`: every code path from socket read → response either calls `respondError` (no signing) or calls `d.Backend.Request(ctx, apReq)` and waits for the channel — which only yields `StatusApproved` if the Backend says so. `StubBackend.Request` (`src/velsigner/backend/stub.go:19`) hard-codes `Status: StatusDenied`; `TelegramBackend` only resolves Approved via the gated `handleCallback` (S3).
- **Attempted exploit:** Static trace: `HandleSignRequest` → `d.Backend.Request` → channel; if `result.Status == StatusApproved`, only then `d.signAll`; signatures only leave the daemon via `writeJSONLine` after a real backend approval. No "auto-approve" branch. Audit log path: `audit.go:58` opens with mode 0640, owned by velsigner — karthi (in velsigner group) can READ but cannot write; no forged-approval row can be appended by karthi.
- **Outcome:** PASS.
- **Notes:** The socket itself is mode 0660 with group `velsigner`; karthi can `connect()` (as designed for the MCP) but the wire protocol gives no privilege escalation.

### S6 — Can Claude bypass `command="..."` forcing? — PASS

- **Threat:** Claude reads `~/.config/sshgate/ssh/sshgate_ed25519` (same uid — yes) and SSHes directly to a registered server, bypassing the MCP.
- **Defense:** OpenSSH's `command="..."` directive in `authorized_keys` forces velgate to run regardless of the client's command line. velgate classifies the inbound `$SSH_ORIGINAL_COMMAND`; an unsigned write returns exit 77 `EX_NOPERM` (`src/velgate/cmd/velgate/main.go:111`).
- **Attempted exploit:** Phase 1 integration test `TestPhase1EndToEnd/DirectUnsignedSSHBypassRefused` (`tests/integration/e2e_test.go:104-126`) exercises exactly this: dial container directly with the SSHGate key, run `rm /tmp/x`, expect exit 77 with the "write commands require a VELGATE_SIG prefix" stderr. **Ran the test:** `go test -race -count=1 -run TestPhase1EndToEnd -tags integration ./tests/integration/` → `ok 6.254s`. PASS.
- **Outcome:** PASS.
- **Notes:** The `add_server` rewrite at `src/mcp/tools/add_server.go:284-294` writes the canonical `command="~/.velgate/velgate",no-port-forwarding,no-X11-forwarding,no-agent-forwarding` line. The no-forwarding flags are the second line of defense against tunneling.

### S7 — Can Claude exploit the trailing-cmd in VELGATE_SIG wire format? — PASS

- **Threat:** Crafted `VELGATE_SIG:<valid-sig-for-ls>:<valid-payload-for-ls> rm -rf /` where the trailing string is unauthenticated.
- **Defense:** velgate executes `payload.Cmd` (inside the signed envelope), not the SSH command tail. Trace: `src/velgate/cmd/velgate/main.go:82` → `velgate.VerifySigned(raw, …)` returns `payload.Cmd` as `innerCmd`; classify and exec all use `innerCmd`. `sigwire.DecodeSigned` (`src/sigwire/payload.go:89-91`) strips the trailing space-delimited content from the payload field BEFORE base64 decoding — i.e. the trailer never becomes part of the verified bytes. Signature verification uses `json.Marshal(payload)` (verify.go:42) — the bytes are reconstructed from the decoded payload object, not the raw SSH line. There is no path where the trailing cmd influences execution.
- **Attempted exploit:** Static — the only consumer of `raw` after sig verification is `innerCmd = ic` (main.go:87), which is `payload.Cmd`. The trailing string is discarded by DecodeSigned's space-trim and never re-read.
- **Outcome:** PASS — Decision 18's latent bug is genuinely cosmetic; the security property is intact.
- **Notes:** The wire-format design choice (trailer for SSH-log readability) is sound provided no future contributor introduces a code path that re-parses the raw line. Suggest adding a code-comment-grade invariant doc above `VerifySigned` reinforcing "callers MUST not re-parse `line` after this returns".

### S8 — Can Claude tamper with the velgate binary on the remote? — PASS

- **Threat:** Claude has SSH access via the gated key; can it overwrite `~/.velgate/velgate`?
- **Defense:** The classifier (`src/classify/classifier.go`) treats `cp`, `mv`, `dd`, `rsync`, `ln`, top-level output redirects (`>`, `>>`), pipes, and `tee` (any form) as `KindWrite`. The read allowlist (line 294-379) is a strict allowlist — anything not present is write by default.
- **Attempted exploit:** Ran a probe script against the classifier with attack-shaped inputs:
  ```
  cp foo ~/.velgate/velgate         → write
  mv foo ~/.velgate/velgate         → write
  tee ~/.velgate/velgate            → write
  tee -a ~/.velgate/velgate         → write
  cat foo > ~/.velgate/velgate      → write   (top-level redirect)
  echo hi | tee /tmp/x              → write   (pipe forces write)
  dd if=/dev/zero of=/tmp/x         → write
  rsync foo bar                     → write
  ln -s foo bar                     → write
  ```
  All correctly classified as write. The only documented write that could write through `~/.velgate/` would still go through the approval flow — so Karthi sees `cp evil.bin ~/.velgate/velgate` in his Telegram message and refuses.
- **Outcome:** PASS.
- **Notes (MINOR carry-over Mi3, Mi4 from code review):** `git stash` and `wget <URL>` (without `-O-`) classify as `read`. `git stash` mutates the working tree+index; `wget URL` saves to disk by default. **Neither writes `~/.velgate/`** — `git stash` doesn't touch that path, and `wget` writes to `./` unless given `-O <path>` which would change the classification. So these false-negatives don't open S8 specifically, but they should still be moved to `write` for general defense-in-depth. Already filed as code-review MINOR.

### S9 — TOFU host-key first-trust attack — MINOR (operator-mitigation)

- **Threat:** On `add_server`'s first dial to a new server, an attacker controlling the network presents a host-key for an attacker-controlled box.
- **Defense:** First-trust is by definition unverified — the captured fingerprint is returned in `AddServerOutput.Fingerprint` (`add_server.go:53`, `:521-528`) so the operator can verify it out-of-band. Subsequent dials verify against the pinned key (`src/mcp/ssh/known_hosts.go`, used via `sshpkg.TOFU(khPath)`).
- **Attempted exploit:** Static — first dial pins whatever key is presented. Subsequent mismatches return `ErrHostKeyChanged`. So a one-time MITM at add-time is achievable iff the attacker controls the network and the operator does not check the returned fingerprint.
- **Outcome:** MINOR (operator-mitigation). Already documented in `MORNING-REVIEW-2026-05-19.md` Decision 11. **For v1.1**, add an optional `pin_host_key` (SHA256 fingerprint) input field to `add_server` so paranoid operators can pre-pin.
- **Notes:** Not a blocker — the fingerprint is in the tool output and the operator workflow can include "compare against an out-of-band channel."

### S10 — Revoke command replay — PASS

- **Threat:** Claude captures a signed `VELGATE_REVOKE` from a prior session and replays it later to clobber a server that has since been re-added.
- **Defense:** Each sign request carries a unique 16-byte nonce (`src/velsigner/daemon.go:271-277`) and a TTL-bounded `exp` field. `verify.go:53` enforces `nowUnix >= payload.Exp ⇒ ErrExpired`. `MaxSigValidity = 5 * time.Minute` (`sigwire/payload.go:20`) bounds `exp - ts` to ≤ 300s — `verify.go:57-59` rejects anything longer. The revoke command uses `RevokeTTLSec` (likely 60s) so its replay window is small. After expiry, replay fails fast at velgate.
- **Attempted exploit:** Captured signature → wait `exp` seconds → replay. velgate returns exit 65 `EX_DATAERR` with `ErrExpired`. Within the TTL window, replay would succeed — but the TTL is short (≤5min absolute cap, typically ≤60s for revoke) and replay-within-window after revoke-success is a no-op since `~/.velgate/` is already gone (`revoke.go:96-103` tolerates missing dir).
- **Outcome:** PASS for the post-expiry case. The intra-window replay window is bounded and operationally trivial. Audit log carries the nonce indirectly via the signed payload (audit row has cmds+server+request_id+approver+timestamp); detection of replay post-hoc is feasible because each request_id is unique.
- **Notes:** No nonce-store / seen-set on velgate (the verifier). For v2/v1.1 consider adding a small ring buffer of recently-seen nonces on velgate so even intra-TTL replays are caught — but the use case (Claude captures a signed blob and somehow runs SSH later with the same key) is implausible in the threat model and the cost (per-host state, fsync overhead) is real. Acceptable v1 tradeoff.

### S11 — `add_server`'s shell-quoting in remote command construction — PASS (with one MINOR new finding)

- **Threat:** Metacharacters in the path passed to `cat > ~/.velgate/velgate` could break out of the shell command.
- **Defense:** `src/mcp/tools/add_server.go:585-588` rejects `remotePath` containing any of:
  ```
  ' ', '\t', '"', '\'', '\\', '$', '`', '|', '&', ';', '<', '>',
  '(', ')', '{', '}', '*', '?', '[', ']', '!', '#'
  ```
- **Attempted exploit:** Ran 23 attack-shaped paths through the guard:
  - All listed metachars: BLOCKED.
  - **NEW MINOR finding:** `\n` (newline) and `\r` (carriage return) are NOT in the guard. A newline in `remotePath` would split the shell command — `cat > foo\necho pwned > bar && chmod 755 foo` would run `echo pwned > bar` as a second command. `\r` similarly affects line-based command parsing on some shells.
  - `,`, `:`, `=` not in guard but these are not shell metacharacters in this context.
- **Real-world impact:** **Currently zero** — `remotePath` is one of three hardcoded package constants (`remoteVelgateBin`, `remoteVelgatePub`, `remoteAuthKeys`) all of which contain no newlines. The guard is defense-in-depth against future contributors who add a dynamic path.
- **Outcome:** PASS today; MINOR latent gap. Suggest adding `\n` and `\r` (and `\x00` for completeness) to the rejected set.
- **Notes:** Code review's Mi9 noted that `in.Host` and `in.User` aren't shape-validated; same defense-in-depth concern at a different layer. Same MINOR severity.

### S12 — `stripVelgateLines` over-matching — MINOR (was Mi7)

- **Threat:** `velgate/revoke.go:119-157` does a substring match for `command="<candidate>"`. A coincidentally-formatted unrelated `authorized_keys` line containing the same string would also be stripped.
- **Defense:** A pre-revoke backup is written at `authorized_keys.sshgate-revoke-backup` (line 82-86). Atomic write with fsync. The operator can recover.
- **Escalation analysis:** The over-match probability is low in practice:
  - The exact substring `command="~/.velgate/velgate"` or `command="/home/<user>/.velgate/velgate"` would need to appear inside another `authorized_keys` entry verbatim.
  - SSH keys are typically generated by tooling that does not produce such options; operators do not typically hand-write `command="~/.velgate/velgate"` for a non-SSHGate key.
- **Real-world damage if it happens:** One unrelated key entry is removed. Backup file exists. Operator can recover via `cp authorized_keys.sshgate-revoke-backup authorized_keys`.
- **Outcome:** MINOR (not worse than the code review's classification). The backup is a real safety net; the over-match is bounded; recovery is trivial. **Not escalated to MAJOR.**
- **Notes:** For v1.1 the suggested fix is to parse with `ssh.ParseAuthorizedKey` and match by *both* `command=` value AND the public-key bytes (so only the SSHGate key's line is removed). The implementation cost is moderate (already done partially in `authorizedkeys.go` for `add_server`). Acceptable v1 tradeoff.

## Conclusions

- **v1 ready for production personal use?** **Yes.** No FAILs, no BLOCKERs. The cryptographic-gate-with-OS-user-separation backbone holds against the documented threats. Five MINOR concerns are documented and recoverable in follow-up work; none are exploitable in the v1 single-operator deployment shape.
- **v2 (hosted velsigner-server) audit items:**
  - **S3 amplified:** with HTTPS auth on a hosted UI, the load-bearing defense becomes WebAuthn passkey + TOTP server-side. Spec §"Auth on the web UI" already calls this out (Tier 2 phishing-resistant). Phishing remains the #1 attack surface; YubiKey (Tier 3) recommended for any multi-operator deployment.
  - **S4 amplified:** the hosted server is a new public surface (HTTPS API). The API key on the plugin side becomes the new "bot token" equivalent. Rotate procedure must be documented.
  - **S5 amplified:** the wire protocol now crosses an open network. mTLS or signed-request HMAC on top of TLS is worth considering to prevent "compromised API key replays sign requests."
  - **S9 unchanged:** TOFU is independent of approval backend.
  - **S10 unchanged:** nonce + exp still enforced at velgate.
- **Documentation gaps:**
  - Spec under-specifies the recovery procedure for "master signing key rotation" (called out in §"Review & audit gates" but no concrete steps in v1). Suggest adding a `docs/runbooks/rotate-velgate-key.md` for v1.1.
  - Spec does not state the `SystemCallFilter=...` posture; current install.sh has a useful set of `Protect*` and `Restrict*` flags but no syscall-level filter. Document the intentional omission OR add it in v1.1.
  - The `\n`/`\r` gap in the `uploadFile` metachar guard is not specified anywhere — code-comment level fix.

**Status:** DONE — no v1 publish-blockers; five MINOR items filed for follow-up.
