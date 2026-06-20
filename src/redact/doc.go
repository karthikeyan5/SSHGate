// Package redact implements the SSHGate v1.2 output redactor.
//
// The redactor sits between a child process's stdout/stderr pipes and
// the SSH stream back to the MCP. Every byte the child emits flows
// through a redact.Writer; any byte matched by a named-format rule is
// replaced inline with `[SSHGATE_REDACTED key=<8hex>]`. The HMAC key
// is derived from a per-session 32-byte random salt that lives only
// in the gate process — never persisted, never transmitted. Because
// OpenSSH spawns a fresh gate per forced-command, per-process equals
// per-session.
//
// # Layers (in scope for v1.2 R1)
//
// R1 implements Layer 1 only: a streaming sliding-window scanner that
// runs a vendored ruleset (gitleaks-derived named formats + SSHGate
// floor rules) over the bytes. Matches become inline markers. A PEM
// accumulator special-cases multi-kilobyte ASCII-armoured private
// keys that exceed the sliding-window safe prefix.
//
// Layers 2 (file-mode), 3 (operator redactlist), the depth-1 decode
// pass, and the SSHGATE_CMD envelope are subsequent tasks (R2-R5);
// the writer's chunk path is structured so those layers can hook in
// at well-defined points without re-plumbing the executor.
//
// # Writer contract
//
// NewWriter wraps an io.Writer. Bytes are buffered in a ring whose
// initial capacity is 8 KiB and hard cap is 64 KiB. The scanner
// always leaves a 4 KiB "safe prefix" unwritten at the tail so a
// secret straddling chunk boundaries can still be matched on the
// next Write. Close flushes the remaining tail.
//
// The threat model is in
// docs/redaction-architecture.md
// §"Threat model". Honest framing: redaction is defense-in-depth,
// not a perimeter. A truly hostile LLM can craft evasions. The
// redactor catches the typical-case accidental leak, not adversarial
// exfiltration.
package redact
