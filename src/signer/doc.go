// Package signer implements the local approval daemon that owns the
// master Ed25519 signing key on the operator's machine. It runs as a dedicated
// OS user so that Claude Code (running as karthi) cannot read the key
// or attach to the daemon's process memory.
//
// The daemon listens on a Unix socket and serves a one-JSON-line
// request/response protocol from the SSHGate MCP. Each sign request is
// dispatched to a pluggable backend.Backend (StubBackend for the
// phase-1 test that proves the cryptographic loop without a human in
// the loop; TelegramBackend lands in task 2.1). On Approved the daemon
// signs each command with the master key and returns the wire-format
// SSHGATE_SIG envelope; on Denied or Timeout the daemon writes an
// audit record and returns the status with no signatures.
//
// The package exports five pieces of machinery used by the cmd/
// entry point and tests:
//
//   - LoadKey, GenerateKeyPair: master private key on disk, with the
//     0o077 permission check that makes "world-readable signing key"
//     a startup failure.
//   - AuditLog, OpenAuditLog: append-only JSON-Lines audit with fsync
//     per record, per daemon.md §5.
//   - Server (+ RequestHandler interface): the Unix-socket accept loop
//     with per-connection deadlines, panic recovery, and stale-socket
//     cleanup.
//   - Daemon (+ HandleSignRequest): the orchestrator — read request,
//     ask Backend, sign, respond, audit. Implements RequestHandler.
//   - AuditEvent: the on-disk schema for the audit log.
//
// Stdio discipline: operator-side log lines go to stderr, prefixed
// with "signer: ". Stdout is unused (the protocol is on the Unix
// socket).
package signer
