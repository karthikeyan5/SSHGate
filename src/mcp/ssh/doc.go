// Package ssh wraps golang.org/x/crypto/ssh to provide a thin client
// the MCP runner uses for one-shot remote command execution.
//
// Responsibilities:
//
//   - Load the SSHGate-dedicated Ed25519 key from disk (the same key
//     whose authorized_keys line on the remote forces command=velgate).
//   - Verify host keys against a TOFU (trust-on-first-use) known_hosts
//     file: first contact appends, mismatch refuses.
//   - Run a single command per connection. Stdout, stderr, and the
//     remote exit code are returned independently; the caller decides
//     how to surface them to Claude.
//
// All operations are bounded by Client.Timeout, which covers dial +
// auth + exec. Cancellation via ctx aborts a stuck dial or session.
//
// The TOFU strategy is appropriate for v1: pubkeys are pinned the
// first time the MCP connects, and any subsequent mismatch is treated
// as an attack. The mismatch error surfaces both fingerprints so the
// operator can compare with the real server's host key before
// rotating known_hosts manually.
package ssh
