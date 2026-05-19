// Package classify holds the read/write command classifier defined by
// the spec's "Command Classification" section. It is shared by gate
// (the remote gate), signer (the signing daemon), and the SSHGate
// MCP so all three components share one source of truth about which
// shell commands need an approval flow.
//
// The classifier is fail-safe: anything that is not affirmatively a
// read command is reported as a write so callers can route it through
// the approval flow. Pipes, redirects, control operators (;, &&, ||),
// sudo prefixes, command substitutions, and unknown binaries all
// collapse to KindWrite by design.
package classify
