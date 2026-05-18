// Package common holds types and helpers shared by velgate, velsigner, and
// the SSHGate MCP. It currently exposes two pieces of shared logic from the
// spec: the read/write command classifier (§"Command Classification") and
// the VELGATE_SIG payload wire format (§"Signature Scheme"). One source of
// truth for both so the remote gate (velgate), the signing daemon
// (velsigner), and the local MCP cannot drift from each other.
//
// The classifier is fail-safe: anything that is not affirmatively a read
// command is reported as a write so callers can route it through the
// approval flow. Pipes, redirects, control operators (;, &&, ||), sudo
// prefixes, command substitutions, and unknown binaries all collapse to
// KindWrite by design.
//
// The payload module owns the VELGATE_SIG:<sigB64>:<payloadB64> envelope.
// EncodeSigned/DecodeSigned handle the encoding only; signing and
// verification live with the keyholders (velsigner and velgate).
package common
