// Package common holds types and helpers shared by velgate, velsigner, and
// the SSHGate MCP. The first member of the package is the read/write command
// classifier from spec §"Command Classification": one source of truth so the
// remote gate (velgate) and the local MCP cannot drift from each other.
//
// The classifier is fail-safe: anything that is not affirmatively a read
// command is reported as a write so callers can route it through the
// approval flow. Pipes, redirects, control operators (;, &&, ||), sudo
// prefixes, command substitutions, and unknown binaries all collapse to
// KindWrite by design.
package common
