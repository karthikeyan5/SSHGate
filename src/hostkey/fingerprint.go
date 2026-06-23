// Package hostkey is the low-level, dependency-light home of the canonical
// SSH host-key fingerprint function shared by BOTH the gate and the MCP.
//
// The gate (remote, untrusted-input side) self-derives its own host-key
// fingerprints from /etc/ssh/ssh_host_*.pub and rejects any signed write
// whose payload.Host does not match one of them. The MCP (control plane)
// computes the same fingerprint when it pins a server's host key (TOFU) and
// records it in the registry, then supplies it — from the trusted registry,
// never from an agent parameter — in the sign request.
//
// Because the gate enforces what the MCP supplied, the two fingerprint
// computations MUST be byte-identical. They live here, in one place, so they
// cannot drift: the gate imports hostkey directly, and the MCP-side
// ssh.Fingerprint delegates here. A parity test in src/mcp/ssh locks them
// together.
//
// This package deliberately depends only on the standard library plus
// golang.org/x/crypto/ssh — it must NOT import any gate or MCP package, so
// the gate can import it without dragging in the MCP's registry/SSH-client
// surface.
package hostkey

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// Fingerprint returns the SHA256 fingerprint of key in the standard OpenSSH
// "SHA256:<base64>" form: SHA-256 over the key's SSH wire marshalling,
// base64-encoded with the standard alphabet and NO padding (matching
// `ssh-keygen -l`).
//
// This is THE canonical definition for SSHGate. Both the gate and the MCP
// fingerprint host keys through this function (the MCP via the thin
// ssh.Fingerprint wrapper), so an "approve on server X" signature binds to
// X's real pinned host key and is cryptographically un-replayable on any
// other host.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
