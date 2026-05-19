package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// MarkerPrefix and MarkerSuffix bracket every inline redaction marker.
// The fixed prefix lets a downstream consumer find marker boundaries
// without parsing the variable-width key.
const (
	MarkerPrefix = "[SSHGATE_REDACTED key="
	MarkerSuffix = "]"
)

// MarkerKey returns the 8-hex-character key for secret under
// sessionSalt. It is the first 4 bytes of HMAC-SHA256(salt, secret)
// rendered as lowercase hex.
//
// Determinism within a session: the same (salt, secret) pair always
// yields the same key, so an agent reading two occurrences of the
// same redacted secret sees the same marker and can recognise them
// as identical without learning their content.
//
// Freshness across sessions: salt is per-process random, so the same
// secret in a new session yields a different key. There is no
// cross-session linkage of redactions.
//
// Truncation to 32 bits is a deliberate trade — agents see short
// markers, the wire stays human-readable, and the collision rate
// (1 in ~4 billion per session) is acceptable for the
// recognise-same-secret use case. It is NOT a cryptographic identifier;
// `redact.why <key>` (R5) is the only sanctioned way to resolve a
// key back to its source rule.
func MarkerKey(sessionSalt [32]byte, secret []byte) string {
	mac := hmac.New(sha256.New, sessionSalt[:])
	mac.Write(secret)
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:4])
}

// FormatMarker returns the full inline marker for secret. Allocation
// happens once per redaction; the hot path uses this directly rather
// than re-constructing the string each Write call.
func FormatMarker(sessionSalt [32]byte, secret []byte) string {
	return MarkerPrefix + MarkerKey(sessionSalt, secret) + MarkerSuffix
}

// FormatFileMarker returns the whole-file redaction marker used by
// Layer 2 (file-mode heuristic) and Layer 3 file entries. It lives in
// markers.go so the wire format is in one place; the file-mode
// predicates (R3) call this directly.
//
// path is the file path the agent asked to read; mode is the file's
// permission bits in octal (e.g. 0o600); sha256First4 is the first 4
// bytes of SHA-256 of the file contents, rendered as 8 hex chars.
// The agent can recognise "same file as before" within the session
// without learning what's in it.
func FormatFileMarker(path string, mode uint32, sha256First4 [4]byte) string {
	return fmt.Sprintf("[SSHGATE_REDACTED_FILE path=%s mode=%#o sha256=%s]",
		path, mode, hex.EncodeToString(sha256First4[:]))
}
