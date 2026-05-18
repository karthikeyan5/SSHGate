package velgate

import "errors"

// Sentinel errors returned by VerifySigned. Callers should match them
// with errors.Is rather than string-comparing the message.
var (
	// ErrBadFormat means the input did not parse as a well-formed
	// VELGATE_SIG envelope (missing prefix, bad base64, bad JSON, or
	// missing required field).
	ErrBadFormat = errors.New("bad signed-command format")

	// ErrBadSig means the envelope parsed but the Ed25519 signature did
	// not verify against the supplied public key.
	ErrBadSig = errors.New("signature verification failed")

	// ErrExpired means the signed command's exp timestamp is at or
	// before the verification clock (now >= exp).
	ErrExpired = errors.New("signature expired")

	// ErrValidityTooLong means the signed command's validity window
	// (exp-ts) exceeds sigwire.MaxSigValidity. This caps the blast
	// radius of an approved signature and is enforced even if the
	// signature itself is valid.
	ErrValidityTooLong = errors.New("signature validity window too long")

	// ErrEmptyCmd means the signed payload's cmd field was empty after
	// decoding. velgate refuses to execute a zero-length command.
	ErrEmptyCmd = errors.New("signed payload has empty cmd")
)
