package gate

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// VerifySigned parses line as a SSHGATE_SIG envelope, verifies its
// Ed25519 signature against pubkey, and enforces the spec's time
// bounds:
//
//   - exp must be strictly greater than now (now >= exp ⇒ ErrExpired)
//   - exp - ts must not exceed sigwire.MaxSigValidity
//   - the inner cmd must be non-empty
//
// On success, the inner cmd string is returned for execution. On
// failure, the returned error wraps one of the package's sentinels
// (ErrBadFormat, ErrBadSig, ErrExpired, ErrValidityTooLong,
// ErrEmptyCmd) so callers can match with errors.Is.
//
// VerifySigned is the only correct way to unwrap a SSHGATE_SIG line —
// callers MUST NOT execute the inner cmd from sigwire.DecodeSigned
// alone, because DecodeSigned does not verify the signature.
func VerifySigned(line string, pubkey ed25519.PublicKey, now time.Time) (innerCmd string, err error) {
	sig, payload, err := sigwire.DecodeSigned(line)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadFormat, err)
	}
	// DecodeSigned already enforces non-empty cmd at the wire layer;
	// this second check is defensive in case the contract ever loosens.
	if payload.Cmd == "" {
		return "", ErrEmptyCmd
	}

	// Re-marshal the payload to obtain the exact bytes that were signed.
	// Both signer and verifier go through encoding/json, so the byte
	// sequence is stable.
	signedBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: marshal payload for verify: %v", ErrBadFormat, err)
	}
	if !ed25519.Verify(pubkey, signedBytes, sig) {
		return "", ErrBadSig
	}

	// Time bounds. The spec requires now < exp; we enforce now >= exp
	// as expired. Use Unix seconds for parity with the payload fields.
	nowUnix := now.Unix()
	if nowUnix >= payload.Exp {
		return "", ErrExpired
	}
	validity := time.Duration(payload.Exp-payload.TS) * time.Second
	if validity > sigwire.MaxSigValidity {
		return "", ErrValidityTooLong
	}
	return payload.Cmd, nil
}
