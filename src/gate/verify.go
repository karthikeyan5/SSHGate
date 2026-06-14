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

	// Time bounds. The gate is the AUTHORITATIVE validity cap, independent
	// of the signer — so a buggy, leaked, or hostile signer can never mint
	// an over-long or never-expiring token. Reject malformed timestamps
	// BEFORE any arithmetic: this both rejects nonsense (ts/exp <= 0, or a
	// non-positive window) and guarantees 0 < TS < Exp so the Exp-TS
	// subtraction below cannot overflow.
	nowUnix := now.Unix()
	if payload.TS <= 0 || payload.Exp <= 0 || payload.Exp <= payload.TS {
		return "", ErrBadFormat
	}
	if nowUnix >= payload.Exp {
		return "", ErrExpired
	}
	// Compare the window in int64 SECONDS. Multiplying an attacker-controlled
	// seconds value into an int64-ns time.Duration (Duration(exp-ts)*Second)
	// overflows NEGATIVE for windows > ~9.2e9s, so a `> MaxSigValidity` check
	// silently ACCEPTS a ~290-billion-year token. The guards above keep both
	// operands positive with Exp > TS, so this subtraction stays in range.
	if payload.Exp-payload.TS > int64(sigwire.MaxSigValidity/time.Second) {
		return "", ErrValidityTooLong
	}
	return payload.Cmd, nil
}
