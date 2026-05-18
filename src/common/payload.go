package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// sigPrefix is the literal ASCII prefix that marks a signed command on the
// wire. Keeping it unexported (and a constant) means it cannot drift between
// velgate, velsigner, and the MCP.
const sigPrefix = "VELGATE_SIG:"

// MaxSigValidity is the spec's "exp - ts < 300 seconds" upper bound on
// signature validity windows. velgate enforces this on verification so that
// approved commands cannot be replayed long after the human tapped approve.
const MaxSigValidity time.Duration = 5 * time.Minute

// SigPayload is the signed-command payload defined in the spec. It is the
// JSON object that velsigner signs and velgate verifies, carried on the wire
// inside a VELGATE_SIG envelope.
type SigPayload struct {
	Cmd   string `json:"cmd"`
	TS    int64  `json:"ts"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

// sigEncoding is the base64 alphabet used for both halves of the wire
// envelope: URL-safe (no '+' or '/') and unpadded (no '='), so the encoded
// string is safe to drop directly onto an SSH command line without quoting.
var sigEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// EncodeSigned produces the wire format "VELGATE_SIG:<sigB64>:<payloadB64>"
// using URL-safe base64 without padding (SSH-command-line safe). sig is the
// 64-byte Ed25519 signature over the JSON-marshalled payload; EncodeSigned
// does not compute the signature — that is the caller's job (velsigner
// owns the key, this package owns the wire shape).
func EncodeSigned(sig []byte, payload SigPayload) (string, error) {
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	var b strings.Builder
	b.Grow(len(sigPrefix) + sigEncoding.EncodedLen(len(sig)) + 1 + sigEncoding.EncodedLen(len(pb)))
	b.WriteString(sigPrefix)
	b.WriteString(sigEncoding.EncodeToString(sig))
	b.WriteByte(':')
	b.WriteString(sigEncoding.EncodeToString(pb))
	return b.String(), nil
}

// DecodeSigned parses the wire format back into the raw sig bytes and the
// decoded payload. It returns an error if the prefix is missing, if the
// envelope's two-colon shape is broken, if either base64 block is
// malformed, or if the JSON payload is malformed or missing a required
// field. DecodeSigned is strict: it does not tolerate surrounding
// whitespace.
//
// DecodeSigned does not verify the signature — that is the caller's job,
// so this function can be reused by anything that needs to read the
// envelope (velgate, audit tooling, tests).
func DecodeSigned(s string) (sig []byte, payload SigPayload, err error) {
	if !strings.HasPrefix(s, sigPrefix) {
		return nil, SigPayload{}, errors.New("missing VELGATE_SIG: prefix")
	}
	rest := s[len(sigPrefix):]
	sep := strings.IndexByte(rest, ':')
	if sep < 0 {
		return nil, SigPayload{}, errors.New("missing payload separator")
	}
	sigB64 := rest[:sep]
	payloadB64 := rest[sep+1:]
	if sigB64 == "" {
		return nil, SigPayload{}, errors.New("empty signature field")
	}
	if payloadB64 == "" {
		return nil, SigPayload{}, errors.New("empty payload field")
	}
	sig, err = sigEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, SigPayload{}, fmt.Errorf("decode signature: %w", err)
	}
	pb, err := sigEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, SigPayload{}, fmt.Errorf("decode payload: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.DisallowUnknownFields()
	var p SigPayload
	if err := dec.Decode(&p); err != nil {
		return nil, SigPayload{}, fmt.Errorf("unmarshal payload: %w", err)
	}
	if p.Cmd == "" {
		return nil, SigPayload{}, errors.New("payload missing required field: cmd")
	}
	return sig, p, nil
}

// IsSigned reports whether s starts with the literal "VELGATE_SIG:" prefix.
// It is a cheap pre-check intended for callers that route signed vs.
// unsigned commands down different paths before incurring the cost of a
// full DecodeSigned call.
func IsSigned(s string) bool {
	return strings.HasPrefix(s, sigPrefix)
}
