package gate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/gate"
)

// signedLine signs a SigPayload with priv and returns the wire string
// produced by sigwire.EncodeSigned. Test helper — not for production use.
func signedLine(t *testing.T, priv ed25519.PrivateKey, p sigwire.SigPayload) string {
	t.Helper()
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, pb)
	line, err := sigwire.EncodeSigned(sig, p)
	if err != nil {
		t.Fatalf("encode signed: %v", err)
	}
	return line
}

// genKey returns a fresh Ed25519 keypair using crypto/rand.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestVerifySigned(t *testing.T) {
	pub, priv := genKey(t)
	otherPub, _ := genKey(t)
	_ = otherPub

	now := time.Unix(1_700_000_000, 0)

	mkPayload := func(cmd string, ts, exp time.Time) sigwire.SigPayload {
		return sigwire.SigPayload{
			Cmd:   cmd,
			TS:    ts.Unix(),
			Exp:   exp.Unix(),
			Nonce: "nonce-abc",
		}
	}

	t.Run("valid signed read", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-10*time.Second), now.Add(60*time.Second))
		line := signedLine(t, priv, p)
		inner, err := gate.VerifySigned(line, pub, now)
		if err != nil {
			t.Fatalf("VerifySigned returned err=%v, want nil", err)
		}
		if inner != "df -h" {
			t.Errorf("inner = %q, want %q", inner, "df -h")
		}
	})

	t.Run("valid signed write", func(t *testing.T) {
		p := mkPayload("systemctl restart nginx", now.Add(-5*time.Second), now.Add(60*time.Second))
		line := signedLine(t, priv, p)
		inner, err := gate.VerifySigned(line, pub, now)
		if err != nil {
			t.Fatalf("VerifySigned returned err=%v, want nil", err)
		}
		if inner != "systemctl restart nginx" {
			t.Errorf("inner = %q, want write cmd", inner)
		}
	})

	t.Run("expired", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-120*time.Second), now.Add(-1*time.Second))
		line := signedLine(t, priv, p)
		_, err := gate.VerifySigned(line, pub, now)
		if !errors.Is(err, gate.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("exp equal to now is expired", func(t *testing.T) {
		// exp == now: token is no longer valid (now >= exp).
		p := mkPayload("df -h", now.Add(-60*time.Second), now)
		line := signedLine(t, priv, p)
		_, err := gate.VerifySigned(line, pub, now)
		if !errors.Is(err, gate.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("validity window too long", func(t *testing.T) {
		// exp - ts = 10 minutes > MaxSigValidity (5 min)
		p := mkPayload("df -h", now, now.Add(sigwire.MaxSigValidity+1*time.Second))
		line := signedLine(t, priv, p)
		_, err := gate.VerifySigned(line, pub, now)
		if !errors.Is(err, gate.ErrValidityTooLong) {
			t.Fatalf("err = %v, want ErrValidityTooLong", err)
		}
	})

	t.Run("validity window at the edge is accepted", func(t *testing.T) {
		// exp - ts == MaxSigValidity exactly is fine
		p := mkPayload("df -h", now, now.Add(sigwire.MaxSigValidity))
		line := signedLine(t, priv, p)
		inner, err := gate.VerifySigned(line, pub, now)
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if inner != "df -h" {
			t.Errorf("inner = %q", inner)
		}
	})

	t.Run("tampered cmd", func(t *testing.T) {
		// Sign one payload, then re-encode with a different cmd. Same
		// sig on different payload bytes -> verify must fail.
		p := mkPayload("df -h", now.Add(-1*time.Second), now.Add(60*time.Second))
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(priv, pb)
		// Build a tampered payload object with a different cmd.
		tampered := p
		tampered.Cmd = "rm -rf /"
		line, err := sigwire.EncodeSigned(sig, tampered)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = gate.VerifySigned(line, pub, now)
		if !errors.Is(err, gate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("bad sig bytes (right length, wrong content)", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-1*time.Second), now.Add(60*time.Second))
		// Sign with the WRONG key, then submit under the right pubkey.
		_, otherPriv := genKey(t)
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(otherPriv, pb)
		line, err := sigwire.EncodeSigned(sig, p)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = gate.VerifySigned(line, pub, now)
		if !errors.Is(err, gate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("wrong key entirely", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-1*time.Second), now.Add(60*time.Second))
		line := signedLine(t, priv, p)
		// Verify with otherPub (a different key).
		_, err := gate.VerifySigned(line, otherPub, now)
		if !errors.Is(err, gate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("empty cmd in payload", func(t *testing.T) {
		// sigwire.DecodeSigned rejects empty cmd at the wire layer; we
		// expect VerifySigned to surface that as ErrBadFormat (the wire
		// envelope is malformed) — payload-level empty-cmd would surface
		// as ErrEmptyCmd if DecodeSigned didn't catch it. Either is
		// acceptable so long as the call fails; we accept both.
		p := sigwire.SigPayload{
			Cmd:   "",
			TS:    now.Add(-1 * time.Second).Unix(),
			Exp:   now.Add(60 * time.Second).Unix(),
			Nonce: "nonce-abc",
		}
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(priv, pb)
		line, err := sigwire.EncodeSigned(sig, p)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = gate.VerifySigned(line, pub, now)
		if err == nil {
			t.Fatalf("err = nil, want some error")
		}
		if !errors.Is(err, gate.ErrBadFormat) && !errors.Is(err, gate.ErrEmptyCmd) {
			t.Fatalf("err = %v, want ErrBadFormat or ErrEmptyCmd", err)
		}
	})

	t.Run("non-SSHGATE_SIG prefix returns ErrBadFormat", func(t *testing.T) {
		_, err := gate.VerifySigned("df -h", pub, now)
		if !errors.Is(err, gate.ErrBadFormat) {
			t.Fatalf("err = %v, want ErrBadFormat", err)
		}
	})

	t.Run("malformed envelope returns ErrBadFormat", func(t *testing.T) {
		// Prefix is right but body is junk.
		_, err := gate.VerifySigned("SSHGATE_SIG:not-base64::also-not", pub, now)
		if !errors.Is(err, gate.ErrBadFormat) {
			t.Fatalf("err = %v, want ErrBadFormat", err)
		}
	})

	t.Run("error strings are lowercase", func(t *testing.T) {
		// go.md §1.3: lowercase, no trailing punctuation.
		for _, e := range []error{
			gate.ErrBadFormat,
			gate.ErrBadSig,
			gate.ErrExpired,
			gate.ErrValidityTooLong,
			gate.ErrEmptyCmd,
		} {
			m := e.Error()
			if m == "" {
				t.Errorf("error message is empty for %v", e)
				continue
			}
			if strings.ToLower(m[:1]) != m[:1] {
				t.Errorf("error %q starts with uppercase letter", m)
			}
			if strings.HasSuffix(m, ".") {
				t.Errorf("error %q ends with period", m)
			}
		}
	})
}

// TestVerifySigned_ValidityOverflow pins the int64-overflow class of TTL
// bypass at the gate. The pre-fix gate computed the window as
// time.Duration(exp-ts)*time.Second and compared against MaxSigValidity.
// time.Duration is int64 NANOSECONDS, so a window beyond ~9.2e9 seconds
// overflowed NEGATIVE and sailed under the cap — letting a single signed
// (or signer-minted) envelope live for ~290 billion years. The gate is the
// authoritative cap, so it MUST reject these regardless of what the signer
// produced. Each row asserts refusal (never a returned inner cmd).
func TestVerifySigned_ValidityOverflow(t *testing.T) {
	pub, priv := genKey(t)
	now := time.Unix(1_700_000_000, 0)
	nowUnix := now.Unix()

	const maxInt64 = int64(9223372036854775807)

	cases := []struct {
		name    string
		ts, exp int64
		wantErr error
	}{
		{
			// window 9.3e9s: Duration(exp-ts)*Second overflows int64-ns
			// negative; pre-fix this was ACCEPTED.
			name: "window just past the int64-nanosecond overflow point",
			ts:   nowUnix, exp: nowUnix + 9_300_000_000,
			wantErr: gate.ErrValidityTooLong,
		},
		{
			name: "exp pinned at MaxInt64",
			ts:   nowUnix, exp: maxInt64,
			wantErr: gate.ErrValidityTooLong,
		},
		{
			// huge gap AND a negative ts — the subtraction itself would
			// overflow if the ts<=0 guard didn't fire first.
			name: "negative ts widening the window",
			ts:   -100, exp: maxInt64,
			wantErr: gate.ErrBadFormat,
		},
		{
			name: "ts zero",
			ts:   0, exp: nowUnix + 60,
			wantErr: gate.ErrBadFormat,
		},
		{
			name: "exp not greater than ts (zero window)",
			ts:   nowUnix, exp: nowUnix,
			wantErr: gate.ErrBadFormat,
		},
		{
			name: "exp less than ts (negative window)",
			ts:   nowUnix, exp: nowUnix - 100,
			wantErr: gate.ErrBadFormat,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := sigwire.SigPayload{Cmd: "rm -rf /data", TS: tc.ts, Exp: tc.exp, Nonce: "n-overflow"}
			line := signedLine(t, priv, p)
			inner, err := gate.VerifySigned(line, pub, now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifySigned err = %v; want %v", err, tc.wantErr)
			}
			if inner != "" {
				t.Errorf("inner cmd = %q; want empty string on rejection (no command may leak through)", inner)
			}
		})
	}
}
