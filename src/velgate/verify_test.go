package velgate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/common"
	"github.com/karthikeyan5/sshgate/src/velgate"
)

// signedLine signs a SigPayload with priv and returns the wire string
// produced by common.EncodeSigned. Test helper — not for production use.
func signedLine(t *testing.T, priv ed25519.PrivateKey, p common.SigPayload) string {
	t.Helper()
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig := ed25519.Sign(priv, pb)
	line, err := common.EncodeSigned(sig, p)
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

	mkPayload := func(cmd string, ts, exp time.Time) common.SigPayload {
		return common.SigPayload{
			Cmd:   cmd,
			TS:    ts.Unix(),
			Exp:   exp.Unix(),
			Nonce: "nonce-abc",
		}
	}

	t.Run("valid signed read", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-10*time.Second), now.Add(60*time.Second))
		line := signedLine(t, priv, p)
		inner, err := velgate.VerifySigned(line, pub, now)
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
		inner, err := velgate.VerifySigned(line, pub, now)
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
		_, err := velgate.VerifySigned(line, pub, now)
		if !errors.Is(err, velgate.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("exp equal to now is expired", func(t *testing.T) {
		// exp == now: token is no longer valid (now >= exp).
		p := mkPayload("df -h", now.Add(-60*time.Second), now)
		line := signedLine(t, priv, p)
		_, err := velgate.VerifySigned(line, pub, now)
		if !errors.Is(err, velgate.ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})

	t.Run("validity window too long", func(t *testing.T) {
		// exp - ts = 10 minutes > MaxSigValidity (5 min)
		p := mkPayload("df -h", now, now.Add(common.MaxSigValidity+1*time.Second))
		line := signedLine(t, priv, p)
		_, err := velgate.VerifySigned(line, pub, now)
		if !errors.Is(err, velgate.ErrValidityTooLong) {
			t.Fatalf("err = %v, want ErrValidityTooLong", err)
		}
	})

	t.Run("validity window at the edge is accepted", func(t *testing.T) {
		// exp - ts == MaxSigValidity exactly is fine
		p := mkPayload("df -h", now, now.Add(common.MaxSigValidity))
		line := signedLine(t, priv, p)
		inner, err := velgate.VerifySigned(line, pub, now)
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
		line, err := common.EncodeSigned(sig, tampered)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = velgate.VerifySigned(line, pub, now)
		if !errors.Is(err, velgate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("bad sig bytes (right length, wrong content)", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-1*time.Second), now.Add(60*time.Second))
		// Sign with the WRONG key, then submit under the right pubkey.
		_, otherPriv := genKey(t)
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(otherPriv, pb)
		line, err := common.EncodeSigned(sig, p)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = velgate.VerifySigned(line, pub, now)
		if !errors.Is(err, velgate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("wrong key entirely", func(t *testing.T) {
		p := mkPayload("df -h", now.Add(-1*time.Second), now.Add(60*time.Second))
		line := signedLine(t, priv, p)
		// Verify with otherPub (a different key).
		_, err := velgate.VerifySigned(line, otherPub, now)
		if !errors.Is(err, velgate.ErrBadSig) {
			t.Fatalf("err = %v, want ErrBadSig", err)
		}
	})

	t.Run("empty cmd in payload", func(t *testing.T) {
		// common.DecodeSigned rejects empty cmd at the wire layer; we
		// expect VerifySigned to surface that as ErrBadFormat (the wire
		// envelope is malformed) — payload-level empty-cmd would surface
		// as ErrEmptyCmd if DecodeSigned didn't catch it. Either is
		// acceptable so long as the call fails; we accept both.
		p := common.SigPayload{
			Cmd:   "",
			TS:    now.Add(-1 * time.Second).Unix(),
			Exp:   now.Add(60 * time.Second).Unix(),
			Nonce: "nonce-abc",
		}
		pb, _ := json.Marshal(p)
		sig := ed25519.Sign(priv, pb)
		line, err := common.EncodeSigned(sig, p)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, err = velgate.VerifySigned(line, pub, now)
		if err == nil {
			t.Fatalf("err = nil, want some error")
		}
		if !errors.Is(err, velgate.ErrBadFormat) && !errors.Is(err, velgate.ErrEmptyCmd) {
			t.Fatalf("err = %v, want ErrBadFormat or ErrEmptyCmd", err)
		}
	})

	t.Run("non-VELGATE_SIG prefix returns ErrBadFormat", func(t *testing.T) {
		_, err := velgate.VerifySigned("df -h", pub, now)
		if !errors.Is(err, velgate.ErrBadFormat) {
			t.Fatalf("err = %v, want ErrBadFormat", err)
		}
	})

	t.Run("malformed envelope returns ErrBadFormat", func(t *testing.T) {
		// Prefix is right but body is junk.
		_, err := velgate.VerifySigned("VELGATE_SIG:not-base64::also-not", pub, now)
		if !errors.Is(err, velgate.ErrBadFormat) {
			t.Fatalf("err = %v, want ErrBadFormat", err)
		}
	})

	t.Run("error strings are lowercase", func(t *testing.T) {
		// go.md §1.3: lowercase, no trailing punctuation.
		for _, e := range []error{
			velgate.ErrBadFormat,
			velgate.ErrBadSig,
			velgate.ErrExpired,
			velgate.ErrValidityTooLong,
			velgate.ErrEmptyCmd,
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
