package gate_test

import (
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestVerifySigned_RevealFlagPropagates pins that the verified reveal flag is
// surfaced by VerifySigned exactly as it was signed — true when the signed
// payload set it, false otherwise. Reveal is the signed capability that lets a
// single command's output bypass the redactor; the gate must read it from the
// authenticated payload (never from the agent), so it is returned alongside the
// inner cmd only after signature + time + host checks pass.
func TestVerifySigned_RevealFlagPropagates(t *testing.T) {
	pub, priv := genKey(t)
	now := time.Unix(1_700_000_000, 0)

	mk := func(reveal bool) sigwire.SigPayload {
		return sigwire.SigPayload{
			Cmd:    "cat /etc/secret.env",
			TS:     now.Add(-5 * time.Second).Unix(),
			Exp:    now.Add(60 * time.Second).Unix(),
			Nonce:  "nonce-reveal",
			Host:   hostFP,
			Reveal: reveal,
		}
	}

	t.Run("reveal=true is surfaced", func(t *testing.T) {
		line := signedLine(t, priv, mk(true))
		inner, reveal, err := gate.VerifySigned(line, pub, now, hostAny)
		if err != nil {
			t.Fatalf("VerifySigned err = %v, want nil", err)
		}
		if inner != "cat /etc/secret.env" {
			t.Errorf("inner = %q", inner)
		}
		if !reveal {
			t.Errorf("reveal = false; want true (the signed flag must propagate)")
		}
	})

	t.Run("reveal=false is surfaced", func(t *testing.T) {
		line := signedLine(t, priv, mk(false))
		inner, reveal, err := gate.VerifySigned(line, pub, now, hostAny)
		if err != nil {
			t.Fatalf("VerifySigned err = %v, want nil", err)
		}
		if inner != "cat /etc/secret.env" {
			t.Errorf("inner = %q", inner)
		}
		if reveal {
			t.Errorf("reveal = true; want false")
		}
	})

	t.Run("reveal is not surfaced on a rejected (host-mismatch) payload", func(t *testing.T) {
		// A reveal=true payload bound to ANOTHER host must be refused; the
		// returned reveal flag is the zero value and no command leaks through.
		p := mk(true)
		p.Host = "SHA256:someOtherServerHostKeyFingerprintZZZZZZZZZZ"
		line := signedLine(t, priv, p)
		inner, reveal, err := gate.VerifySigned(line, pub, now, []string{hostFP})
		if err == nil {
			t.Fatalf("err = nil; want rejection for cross-host reveal")
		}
		if inner != "" {
			t.Errorf("inner = %q; want empty on rejection", inner)
		}
		if reveal {
			t.Errorf("reveal = true on a rejected payload; want false (no capability leaks through a failed verify)")
		}
	})
}
