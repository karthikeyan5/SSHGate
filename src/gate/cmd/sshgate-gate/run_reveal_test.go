package main

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// awsKey is an AWS access-key-shaped string the production redaction ruleset
// (redactrules.Combined()) catches. We echo it from the child so the e2e path
// exercises the real redactor wired into execChild.
const awsKey = "AKIA1234567890ABCDEF"

// TestRunReveal_SignedRevealRawVsRedacted is the end-to-end pin for
// SECRET-REVEAL at the gate boundary:
//
//   - a signed command with reveal=true → the child's secret-bearing output
//     reaches stdout RAW (no redaction marker);
//   - the SAME command signed with reveal=false → the secret is redacted;
//   - an UNSIGNED read of the same command is NEVER revealed (redacted),
//     because reveal can only be set on the signed, verified path.
//
// This is the whole security contract in one test: reveal is signed-only, and
// without the signed flag the redactor always runs.
func TestRunReveal_SignedRevealRawVsRedacted(t *testing.T) {
	t.Run("signed reveal=true -> raw secret passes through", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		p := freshPayload("echo " + awsKey)
		p.Reveal = true
		line := signedLine(t, priv, p)
		code, out, _ := runWith(t, line)
		if code != exitOK {
			t.Errorf("exit = %d, want %d", code, exitOK)
		}
		if !strings.Contains(out, awsKey) {
			t.Errorf("reveal=true must pass the raw secret through; got %q", out)
		}
		if strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("reveal=true wrongly redacted: %q", out)
		}
	})

	t.Run("signed reveal=false -> secret is redacted", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)

		p := freshPayload("echo " + awsKey)
		p.Reveal = false
		line := signedLine(t, priv, p)
		code, out, _ := runWith(t, line)
		if code != exitOK {
			t.Errorf("exit = %d, want %d", code, exitOK)
		}
		if strings.Contains(out, awsKey) {
			t.Errorf("reveal=false leaked the secret: %q", out)
		}
		if !strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("reveal=false should have redacted; got %q", out)
		}
	})

	t.Run("UNSIGNED read is never revealed (redacted) in Tier-1 read-only mode", func(t *testing.T) {
		// No gate.pub seeded -> Tier-1 read-only mode; an unsigned read runs
		// but can NEVER carry reveal=true (the agent cannot self-elevate).
		dir := t.TempDir()
		withGateDir(t, dir)

		code, out, _ := runWith(t, "echo "+awsKey)
		if code != exitOK {
			t.Errorf("exit = %d, want %d", code, exitOK)
		}
		if strings.Contains(out, awsKey) {
			t.Errorf("unsigned read must be redacted; secret leaked: %q", out)
		}
		if !strings.Contains(out, redact.MarkerPrefix) {
			t.Errorf("unsigned read should be redacted; got %q", out)
		}
	})
}

// TestRunReveal_RevealRequiresSignature pins that the reveal capability cannot
// be smuggled in unsigned. With a gate.pub present (Tier-2), an UNSIGNED read
// of a secret-bearing command is redacted — there is no way to express reveal
// without a signature, so the redactor always runs on the unsigned path.
func TestRunReveal_RevealRequiresSignature(t *testing.T) {
	dir := t.TempDir()
	pub, _ := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	// An unsigned read (cat-like) reaches execChild with reveal=false always.
	code, out, _ := runWith(t, "echo "+awsKey)
	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
	if strings.Contains(out, awsKey) {
		t.Errorf("unsigned read leaked secret (reveal must be signed-only): %q", out)
	}
	if !strings.Contains(out, redact.MarkerPrefix) {
		t.Errorf("unsigned read should be redacted; got %q", out)
	}
}

// TestRunReveal_TamperedRevealRejected pins that reveal cannot be smuggled in
// by tampering: signing a reveal=false payload and then flipping the bit to
// reveal=true on the wire invalidates the signature (the bool is in the signed
// bytes), so the gate rejects it (exit 65) and never runs un-redacted. This is
// the self-elevation guard — the agent cannot turn a normal approval into a
// reveal.
func TestRunReveal_TamperedRevealRejected(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	// Sign reveal=false, then re-encode the SAME signature over a payload whose
	// Reveal bit is flipped to true.
	p := freshPayload("echo " + awsKey)
	p.Reveal = false
	pb, _ := json.Marshal(p)
	sig := ed25519.Sign(priv, pb)
	tampered := p
	tampered.Reveal = true
	line, err := sigwire.EncodeSigned(sig, tampered)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	code, out, _ := runWith(t, line)
	if code != exitDataErr {
		t.Errorf("exit = %d, want %d (flipped reveal bit must fail signature verification)", code, exitDataErr)
	}
	// And crucially, the secret never escaped.
	if strings.Contains(out, awsKey) {
		t.Errorf("tampered reveal leaked the secret: %q", out)
	}
}
