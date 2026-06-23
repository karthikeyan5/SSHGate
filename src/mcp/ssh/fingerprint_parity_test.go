package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/hostkey"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// TestFingerprintParity is the MANDATORY parity lock between the gate-side
// fingerprint (src/hostkey.Fingerprint, used by the gate to self-derive its
// own host-key fingerprint) and the MCP-side fingerprint
// (src/mcp/ssh.Fingerprint, used by provision to pin the value into the
// registry). The signed payload's Host field is set from the MCP-side value
// and enforced against the gate-side value: if these two ever diverge by a
// single byte, every signed write would be silently rejected at the gate
// (ErrHostMismatch). This test makes that drift loud.
//
// It compares both for several keys: a fixed-seed key (golden-style) and a
// batch of random keys (fuzz-style).
func TestFingerprintParity(t *testing.T) {
	keys := []gossh.PublicKey{fixedSeedKey(t)}
	for i := 0; i < 8; i++ {
		keys = append(keys, randomKey(t))
	}

	for i, k := range keys {
		mcpFP := sshpkg.Fingerprint(k)
		gateFP := hostkey.Fingerprint(k)
		if mcpFP != gateFP {
			t.Errorf("key #%d: MCP-side Fingerprint %q != gate-side Fingerprint %q (a divergence here silently rejects every write)", i, mcpFP, gateFP)
		}
		if mcpFP == "" {
			t.Errorf("key #%d: empty fingerprint", i)
		}
	}
}

func fixedSeedKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, err := gossh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub
}

func randomKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	pubEd, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := gossh.NewPublicKey(pubEd)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub
}
