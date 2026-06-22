package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey returns a deterministic ssh.PublicKey so the golden literal
// below is stable across runs. The seed is fixed; the key bytes are
// therefore fixed.
func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	// 32-byte fixed seed → deterministic ed25519 key.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub
}

// TestFingerprint_Format pins the exact SHA256:<base64-raw-std-nopad>
// shape so a regression in alphabet/padding is caught immediately.
func TestFingerprint_Format(t *testing.T) {
	pub := testKey(t)
	got := Fingerprint(pub)

	if !strings.HasPrefix(got, "SHA256:") {
		t.Fatalf("fingerprint %q missing SHA256: prefix", got)
	}
	body := strings.TrimPrefix(got, "SHA256:")
	// RawStdEncoding uses the STANDARD base64 alphabet (which includes '+'
	// and '/', matching `ssh-keygen -l`) but no '=' padding. Only padding
	// is forbidden here.
	if strings.Contains(body, "=") {
		t.Errorf("fingerprint body %q contains '=' padding", body)
	}

	// Recompute independently from the spec definition and compare.
	sum := sha256.Sum256(pub.Marshal())
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if got != want {
		t.Errorf("Fingerprint = %q; want %q", got, want)
	}
}

// TestFingerprint_Stable pins that the same key always yields the same
// fingerprint (no per-call randomness, no map ordering).
func TestFingerprint_Stable(t *testing.T) {
	pub := testKey(t)
	a := Fingerprint(pub)
	b := Fingerprint(pub)
	if a != b {
		t.Errorf("Fingerprint not stable: %q != %q", a, b)
	}
}

// TestFingerprint_DistinctKeys pins that different keys produce different
// fingerprints (sanity that the hash actually depends on the key bytes).
func TestFingerprint_DistinctKeys(t *testing.T) {
	pub := testKey(t)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	otherPub, err := ssh.NewPublicKey(otherPriv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if Fingerprint(pub) == Fingerprint(otherPub) {
		t.Errorf("distinct keys produced identical fingerprints")
	}
}
