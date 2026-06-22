package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writePubFile writes an OpenSSH authorized_keys-format public key line for a
// fresh random ed25519 key into dir/name and returns its fingerprint.
func writePubFile(t *testing.T, dir, name string, mode os.FileMode) (path, fp string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := ssh.MarshalAuthorizedKey(sshPub) // "ssh-ed25519 AAAA...\n"
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, line, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path, Fingerprint(sshPub)
}

func TestLoadHostFingerprints_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	_, fp1 := writePubFile(t, dir, "ssh_host_ed25519_key.pub", 0o644)
	_, fp2 := writePubFile(t, dir, "ssh_host_rsa_key.pub", 0o644)
	_, fp3 := writePubFile(t, dir, "ssh_host_ecdsa_key.pub", 0o644)
	// A non-matching file in the same dir must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "ssh_config"), []byte("Host *\n"), 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}

	got, err := LoadHostFingerprintsFromGlob(filepath.Join(dir, "ssh_host_*.pub"))
	if err != nil {
		t.Fatalf("LoadHostFingerprintsFromGlob: %v", err)
	}
	want := []string{fp1, fp2, fp3}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d fingerprints, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fingerprint[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestLoadHostFingerprints_NoneMatchedIsEmptyNoError(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadHostFingerprintsFromGlob(filepath.Join(dir, "ssh_host_*.pub"))
	if err != nil {
		t.Fatalf("LoadHostFingerprintsFromGlob over empty dir errored: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d fingerprints over empty dir, want 0", len(got))
	}
}

// TestLoadHostFingerprints_SkipsUnparseable pins that a malformed .pub file
// does not abort the whole load — the gate must still derive fingerprints
// from the host keys it CAN parse (an unreadable/garbage file alongside good
// ones should not fail every write). The bad file is simply skipped.
func TestLoadHostFingerprints_SkipsUnparseable(t *testing.T) {
	dir := t.TempDir()
	_, fpGood := writePubFile(t, dir, "ssh_host_ed25519_key.pub", 0o644)
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_rsa_key.pub"), []byte("not a key\n"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	got, err := LoadHostFingerprintsFromGlob(filepath.Join(dir, "ssh_host_*.pub"))
	if err != nil {
		t.Fatalf("LoadHostFingerprintsFromGlob: %v", err)
	}
	if len(got) != 1 || got[0] != fpGood {
		t.Errorf("got %v; want exactly [%q]", got, fpGood)
	}
}
