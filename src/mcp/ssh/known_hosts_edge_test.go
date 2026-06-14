package ssh_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// TestTOFU_CorruptKnownHostsErrors asserts that when the known_hosts
// file exists but is unparseable, the TOFU callback surfaces a load
// error rather than silently appending a duplicate or accepting blindly.
// A corrupt pin store must fail closed.
func TestTOFU_CorruptKnownHostsErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")
	// A line that knownhosts cannot parse (no valid key material).
	if err := os.WriteFile(khPath, []byte("this-is-not-a-valid-known-hosts-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := makeHostKey(t)
	cb := sshpkg.TOFU(khPath)
	err := cb("example.com:22", tcpAddr(), key)
	if err == nil {
		t.Fatal("TOFU on corrupt known_hosts returned nil; want error")
	}
	if !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("err = %q; want it to mention known_hosts", err.Error())
	}
}

// TestTOFU_StatPermissionDeniedErrors asserts that a stat failure that
// is NOT "file does not exist" (here: permission denied because the
// parent directory is unsearchable) is surfaced as an error rather than
// being mistaken for first-contact. Skipped under root, which bypasses
// the directory permission check.
func TestTOFU_StatPermissionDeniedErrors(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions do not block stat")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	khPath := filepath.Join(sub, "known_hosts")
	// Remove search/exec permission on the parent so stat(khPath) returns
	// EACCES (a non-ErrNotExist error).
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	key := makeHostKey(t)
	cb := sshpkg.TOFU(khPath)
	err := cb("example.com:22", tcpAddr(), key)
	if err == nil {
		t.Fatal("TOFU with unstatable known_hosts returned nil; want error")
	}
	if !strings.Contains(err.Error(), "stat known_hosts") &&
		!strings.Contains(err.Error(), "pin host key") {
		t.Errorf("err = %q; want a stat/pin failure, not silent accept", err.Error())
	}
}
