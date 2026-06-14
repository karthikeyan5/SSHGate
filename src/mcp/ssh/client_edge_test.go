package ssh_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
)

// TestClient_Run_EmptyArgsValidation asserts the cheap input guards in
// Client.Run fire before any dial: empty KeyPath, empty KnownHostsPath,
// empty host, and empty user each return an error without touching the
// network (no sudo / no network needed).
func TestClient_Run_EmptyArgsValidation(t *testing.T) {
	t.Parallel()
	keyPath, _ := generateClientKey(t)
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	tests := []struct {
		name     string
		client   *sshpkg.Client
		host     string
		user     string
		port     int
		wantSub  string
	}{
		{
			name:    "empty KeyPath",
			client:  &sshpkg.Client{KeyPath: "", KnownHostsPath: khPath, Timeout: time.Second},
			host:    "h", user: "u", port: 22,
			wantSub: "KeyPath is empty",
		},
		{
			name:    "empty KnownHostsPath",
			client:  &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: "", Timeout: time.Second},
			host:    "h", user: "u", port: 22,
			wantSub: "KnownHostsPath is empty",
		},
		{
			name:    "empty host",
			client:  &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: time.Second},
			host:    "", user: "u", port: 22,
			wantSub: "host is empty",
		},
		{
			name:    "empty user",
			client:  &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: time.Second},
			host:    "h", user: "", port: 22,
			wantSub: "user is empty",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, err := tc.client.Run(context.Background(), tc.host, tc.user, tc.port, "echo")
			if err == nil {
				t.Fatalf("Run returned nil; want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestClient_Run_InsecureKeyModeRejected asserts loadKey (via Run)
// refuses a private key whose permissions carry any group/world bit
// (mode & 0o077 != 0) — matching SSH's own client expectation that a
// private key must be 0600. We skip when running as root because the
// key file is then owned by root and the mode check still fires, but to
// be safe we assert on the error path that is exercised regardless.
func TestClient_Run_InsecureKeyModeRejected(t *testing.T) {
	t.Parallel()
	keyPath, _ := generateClientKey(t)
	// generateClientKey wrote 0o600; loosen to 0o640 (group-readable) so
	// 0o077 mask trips.
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: file ownership/perm semantics differ")
	}
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: time.Second}
	_, _, _, err := c.Run(context.Background(), "127.0.0.1", "u", 22, "echo")
	if err == nil {
		t.Fatal("Run with 0640 key returned nil; want insecure-mode error")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Errorf("err = %q; want substring %q", err.Error(), "insecure mode")
	}
}

// TestClient_Run_ExitMissingErrorMapsToMinusOne asserts that when the
// remote tears the session down WITHOUT sending an exit-status (i.e. it
// was killed by a signal), Client.Run maps the resulting
// *ssh.ExitMissingError to exit=-1 and a nil error, surfacing whatever
// stdout/stderr arrived. Uses the exitNoStatus sentinel handled by the
// in-process test server.
func TestClient_Run_ExitMissingErrorMapsToMinusOne(t *testing.T) {
	t.Parallel()
	keyPath, pub := generateClientKey(t)
	srv := newTestServer(t, pub, func(cmd string) ([]byte, []byte, int) {
		return []byte("partial-out\n"), nil, exitNoStatus
	})
	defer srv.stop()

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	c := &sshpkg.Client{KeyPath: keyPath, KnownHostsPath: khPath, Timeout: 5 * time.Second}
	stdout, _, exit, err := c.Run(context.Background(), srv.host, "tester", srv.port, "killed-by-signal")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if exit != -1 {
		t.Errorf("exit = %d; want -1 (signal-terminated)", exit)
	}
	if string(stdout) != "partial-out\n" {
		t.Errorf("stdout = %q; want partial output preserved", stdout)
	}
}
