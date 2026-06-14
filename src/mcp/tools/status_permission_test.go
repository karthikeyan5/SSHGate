package tools

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestProbeSignerSocket_PermissionDenied pins that an EACCES dial on a socket
// that EXISTS is reported as a permission problem (group not active), not a
// generic unreachable/dead-daemon — the distinction drives the right
// remediation (re-login + relaunch vs systemctl).
func TestProbeSignerSocket_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses unix-socket permission checks; need a non-root euid")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "signer.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer l.Close()
	// 0000 => even the owner cannot connect (EACCES), while the socket file
	// still exists so Configured stays true.
	if err := os.Chmod(sock, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	s := probeSignerSocket(context.Background(), sock)

	if !s.Configured {
		t.Errorf("Configured = false; the socket file exists, want true")
	}
	if s.Reachable {
		t.Errorf("Reachable = true; want false on a permission-denied dial")
	}
	if !s.Permission {
		t.Errorf("Permission = false; want true for EACCES on an existing socket (Error=%q)", s.Error)
	}
}
