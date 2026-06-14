package main

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildServer_InsecureKnownHostsAborts asserts that buildServer
// refuses to start when an existing known_hosts file carries group/world
// permission bits (looser than 0600). A world-writable pin store is a
// MITM hole — an attacker who can edit it can swap a host key — so
// startup must fail closed, mirroring the SSH-key invariant. Skipped
// under root, whose perm checks differ.
func TestBuildServer_InsecureKnownHostsAborts(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: file permission bits do not gate access")
	}
	cfgRoot := t.TempDir()
	khPath := filepath.Join(cfgRoot, "known_hosts")
	if err := os.WriteFile(khPath, []byte("example.com ssh-ed25519 AAAA...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Loosen to group+world readable/writable (0666) — must trip the
	// requireFileIfExists(khPath, 0o600) guard.
	if err := os.Chmod(khPath, 0o666); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "test: ", 0)
	_, err := buildServer(cfgRoot, "/tmp/sshgate-test.sock", logger)
	if err == nil {
		t.Fatal("buildServer with 0666 known_hosts = nil; want abort (security invariant)")
	}
}

// TestBuildServer_SecureKnownHostsSucceeds asserts that a 0600
// known_hosts file (the mode TOFU writes) does NOT block startup — the
// invariant rejects only loose modes, not a correctly-permissioned pin
// store.
func TestBuildServer_SecureKnownHostsSucceeds(t *testing.T) {
	t.Parallel()
	cfgRoot := t.TempDir()
	khPath := filepath.Join(cfgRoot, "known_hosts")
	if err := os.WriteFile(khPath, []byte("example.com ssh-ed25519 AAAA...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := log.New(os.Stderr, "test: ", 0)
	srv, err := buildServer(cfgRoot, "/tmp/sshgate-test.sock", logger)
	if err != nil {
		t.Fatalf("buildServer with 0600 known_hosts = %v; want nil", err)
	}
	if srv == nil {
		t.Fatal("buildServer returned nil server; want non-nil")
	}
}
