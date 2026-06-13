package main

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildServer_KeylessStartup asserts that buildServer succeeds when
// the SSH key file does not exist (Tier-1 fresh install: /reload-plugins
// runs before /sshgate:setup).
func TestBuildServer_KeylessStartup(t *testing.T) {
	t.Parallel()
	cfgRoot := t.TempDir()
	logger := log.New(os.Stderr, "test: ", 0)

	srv, err := buildServer(cfgRoot, "/tmp/sshgate-test.sock", logger)
	if err != nil {
		t.Fatalf("buildServer with missing key = %v; want nil", err)
	}
	if srv == nil {
		t.Fatal("buildServer returned nil server; want non-nil")
	}
}

// TestBuildServer_InsecureKeyAborts asserts that buildServer returns an
// error when the SSH key file exists but has insecure permissions (0644).
// This is the security invariant: present-but-loose MUST abort startup.
func TestBuildServer_InsecureKeyAborts(t *testing.T) {
	t.Parallel()
	cfgRoot := t.TempDir()

	// Create the ssh/ sub-directory and write a dummy key with 0644.
	sshDir := filepath.Join(cfgRoot, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "sshgate_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy-key"), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "test: ", 0)
	_, err := buildServer(cfgRoot, "/tmp/sshgate-test.sock", logger)
	if err == nil {
		t.Fatal("buildServer with 0644 key = nil; want non-nil error (security invariant)")
	}
}

// TestBuildServer_SecureKeySucceeds asserts that buildServer succeeds
// when the SSH key file exists AND has the correct 0600 permissions.
func TestBuildServer_SecureKeySucceeds(t *testing.T) {
	t.Parallel()
	cfgRoot := t.TempDir()

	sshDir := filepath.Join(cfgRoot, "ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "sshgate_ed25519")
	if err := os.WriteFile(keyPath, []byte("dummy-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "test: ", 0)
	srv, err := buildServer(cfgRoot, "/tmp/sshgate-test.sock", logger)
	if err != nil {
		t.Fatalf("buildServer with 0600 key = %v; want nil", err)
	}
	if srv == nil {
		t.Fatal("buildServer returned nil server; want non-nil")
	}
}
