package main

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestSignTimeoutOutlastsSignerHandler pins the fix for the 2026-07-01
// verdict-undelivered incident. The MCP sign client's total per-request
// budget (signTimeout, wired into the sign client in buildServer) MUST
// outlast the signer's whole connection handler — and therefore the full
// human approval window — or the client abandons the socket mid-approval
// and a decided verdict (approve OR deny) is stranded as an opaque
// "verdict undelivered" i/o timeout. The original bug was a hardcoded 75s
// budget against a 5-minute approval window, so the client gave up ~4
// minutes early on every slow tap. The budget must be sourced from the
// single sigwire source of truth, never a hand-rolled literal, so the four
// timeouts can never silently drift again.
func TestSignTimeoutOutlastsSignerHandler(t *testing.T) {
	t.Parallel()
	if signTimeout < sigwire.SignerHandlerTimeout {
		t.Fatalf("signTimeout(%v) < sigwire.SignerHandlerTimeout(%v); the MCP client must outlive the signer's connection handler so an approved (or denied) verdict is delivered, not stranded as verdict-undelivered",
			signTimeout, sigwire.SignerHandlerTimeout)
	}
	if signTimeout != sigwire.ClientSignTimeout {
		t.Errorf("signTimeout(%v) != sigwire.ClientSignTimeout(%v); the client budget must be sourced from sigwire's single source of truth, not a separate literal, so ClientSignTimeout > SignerHandlerTimeout > ApprovalWindow can never drift",
			signTimeout, sigwire.ClientSignTimeout)
	}
}

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
