package tools_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"golang.org/x/crypto/ssh"
)

// These tests exercise AddServer's SEAM-FREE pre-flight guards — every
// case here returns BEFORE any network dial. The full bootstrap flow
// (happy / rollback / idempotent / upgrade) is covered as white-box tests
// in add_server_bootstrap_test.go via the newBootstrapSession seam.

// addServerMaterials writes the three local files AddServer reads up front
// (gate binary, gate.pub, sshgate dedicated SSH pubkey) into a temp dir and
// returns a populated AddServerConfig pointing at them. The sshgate pubkey
// is a real, parseable OpenSSH authorized-key line so ParseAuthorizedKey
// (which runs before any dial) succeeds.
func addServerMaterials(t *testing.T) tools.AddServerConfig {
	t.Helper()
	dir := t.TempDir()

	gateBin := filepath.Join(dir, "sshgate-gate-linux-amd64")
	if err := os.WriteFile(gateBin, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gatePub := filepath.Join(dir, "gate.pub")
	if err := os.WriteFile(gatePub, []byte("gate-signing-pubkey-bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sshgatePub := filepath.Join(dir, "sshgate_ed25519.pub")
	if err := os.WriteFile(sshgatePub, ssh.MarshalAuthorizedKey(sshPub), 0o644); err != nil {
		t.Fatal(err)
	}

	return tools.AddServerConfig{
		GateBinaryPath: gateBin,
		GatePubPath:    gatePub,
		SSHGatePubPath: sshgatePub,
	}
}

// writePrivKey writes a valid OpenSSH ed25519 private key at the given mode
// and returns its path.
func writePrivKey(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func emptyRegistry(t *testing.T) *registry.Servers {
	t.Helper()
	r, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestAddServer_BootstrapMethodExactlyOne asserts the "exactly one of
// bootstrap_key_path / bootstrap_agent" guard fires for BOTH the
// neither-set and both-set inputs, before any local file is read or any
// dial happens.
func TestAddServer_BootstrapMethodExactlyOne(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   tools.AddServerInput
	}{
		{
			name: "neither set",
			in:   tools.AddServerInput{Alias: "new", Host: "h.example.com", User: "u"},
		},
		{
			name: "both set",
			in: tools.AddServerInput{
				Alias: "new", Host: "h.example.com", User: "u",
				BootstrapAgent:   true,
				BootstrapKeyPath: "/some/key",
			},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ssh := &fakeSSH{}
			runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh}

			_, err := runner.AddServer(context.Background(), c.in)
			if err == nil {
				t.Fatal("AddServer = nil; want 'exactly one' rejection")
			}
			if !strings.Contains(err.Error(), "exactly one") {
				t.Errorf("err = %v; want 'exactly one of bootstrap_key_path or bootstrap_agent'", err)
			}
			if len(ssh.callHistory) != 0 {
				t.Error("SSH was used; the guard must fire before any dial")
			}
		})
	}
}

// TestAddServer_AliasAlreadyRegistered asserts a duplicate alias is
// rejected with an actionable "revoke_server first" message before any
// dial.
func TestAddServer_AliasAlreadyRegistered(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "dup", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(),
	})
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, SSH: ssh}

	_, err := runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:          "dup",
		Host:           "1.2.3.4",
		User:           "u",
		BootstrapAgent: true,
	})
	if err == nil {
		t.Fatal("AddServer with duplicate alias = nil; want error")
	}
	if !strings.Contains(err.Error(), "dup") || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err = %v; want 'already registered' naming the alias", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was used; the duplicate-alias guard must fire before any dial")
	}
}

// TestAddServer_BootstrapAgentEmptySocket asserts that bootstrap_agent=true
// with an empty $SSH_AUTH_SOCK is rejected. Local materials are present so
// the failure is unambiguously the agent socket, not a missing file.
func TestAddServer_BootstrapAgentEmptySocket(t *testing.T) {
	// Not parallel: mutates the process-wide SSH_AUTH_SOCK.
	t.Setenv("SSH_AUTH_SOCK", "")
	cfg := addServerMaterials(t)
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:          "new",
		Host:           "h.example.com",
		User:           "u",
		BootstrapAgent: true,
	})
	if err == nil {
		t.Fatal("AddServer (agent, empty SSH_AUTH_SOCK) = nil; want error")
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("err = %v; want mention of empty $SSH_AUTH_SOCK", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was used; the empty-agent guard must fire before any dial")
	}
}

// TestAddServer_InsecureBootstrapKeyRejected asserts a bootstrap key file
// with a group/other-accessible mode (0077 bits set) is refused.
func TestAddServer_InsecureBootstrapKeyRejected(t *testing.T) {
	t.Parallel()
	cfg := addServerMaterials(t)
	keyPath := writePrivKey(t, t.TempDir(), 0o644) // insecure
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:            "new",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: keyPath,
	})
	if err == nil {
		t.Fatal("AddServer (0644 bootstrap key) = nil; want insecure-mode rejection")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Errorf("err = %v; want an 'insecure mode' rejection", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was used; the insecure-key guard must fire before any dial")
	}
}

// TestAddServer_MissingBootstrapKeyRejected asserts a bootstrap key path
// pointing at a nonexistent file is refused with a clear message.
func TestAddServer_MissingBootstrapKeyRejected(t *testing.T) {
	t.Parallel()
	cfg := addServerMaterials(t)
	missing := filepath.Join(t.TempDir(), "no-such-key")
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:            "new",
		Host:             "h.example.com",
		User:             "u",
		BootstrapKeyPath: missing,
	})
	if err == nil {
		t.Fatal("AddServer (missing bootstrap key) = nil; want error")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("err = %v; want a 'does not exist' message", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was used; the missing-key guard must fire before any dial")
	}
}

// TestAddServer_MissingLocalMaterials asserts that each missing local file
// (gate binary, gate.pub, sshgate pubkey) surfaces the actionable
// readLocalFile error — naming the file kind and the remediation hint —
// before any dial. The table swaps ONE path to a nonexistent file per row
// while keeping the other two valid.
func TestAddServer_MissingLocalMaterials(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// mutate clears one path so readLocalFile fails on it.
		mutate       func(c *tools.AddServerConfig, missing string)
		wantContains []string
		// readOnly skips the gate.pub read entirely; used to prove the
		// gate.pub-missing case is GATED on tier-2 (not read in tier-1).
		readOnly bool
	}{
		{
			name:         "missing gate binary",
			mutate:       func(c *tools.AddServerConfig, missing string) { c.GateBinaryPath = missing },
			wantContains: []string{"gate binary", "not found"},
		},
		{
			name:         "missing gate.pub (tier-2)",
			mutate:       func(c *tools.AddServerConfig, missing string) { c.GatePubPath = missing },
			wantContains: []string{"gate signing public key", "not found"},
		},
		{
			name:         "missing sshgate pubkey",
			mutate:       func(c *tools.AddServerConfig, missing string) { c.SSHGatePubPath = missing },
			wantContains: []string{"SSHGate dedicated SSH public key", "not found"},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			cfg := addServerMaterials(t)
			missing := filepath.Join(t.TempDir(), "absent-file")
			c.mutate(&cfg, missing)

			ssh := &fakeSSH{}
			runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh, AddServerCfg: cfg}

			_, err := runner.AddServer(context.Background(), tools.AddServerInput{
				Alias:          "new",
				Host:           "h.example.com",
				User:           "u",
				BootstrapAgent: true, // never reached; file read fails first
				ReadOnly:       c.readOnly,
			})
			if err == nil {
				t.Fatalf("AddServer (%s) = nil; want readLocalFile error", c.name)
			}
			for _, sub := range c.wantContains {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("err = %v; want substring %q", err, sub)
				}
			}
			if len(ssh.callHistory) != 0 {
				t.Error("SSH was used; the missing-material guard must fire before any dial")
			}
		})
	}
}

// TestAddServer_ReadOnlySkipsGatePub asserts the tier-1 read-only path does
// NOT read gate.pub at all: a missing gate.pub must NOT abort an otherwise
// valid read-only add before the dial. We point gate.pub at a nonexistent
// file and verify the failure is NOT the gate.pub read (it proceeds to the
// agent-socket check instead).
func TestAddServer_ReadOnlySkipsGatePub(t *testing.T) {
	// Not parallel: mutates SSH_AUTH_SOCK.
	t.Setenv("SSH_AUTH_SOCK", "")
	cfg := addServerMaterials(t)
	cfg.GatePubPath = filepath.Join(t.TempDir(), "no-gate-pub") // absent
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: emptyRegistry(t), SSH: ssh, AddServerCfg: cfg}

	_, err := runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:          "new",
		Host:           "h.example.com",
		User:           "u",
		BootstrapAgent: true,
		ReadOnly:       true,
	})
	if err == nil {
		t.Fatal("AddServer (read-only) = nil; expected the empty-agent-socket error downstream")
	}
	// The gate.pub read was skipped, so we should hit the agent-socket
	// check, NOT a gate.pub "not found".
	if strings.Contains(err.Error(), "gate signing public key") {
		t.Errorf("err = %v; tier-1 read-only must NOT read gate.pub", err)
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("err = %v; want the downstream empty-agent-socket error", err)
	}
}
