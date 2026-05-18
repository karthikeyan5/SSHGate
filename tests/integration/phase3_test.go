//go:build integration

// Phase-3 end-to-end test for SSHGate (task 3.4 / lock criterion for
// task 3.1).
//
// Boots a FRESH linuxserver/openssh-server container with NO velgate
// pre-installed, then exercises the real sshgate.add_server tool:
//
//   1. Success path. AddServer dials with the operator's bootstrap key
//      (the one the linuxserver image baked into authorized_keys),
//      uploads velgate + signing pubkey, rewrites authorized_keys to
//      gate the SSHGate dedicated key behind command="..." forcing,
//      verifies via the VELGATE_OK probe, registers the alias. Then
//      a plain `df -h` Runner.Run goes through and works.
//   2. Verify failure → rollback. We re-use the same fresh container
//      after tearing down between subtests, point AddServer at a
//      pubkey that won't actually let the sshgate key in, and assert
//      that authorized_keys is restored from the backup (the bootstrap
//      key still works) AND ~/.velgate/ no longer exists.
//   3. Idempotent re-add (different alias, already-restricted state) →
//      skip rewrite, return Idempotent=true, register the new alias.
//   4. Re-adding the same alias → "already registered" error.
//
// Goroutine leak check at the end mirrors Phases 1-2.
package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	sshlib "golang.org/x/crypto/ssh"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestPhase3AddServer_Success(t *testing.T) {
	// The linuxserver image bakes ONE pubkey into authorized_keys at
	// boot — call that the "bootstrap key" (operator's normal access).
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	// SSHGate-dedicated key (separate from bootstrap) — the auto-setup
	// rewrites authorized_keys for THIS pubkey.
	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)

	// Cross-compile velgate + generate signing keypair.
	velgateBin := buildVelgateLinux(t)
	_, velgatePub := generateVelgateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	sshClient := &sshpkg.Client{
		KeyPath:        dedicatedPriv,
		KnownHostsPath: khPath,
		Timeout:        15 * time.Second,
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{}, // not used by AddServer or by reads
		SSH:     sshClient,
		AddServerCfg: tools.AddServerConfig{
			VelgateBinaryPath: velgateBin,
			VelgatePubPath:    velgatePub,
			SSHGatePubPath:    dedicatedPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "test",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
	})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	if !out.VerifiedOK {
		t.Errorf("VerifiedOK=false; want true")
	}
	if out.Fingerprint == "" {
		t.Errorf("Fingerprint is empty; want a SHA256 capture")
	}
	if !strings.HasPrefix(out.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint=%q; want SHA256: prefix", out.Fingerprint)
	}
	if out.BinaryPath != "~/.velgate/velgate" {
		t.Errorf("BinaryPath=%q; want ~/.velgate/velgate", out.BinaryPath)
	}
	if out.Idempotent {
		t.Errorf("Idempotent=true on first add; want false")
	}
	// Registry now holds the alias.
	if _, ok := servers.Get("test"); !ok {
		t.Errorf("registry does not have 'test' after AddServer")
	}

	// Now run a read via the dedicated key — confirm velgate is in the
	// loop and routes the read through to /bin/sh -c successfully.
	rdOut, err := runner.Run(ctx, tools.RunInput{Alias: "test", Command: "df -h"})
	if err != nil {
		t.Fatalf("Runner.Run(df -h) after add: %v", err)
	}
	if rdOut.ExitCode != 0 {
		t.Errorf("df -h exit=%d; want 0 (stderr=%q)", rdOut.ExitCode, rdOut.Stderr)
	}
	if rdOut.Kind != "read" {
		t.Errorf("Kind=%q; want read", rdOut.Kind)
	}

	// Captured fingerprint should match what's now in known_hosts.
	if got := fingerprintFromKnownHosts(t, khPath); got != out.Fingerprint {
		t.Errorf("captured fingerprint=%q; known_hosts has %q", out.Fingerprint, got)
	}
}

func TestPhase3AddServer_VerifyFailureRollsBack(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	// Generate the SSHGate-dedicated key, but DELIBERATELY give
	// AddServer a DIFFERENT pubkey to put into authorized_keys. The
	// verify probe (which uses the dedicated key) won't authenticate,
	// triggering the rollback path.
	dedicatedPriv, _ := generateStandaloneSSHKey(t)
	_, wrongPub := generateStandaloneSSHKey(t)

	velgateBin := buildVelgateLinux(t)
	_, velgatePub := generateVelgateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	sshClient := &sshpkg.Client{
		KeyPath:        dedicatedPriv,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        10 * time.Second,
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{},
		SSH:     sshClient,
		AddServerCfg: tools.AddServerConfig{
			VelgateBinaryPath: velgateBin,
			VelgatePubPath:    velgatePub,
			// authorized_keys will be rewritten for THIS key — but the
			// SSH client above uses the OTHER key, so verify fails.
			SSHGatePubPath: wrongPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err = runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "test",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
	})
	if err == nil {
		t.Fatalf("AddServer: nil err; expected verify failure")
	}
	if !strings.Contains(err.Error(), "verify") {
		t.Errorf("err=%v; expected message mentioning verify", err)
	}

	// Registry must NOT have been touched.
	if _, ok := servers.Get("test"); ok {
		t.Errorf("registry has 'test' after rollback; should be empty")
	}

	// authorized_keys must have been restored — the BOOTSTRAP key
	// should still work. (If rollback failed, the rewritten file would
	// reject the bootstrap key.)
	stdout, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "echo BOOTSTRAP_OK")
	if err != nil {
		t.Fatalf("post-rollback bootstrap SSH: %v", err)
	}
	if exit != 0 || !strings.Contains(string(stdout), "BOOTSTRAP_OK") {
		t.Errorf("post-rollback bootstrap SSH exit=%d stdout=%q; bootstrap key was locked out",
			exit, stdout)
	}

	// ~/.velgate/ must have been removed.
	dirCheck, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "test -d ~/.velgate && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("post-rollback dir probe: %v", err)
	}
	if !strings.Contains(string(dirCheck), "ABSENT") {
		t.Errorf("~/.velgate still present after rollback (exit=%d, stdout=%q)", exit, dirCheck)
	}
}

func TestPhase3AddServer_AliasAlreadyRegistered(t *testing.T) {
	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := servers.Add("dup", registry.Entry{
		Host: "h", Port: 22, User: "u", AddedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{},
		SSH:     &sshpkg.Client{KeyPath: "/nonexistent", KnownHostsPath: "/nonexistent"},
	}
	_, err = runner.AddServer(context.Background(), tools.AddServerInput{
		Alias:            "dup",
		Host:             "127.0.0.1",
		User:             "anyone",
		BootstrapKeyPath: "/dev/null",
	})
	if err == nil {
		t.Fatalf("AddServer: nil err; expected 'already registered'")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err=%v; expected 'already registered'", err)
	}
}

func TestPhase3AddServer_IdempotentReAdd(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	velgateBin := buildVelgateLinux(t)
	_, velgatePub := generateVelgateKeyPair(t)

	regPath := filepath.Join(t.TempDir(), "servers.json")
	servers, err := registry.New(regPath)
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	sshClient := &sshpkg.Client{
		KeyPath:        dedicatedPriv,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        15 * time.Second,
	}
	runner := &tools.Runner{
		Servers: servers,
		Sign:    &noopSign{},
		SSH:     sshClient,
		AddServerCfg: tools.AddServerConfig{
			VelgateBinaryPath: velgateBin,
			VelgatePubPath:    velgatePub,
			SSHGatePubPath:    dedicatedPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "first",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
	})
	if err != nil {
		t.Fatalf("first AddServer: %v", err)
	}
	if out.Idempotent {
		t.Errorf("Idempotent=true on first add; want false")
	}

	// Now re-add with a DIFFERENT alias — same pubkey is already
	// installed on the remote, so the tool should detect the canonical
	// restricted entry and skip the rewrite.
	out2, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "second",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
	})
	if err != nil {
		t.Fatalf("second AddServer (idempotent): %v", err)
	}
	if !out2.Idempotent {
		t.Errorf("Idempotent=false on the re-add; want true (restricted entry already present)")
	}
	if _, ok := servers.Get("second"); !ok {
		t.Errorf("second alias not registered after idempotent re-add")
	}
}

func TestPhase3AddServer_NoGoroutineLeaks(t *testing.T) {
	// The other Phase-3 subtests own the heavy lifetimes via t.Cleanup;
	// goleak here is a final sanity check that any docker/SSH goroutines
	// have unwound.
	goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("os/exec.(*Cmd).watchCtx"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	)
}

// noopSign is a Sign stub that errors if invoked. AddServer must not
// call Sign at any point; reads after the add must not call Sign
// either (the read path is direct).
type noopSign struct{}

func (noopSign) Sign(_ context.Context, _ string, _ []signpkg.CmdReq) ([]signpkg.Signed, error) {
	return nil, errors.New("noopSign: Sign should not be invoked in Phase 3 tests")
}

// fingerprintFromKnownHosts reads the first host-key line out of path
// and returns its SHA256 fingerprint in "SHA256:..." form.
func fingerprintFromKnownHosts(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts %s: %v", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// known_hosts line: "host keytype b64"
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			continue
		}
		key, err := sshlib.ParsePublicKey(keyBytes)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(key.Marshal())
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	t.Fatalf("no host-key line in %s", path)
	return ""
}
