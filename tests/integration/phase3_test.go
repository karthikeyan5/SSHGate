//go:build integration

// Phase-3 end-to-end test for SSHGate (task 3.4 / lock criterion for
// task 3.1).
//
// Boots a FRESH linuxserver/openssh-server container with NO gate
// pre-installed, then exercises the real sshgate.add_server tool:
//
//   1. Success path. AddServer dials with the operator's bootstrap key
//      (the one the linuxserver image baked into authorized_keys),
//      uploads gate + signing pubkey, rewrites authorized_keys to
//      gate the SSHGate dedicated key behind command="..." forcing,
//      verifies via the SSHGATE_OK probe, registers the alias. Then
//      a plain `df -h` Runner.Run goes through and works.
//   2. Verify failure → rollback. We re-use the same fresh container
//      after tearing down between subtests, point AddServer at a
//      pubkey that won't actually let the sshgate key in, and assert
//      that authorized_keys is restored from the backup (the bootstrap
//      key still works) AND ~/.sshgate-gate/ no longer exists.
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

	// Cross-compile gate + generate signing keypair.
	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

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
			GateBinaryPath: gateBin,
			GatePubPath:    gatePub,
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
	if out.BinaryPath != "~/.sshgate-gate/gate" {
		t.Errorf("BinaryPath=%q; want ~/.sshgate-gate/gate", out.BinaryPath)
	}
	if out.Idempotent {
		t.Errorf("Idempotent=true on first add; want false")
	}
	// Registry now holds the alias.
	if _, ok := servers.Get("test"); !ok {
		t.Errorf("registry does not have 'test' after AddServer")
	}

	// Now run a read via the dedicated key — confirm gate is in the
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

	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

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
			GateBinaryPath: gateBin,
			GatePubPath:    gatePub,
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

	// ~/.sshgate-gate/ must have been removed.
	dirCheck, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "test -d ~/.sshgate-gate && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("post-rollback dir probe: %v", err)
	}
	if !strings.Contains(string(dirCheck), "ABSENT") {
		t.Errorf("~/.sshgate-gate still present after rollback (exit=%d, stdout=%q)", exit, dirCheck)
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
	gateBin := buildGateLinux(t)
	_, gatePub := generateGateKeyPair(t)

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
			GateBinaryPath: gateBin,
			GatePubPath:    gatePub,
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

// TestPhase3AddServer_ReadOnly covers the tier-1 install path: deploy
// gate WITHOUT uploading gate.pub. Reads should still execute
// through the gate (gate's keystore returns (nil, nil) for the
// missing pubkey and treats reads as allowed); writes must be denied
// with the read-only-mode error message and exit code 77.
func TestPhase3AddServer_ReadOnly(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	gateBin := buildGateLinux(t)
	// GatePubPath points at a non-existent file — AddServer in
	// ReadOnly mode must not read it. The slash command flow doesn't
	// have it on disk yet in tier-1.
	gatePubPath := filepath.Join(t.TempDir(), "definitely-not-here.pub")

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
		Sign:    &noopSign{},
		SSH:     sshClient,
		AddServerCfg: tools.AddServerConfig{
			GateBinaryPath: gateBin,
			GatePubPath:    gatePubPath,
			SSHGatePubPath:    dedicatedPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "ro",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
		ReadOnly:         true,
	})
	if err != nil {
		t.Fatalf("AddServer (read-only): %v", err)
	}
	if !out.ReadOnlyMode {
		t.Errorf("ReadOnlyMode=false on read-only add; want true")
	}
	if !out.VerifiedOK {
		t.Errorf("VerifiedOK=false; want true (probe works regardless of pubkey)")
	}

	// Confirm gate.pub is NOT on the remote.
	probe, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser,
		"test -f ~/.sshgate-gate/gate.pub && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("pubkey probe: %v", err)
	}
	if !strings.Contains(string(probe), "ABSENT") {
		t.Errorf("gate.pub present on remote in tier-1 (exit=%d, stdout=%q)", exit, probe)
	}

	// Read goes through.
	rdOut, err := runner.Run(ctx, tools.RunInput{Alias: "ro", Command: "df -h"})
	if err != nil {
		t.Fatalf("Runner.Run(df -h) on tier-1 server: %v", err)
	}
	if rdOut.ExitCode != 0 {
		t.Errorf("df -h exit=%d; want 0 (stderr=%q)", rdOut.ExitCode, rdOut.Stderr)
	}

	// Write hits the SSH layer with a SIG prefix from Sign... but
	// noopSign errors. So we exercise the gate denial path via a
	// direct unsigned SSH dial that gate classifies as a write.
	// SSH_ORIGINAL_COMMAND is set to "rm /tmp/x" by the SSH client.
	_, stderr, exit, err := sshClient.Run(ctx, "127.0.0.1", remoteUser, sshContainerPort, "rm /tmp/x")
	if err == nil && exit == 0 {
		t.Fatalf("write executed on tier-1 server (exit=0, stderr=%q); want denial", stderr)
	}
	if exit != 77 {
		t.Errorf("write exit=%d; want 77 (EX_NOPERM)", exit)
	}
	if !strings.Contains(string(stderr), "no signing key configured") {
		t.Errorf("stderr=%q; want substring %q", stderr, "no signing key configured")
	}
	if !strings.Contains(string(stderr), "/sshgate:setup") {
		t.Errorf("stderr=%q; want substring %q", stderr, "/sshgate:setup")
	}
}

// TestPhase3UpgradeServerToSigning covers the tier-1 → tier-2
// transition: an existing read-only server gets its gate.pub
// pushed via the bootstrap leg, after which signed writes can be
// verified. We don't exercise a real signed write here (that needs
// signer) — we just confirm the upload + probe completes and the
// remote file is present afterward.
func TestPhase3UpgradeServerToSigning(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	gateBin := buildGateLinux(t)
	gatePubPathMissing := filepath.Join(t.TempDir(), "missing.pub")
	_, gatePub := generateGateKeyPair(t) // for the upgrade

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
		Sign:    &noopSign{},
		SSH:     sshClient,
		AddServerCfg: tools.AddServerConfig{
			GateBinaryPath: gateBin,
			GatePubPath:    gatePubPathMissing,
			SSHGatePubPath:    dedicatedPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Step 1: tier-1 add (no pubkey on disk).
	if _, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "upgrade-target",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
		ReadOnly:         true,
	}); err != nil {
		t.Fatalf("tier-1 AddServer: %v", err)
	}

	// Step 2: signer is set up; swap the config to point at the real
	// pubkey and run UpgradeServerToSigning.
	runner.AddServerCfg.GatePubPath = gatePub
	if err := runner.UpgradeServerToSigning(ctx, "upgrade-target", tools.AddServerInput{
		BootstrapKeyPath: bootstrapPriv,
	}); err != nil {
		t.Fatalf("UpgradeServerToSigning: %v", err)
	}

	// Confirm gate.pub is now on the remote.
	probe, _, _, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser,
		"test -f ~/.sshgate-gate/gate.pub && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("post-upgrade pubkey probe: %v", err)
	}
	if !strings.Contains(string(probe), "PRESENT") {
		t.Errorf("gate.pub still absent after upgrade (stdout=%q)", probe)
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
