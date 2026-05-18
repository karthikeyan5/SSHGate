//go:build integration

// Phase-4 end-to-end test for SSHGate (task 4.2 lock criterion).
//
// Demonstrates the full teardown loop:
//
//  1. add_server: real auto-setup against a fresh openssh-server
//     container. velgate is installed; authorized_keys is rewritten
//     with the command="..." forcing for the SSHGate dedicated key.
//  2. run (read): proves velgate is in the loop and routes a read
//     directly.
//  3. revoke_server: signs VELGATE_REVOKE via an auto-approve velsigner
//     backend, ships it; velgate strips its own authorized_keys line
//     and removes ~/.velgate/.
//  4. Confirm cleanup: the BOOTSTRAP key still works (proving
//     authorized_keys was not destroyed); ~/.velgate/ is gone; the MCP
//     registry no longer holds the alias.
//
// The test runs end-to-end with the REAL velsigner.Server (auto-approve
// backend), REAL sign.Client, REAL ssh.Client, REAL velgate binary.
// Only the human-tap stage is replaced by an in-process auto-approver,
// which keeps the focus on the revoke flow rather than re-testing
// Telegram (Phase-2 covers that).
package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	sshpkg "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/velsigner"
	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

// autoApproveBackend is a Backend that approves every request as soon
// as Request is called. It exists for Phase-4: the revoke flow needs a
// signed VELGATE_REVOKE but doesn't need to re-test the Telegram tap
// (Phase-2 covers that). Goroutine bookkeeping ensures all approvers
// finish before the test exits so goleak is clean.
type autoApproveBackend struct {
	mu      sync.Mutex
	wg      sync.WaitGroup
	closed  bool
	closeCh chan struct{}
}

func newAutoApproveBackend() *autoApproveBackend {
	return &autoApproveBackend{closeCh: make(chan struct{})}
}

func (a *autoApproveBackend) Request(ctx context.Context, req backend.ApprovalRequest) (<-chan backend.Result, error) {
	ch := make(chan backend.Result, 1)
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		ch <- backend.Result{Status: backend.StatusTimeout}
		close(ch)
		return ch, nil
	}
	a.wg.Add(1)
	a.mu.Unlock()

	go func() {
		defer a.wg.Done()
		// Resolve immediately; the daemon expects a value followed by
		// channel closure (or just a single send — either is fine per
		// the Backend contract).
		select {
		case ch <- backend.Result{Status: backend.StatusApproved, ApprovedBy: "auto-approve"}:
		case <-ctx.Done():
		case <-a.closeCh:
		}
	}()
	return ch, nil
}

func (a *autoApproveBackend) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	close(a.closeCh)
	a.mu.Unlock()
	a.wg.Wait()
}

// startVelsignerAutoApprove boots a real velsigner.Server backed by the
// auto-approve backend. Returns the socket path and a cleanup func.
func startVelsignerAutoApprove(t *testing.T, masterKeyPath string) (string, func()) {
	t.Helper()
	priv, err := velsigner.LoadKey(masterKeyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	auditPath := filepath.Join(t.TempDir(), "approvals.log")
	audit, err := velsigner.OpenAuditLog(auditPath)
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	be := newAutoApproveBackend()
	daemon := &velsigner.Daemon{Key: priv, Backend: be, Audit: audit}
	socketPath := filepath.Join(t.TempDir(), "velsigner.sock")
	srv := &velsigner.Server{Path: socketPath, Handler: daemon, HandlerTimeout: 15 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Listen(ctx)
	}()
	// Wait briefly for the socket file to appear.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return socketPath, func() {
		cancel()
		<-done
		be.Close()
		_ = audit.Close()
	}
}

func TestPhase4RevokeServer_FullCycle(t *testing.T) {
	bootstrapPriv, _ := generateSSHKey(t)
	cleanup := bootContainer(t)
	t.Cleanup(cleanup)

	dedicatedPriv, dedicatedPub := generateStandaloneSSHKey(t)
	velgateBin := buildVelgateLinux(t)
	velgateKeyPriv, velgatePub := generateVelgateKeyPair(t)

	socketPath, socketCleanup := startVelsignerAutoApprove(t, velgateKeyPriv)
	t.Cleanup(socketCleanup)

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
	signClient := &signpkg.Client{SocketPath: socketPath, Timeout: 15 * time.Second}

	runner := &tools.Runner{
		Servers:           servers,
		Sign:              signClient,
		SSH:               sshClient,
		WriteTTLSec:       60,
		VelsignerSockPath: socketPath,
		AddServerCfg: tools.AddServerConfig{
			VelgateBinaryPath: velgateBin,
			VelgatePubPath:    velgatePub,
			SSHGatePubPath:    dedicatedPub,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// --- add ---
	addOut, err := runner.AddServer(ctx, tools.AddServerInput{
		Alias:            "phase4",
		Host:             "127.0.0.1",
		Port:             sshContainerPort,
		User:             remoteUser,
		BootstrapKeyPath: bootstrapPriv,
	})
	if err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	if !addOut.VerifiedOK {
		t.Fatalf("VerifiedOK=false after AddServer")
	}

	// --- read goes through ---
	readOut, err := runner.Run(ctx, tools.RunInput{Alias: "phase4", Command: "ls /"})
	if err != nil || readOut.ExitCode != 0 {
		t.Fatalf("read after add: err=%v exit=%d stderr=%q", err, readOut.ExitCode, readOut.Stderr)
	}

	// --- revoke ---
	revokeOut, err := runner.RevokeServer(ctx, tools.RevokeServerInput{Alias: "phase4"})
	if err != nil {
		t.Fatalf("RevokeServer: %v", err)
	}
	if !revokeOut.RemoteCleaned {
		t.Errorf("RemoteCleaned = false; want true")
	}
	if !revokeOut.RegistryRemoved {
		t.Errorf("RegistryRemoved = false; want true")
	}
	if !strings.Contains(revokeOut.Message, "VELGATE_REVOKED") {
		t.Errorf("Message = %q; want VELGATE_REVOKED marker", revokeOut.Message)
	}

	// --- registry no longer has alias ---
	if _, ok := servers.Get("phase4"); ok {
		t.Errorf("registry still has the alias after revoke")
	}

	// --- bootstrap key still works (authorized_keys was preserved) ---
	stdout, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "echo POST_REVOKE_BOOTSTRAP_OK")
	if err != nil {
		t.Fatalf("post-revoke bootstrap SSH: %v", err)
	}
	if exit != 0 || !strings.Contains(string(stdout), "POST_REVOKE_BOOTSTRAP_OK") {
		t.Errorf("post-revoke bootstrap exit=%d stdout=%q; bootstrap key was locked out",
			exit, stdout)
	}

	// --- ~/.velgate/ gone ---
	dirCheck, _, exit, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser, "test -d ~/.velgate && echo PRESENT || echo ABSENT")
	if err != nil {
		t.Fatalf("post-revoke dir probe: %v", err)
	}
	if !strings.Contains(string(dirCheck), "ABSENT") {
		t.Errorf("~/.velgate still present after revoke (exit=%d, stdout=%q)", exit, dirCheck)
	}

	// --- velgate-restricted line gone from authorized_keys ---
	authCheck, _, _, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser,
		"grep -c '\\.velgate/velgate' ~/.ssh/authorized_keys || true")
	if err != nil {
		t.Fatalf("authorized_keys probe: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(authCheck)), "0") {
		t.Errorf("authorized_keys still references velgate after revoke: %q", authCheck)
	}

	// --- backup file is present (operator-safety net) ---
	backupCheck, _, _, err := directUnsignedSSH(t, bootstrapPriv,
		"127.0.0.1", sshContainerPort, remoteUser,
		"test -f ~/.ssh/authorized_keys.sshgate-revoke-backup && echo BACKUP_OK || echo NO_BACKUP")
	if err != nil {
		t.Fatalf("backup probe: %v", err)
	}
	if !strings.Contains(string(backupCheck), "BACKUP_OK") {
		t.Errorf("revoke backup not found (stdout=%q)", backupCheck)
	}
}
