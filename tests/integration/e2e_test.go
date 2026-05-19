//go:build integration

// Phase-1 end-to-end test for SSHGate (task 1.6).
//
// This is the lock criterion for Phase 1: it proves the entire
// cryptographic loop works against real components — real Docker
// SSH target, real gate binary on the remote, real signer
// daemon (StubBackend that always denies), real MCP run tool.
//
// Four scenarios:
//
//  1. Read path — Runner.Run("df -h") → exit 0, non-empty stdout,
//     Kind=read, Approved=false. (No sign call happens at all.)
//  2. Write denied — Runner.Run("rm /tmp/foo") → wraps ErrDenied.
//     StubBackend denies; the cmd never reaches the remote.
//  3. Direct unsigned SSH bypass — dial the container with the
//     SSHGate key and run "rm /tmp/x" without a SSHGATE_SIG prefix.
//     gate exits 77 ("write commands require a SSHGATE_SIG
//     prefix"). This is the defense-in-depth check: even if an
//     attacker had the SSHGate key, gate stops them.
//  4. Goroutine leak — goleak.VerifyNone(t) after all the lifetimes
//     have been cancelled.
//
// If Docker isn't available on the host, every scenario skips
// gracefully (skip != fail).
package integration_test

import (
	"errors"
	"strings"
	"testing"

	"go.uber.org/goleak"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

func TestPhase1EndToEnd(t *testing.T) {
	// Order matters: the linuxserver/openssh-server image reads
	// /keys/sshgate_ed25519.pub into authorized_keys at container
	// boot, so the .pub file must exist BEFORE bootContainer.
	sshKeyPriv, _ := generateSSHKey(t)
	_, gatePub := generateGateKeyPair(t)
	// The master key path: re-derive — generateGateKeyPair returns
	// (priv, pub); we need priv for signer.
	masterKey := strings.TrimSuffix(gatePub, ".pub") + ".key"

	// Stand up the stack once for all four scenarios. The container
	// + signer are expensive (~5s); reusing them keeps the suite
	// under the 180s budget.
	containerCleanup := bootContainer(t)
	t.Cleanup(containerCleanup)

	deployGateBinary(t, gatePub)

	socketPath, signerCleanup := startSigner(t, masterKey)
	t.Cleanup(signerCleanup)

	t.Run("ReadPathSucceeds", func(t *testing.T) {
		out, err := runMCPRunTool(t, socketPath, sshKeyPriv,
			"test", "127.0.0.1", sshContainerPort, remoteUser, "df -h")
		if err != nil {
			t.Fatalf("Runner.Run(df -h) err=%v stdout=%q stderr=%q exit=%d",
				err, out.Stdout, out.Stderr, out.ExitCode)
		}
		if out.ExitCode != 0 {
			t.Errorf("exit=%d; want 0 (stderr=%q)", out.ExitCode, out.Stderr)
		}
		if len(out.Stdout) == 0 {
			t.Errorf("stdout was empty; expected df output")
		}
		if out.Kind != "read" {
			t.Errorf("Kind=%q; want read", out.Kind)
		}
		if out.Approved {
			t.Errorf("Approved=true on a read; want false (no sign should be solicited)")
		}
	})

	t.Run("WriteDeniedByStubBackend", func(t *testing.T) {
		out, err := runMCPRunTool(t, socketPath, sshKeyPriv,
			"test", "127.0.0.1", sshContainerPort, remoteUser, "rm /tmp/foo")
		if err == nil {
			t.Fatalf("Runner.Run(rm /tmp/foo) returned nil; want ErrDenied. stdout=%q exit=%d",
				out.Stdout, out.ExitCode)
		}
		if !errors.Is(err, signpkg.ErrDenied) {
			t.Errorf("err did not wrap ErrDenied: %v", err)
		}
		if out.Kind != "write" {
			t.Errorf("Kind=%q; want write", out.Kind)
		}
		// Approved should be false — sign never returned approval.
		if out.Approved {
			t.Errorf("Approved=true on a denied write; want false")
		}
		// stdout must be empty — the command must never have reached
		// the remote. (If it did, this is a security bug.)
		if len(out.Stdout) != 0 {
			t.Errorf("stdout=%q on denied write; should be empty (cmd should never reach remote)", out.Stdout)
		}
	})

	t.Run("DirectUnsignedSSHBypassRefused", func(t *testing.T) {
		// Dial the container directly with the SSHGate key. The
		// dedicated key works (OpenSSH accepts it), but gate's
		// command="..." forcing intercepts, classifies "rm /tmp/x"
		// as a write, sees no SSHGATE_SIG prefix, exits 77.
		stdout, stderr, exit, err := directUnsignedSSH(t, sshKeyPriv,
			"127.0.0.1", sshContainerPort, remoteUser, "rm /tmp/x")
		// ssh.Client returns nil error for non-zero exit; the exit
		// code itself is what we check.
		if err != nil {
			t.Fatalf("directUnsignedSSH err=%v stdout=%q stderr=%q exit=%d",
				err, stdout, stderr, exit)
		}
		if exit != 77 {
			t.Errorf("exit=%d; want 77 (EX_NOPERM from gate)", exit)
		}
		if !strings.Contains(string(stderr), "write commands require a SSHGATE_SIG prefix") {
			t.Errorf("stderr did not carry the expected gate message: %q", stderr)
		}
		// stdout MUST be empty — the command was refused before exec.
		if len(stdout) != 0 {
			t.Errorf("stdout=%q on refused write; should be empty", stdout)
		}
	})

	t.Run("NoGoroutineLeaks", func(t *testing.T) {
		// Force the prior subtests' cleanups (registered via
		// t.Cleanup) to run for goleak by tearing down the heavy
		// lifetimes here. The parent t.Cleanups for container +
		// signer are still registered, so we run goleak BEFORE
		// they fire by triggering them explicitly first.
		signerCleanup()
		containerCleanup()

		// goleak.VerifyNone with the parent t — the SSH client
		// spawns a per-call watcher goroutine that exits when Run
		// returns, and signer.Server's accept loop exits when
		// its ctx is cancelled by signerCleanup.
		goleak.VerifyNone(t,
			// Allow the docker compose subprocess wait goroutine to
			// drain — it's a transient stdlib goroutine, not ours.
			goleak.IgnoreTopFunction("os/exec.(*Cmd).watchCtx"),
			// Ignore goroutines that may be parked in the test
			// runtime itself.
			goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		)
	})
}
