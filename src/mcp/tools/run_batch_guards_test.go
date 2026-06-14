package tools_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestRunBatch_EmptyCommandInList asserts a blank command anywhere in the
// list aborts up front with a 'commands[i] is empty' error naming the
// offending index, before any sign or SSH call.
func TestRunBatch_EmptyCommandInList(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cmds []string
		idx  string
	}{
		{"blank first", []string{"   ", "df -h"}, "commands[0]"},
		{"blank middle", []string{"df -h", "", "uptime"}, "commands[1]"},
		{"whitespace tab last", []string{"df -h", "uptime", "\t"}, "commands[2]"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := newRegistryForBatch(t)
			sign := &batchSign{}
			ssh := &batchSSH{}
			runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

			_, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
				Alias:    "h1",
				Commands: c.cmds,
			})
			if err == nil {
				t.Fatal("RunBatch with a blank command = nil; want error")
			}
			if !strings.Contains(err.Error(), c.idx) || !strings.Contains(err.Error(), "is empty") {
				t.Errorf("err = %v; want '%s is empty'", err, c.idx)
			}
			if sign.calls != 0 {
				t.Error("Sign was called despite a blank command")
			}
			if len(ssh.calls) != 0 {
				t.Error("SSH was called despite a blank command")
			}
		})
	}
}

// TestRunBatch_MidBatchSSHError asserts a transport-layer SSH error partway
// through the batch returns the PARTIAL results gathered so far plus an
// error wrapping 'ssh exec [i]' (naming the failing index) and the
// underlying error.
func TestRunBatch_MidBatchSSHError(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	sign := &batchSign{}
	transportErr := errors.New("dial: connection reset by peer")
	// All reads; the second command's SSH dial fails at the transport
	// layer. The first read completes (so we get a partial result).
	ssh := &batchSSH{
		byContains: []sshResponse{
			{match: "uptime", exit: 0, stdout: "up 3 days"},
			{match: "free -m", err: transportErr},
			{match: "df -h", exit: 0, stdout: "should-not-run"},
		},
	}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: []string{"uptime", "free -m", "df -h"},
	})
	if err == nil {
		t.Fatal("RunBatch with a mid-batch SSH error = nil err; want a wrapped transport error")
	}
	if !errors.Is(err, transportErr) {
		t.Errorf("err = %v; want wrap of the transport error", err)
	}
	if !strings.Contains(err.Error(), "ssh exec [1]") {
		t.Errorf("err = %v; want 'ssh exec [1]' naming the failing index", err)
	}
	// Partial results: index 0 ran to completion; the batch stopped at
	// index 1 so index 2 never dialed.
	if len(out.Results) != 3 {
		t.Fatalf("Results=%d; want 3 (pre-sized, partially filled)", len(out.Results))
	}
	if out.Results[0].Stdout != "up 3 days" {
		t.Errorf("Results[0].Stdout=%q; want the completed first read", out.Results[0].Stdout)
	}
	if len(ssh.calls) != 2 {
		t.Errorf("ssh.calls=%d; want 2 (third command never dialed)", len(ssh.calls))
	}
}

// TestRunBatch_SignatureCountMismatch asserts that when the signer returns
// a different number of signatures than the number of writes requested,
// RunBatch errors (rather than mis-pairing signatures to commands) and
// never reaches the SSH layer.
func TestRunBatch_SignatureCountMismatch(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	writes := []string{"apt update", "apt install -y nginx"}
	// Two writes requested, but the signer returns only one signature.
	short := makeSignedFor(t, writes[:1])
	sign := &batchSign{signed: short}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: writes,
	})
	if err == nil {
		t.Fatal("RunBatch with a signature-count mismatch = nil; want error")
	}
	if !strings.Contains(err.Error(), "expected 2 signatures") || !strings.Contains(err.Error(), "got 1") {
		t.Errorf("err = %v; want 'expected 2 signatures; got 1'", err)
	}
	if len(ssh.calls) != 0 {
		t.Error("SSH was called despite a signature-count mismatch")
	}
}

// TestRun_SignatureCountMismatch asserts the single-command run path errors
// when the signer returns anything other than exactly one signature, and
// never reaches SSH.
func TestRun_SignatureCountMismatch(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		signed int // number of bogus signatures the fake returns
	}{
		{"zero signatures", 0},
		{"two signatures", 2},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
			sigs := make([]signpkg.Signed, c.signed)
			for i := range sigs {
				sigs[i] = signpkg.Signed{Cmd: "rm /tmp/x", Sig: "SSHGATE_SIG:a:b"}
			}
			sign := &fakeSign{signed: sigs}
			ssh := &fakeSSH{}
			runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

			_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
			if err == nil {
				t.Fatalf("Run with %d signatures = nil; want error", c.signed)
			}
			if !strings.Contains(err.Error(), "expected 1 signature") {
				t.Errorf("err = %v; want 'expected 1 signature; got %d'", err, c.signed)
			}
			if len(ssh.callHistory) != 0 {
				t.Error("SSH was called despite a signature-count mismatch")
			}
		})
	}
}

// TestRun_NilSignGuard asserts a nil Sign dependency is reported as a
// configuration error rather than panicking.
func TestRun_NilSignGuard(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: nil, SSH: &fakeSSH{}}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err == nil {
		t.Fatal("Run with nil Sign = nil; want a 'Sign is nil' configuration error")
	}
	if !strings.Contains(err.Error(), "Sign is nil") {
		t.Errorf("err = %v; want 'Sign is nil'", err)
	}
}

// TestRun_NilSSHGuard asserts a nil SSH dependency is reported as a
// configuration error rather than panicking.
func TestRun_NilSSHGuard(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: nil}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err == nil {
		t.Fatal("Run with nil SSH = nil; want a 'SSH is nil' configuration error")
	}
	if !strings.Contains(err.Error(), "SSH is nil") {
		t.Errorf("err = %v; want 'SSH is nil'", err)
	}
}

// TestRevokeServer_SignatureCountMismatch asserts that a revoke whose
// sign request returns anything other than one signature errors before
// SSH and leaves the registry untouched.
func TestRevokeServer_SignatureCountMismatch(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	// Two signatures returned for a single SSHGATE_REVOKE request.
	sign := &fakeSign{signed: []signpkg.Signed{
		{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:a:b"},
		{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:c:d"},
	}}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if err == nil {
		t.Fatal("RevokeServer with 2 signatures = nil; want error")
	}
	if !strings.Contains(err.Error(), "expected 1 signature") {
		t.Errorf("err = %v; want 'expected 1 signature; got 2'", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called despite a signature-count mismatch")
	}
	if _, ok := r.Get("a"); !ok {
		t.Error("registry alias removed despite a signature-count mismatch")
	}
}

// TestRevokeServer_RegistryRemoveFails_RemoteAlreadyCleaned asserts the
// partial-failure contract: the remote confirmed the revoke (marker
// present) but the local registry write fails. The output must report
// RemoteCleaned=true / RegistryRemoved=false and return an error — and the
// alias must REMAIN in the registry (Remove rolls its in-memory state back
// on a persist failure) so the operator can re-run / hand-clean.
func TestRevokeServer_RegistryRemoveFails_RemoteAlreadyCleaned(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory mode 0500 does not block writes, so the persist-failure cannot be simulated")
	}
	// Build the registry in a dedicated dir, then make that dir
	// non-writable so the atomic persist (CreateTemp in the dir) inside
	// Remove fails — no sudo required, just an unwritable parent.
	dir := t.TempDir()
	regPath := filepath.Join(dir, "servers.json")
	reg, err := registry.New(regPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Add("a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Drop write permission on the directory so a later persist fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir clean up

	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:a:b"}}}
	ssh := &fakeSSH{stdout: []byte("SSHGATE_REVOKED lines=1 dir=removed\n"), exit: 0}
	runner := &tools.Runner{Servers: reg, Sign: sign, SSH: ssh}

	out, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if err == nil {
		t.Fatal("RevokeServer (registry write fails) = nil err; want the partial-failure error")
	}
	if !strings.Contains(err.Error(), "remote cleaned but registry remove failed") {
		t.Errorf("err = %v; want the 'remote cleaned but registry remove failed' message", err)
	}
	if !out.RemoteCleaned {
		t.Error("RemoteCleaned=false; want true (the gate confirmed the revoke)")
	}
	if out.RegistryRemoved {
		t.Error("RegistryRemoved=true; want false (the registry write failed)")
	}
	// The alias must still be present (Remove rolled back its in-memory
	// delete when persist failed).
	if _, ok := reg.Get("a"); !ok {
		t.Error("registry alias gone despite the persist failure rollback")
	}
}
