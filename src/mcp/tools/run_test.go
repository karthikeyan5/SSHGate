package tools_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// fakeSign is a Runner.Sign / SignClient stub. signCalled records whether
// Sign was invoked; respond is the canned outcome. The grant* fields
// capture and drive the RequestGrant / RevokeGrant paths.
type fakeSign struct {
	mu         sync.Mutex
	signCalled bool
	gotReqID   string
	gotCmds    []signpkg.CmdReq
	signed     []signpkg.Signed
	authMode   string
	err        error

	// RequestGrant capture + canned result.
	grantCalled      bool
	grantReqID       string
	grantAlias       string
	grantScope       string
	grantCommands    []string
	grantDurationSec int64
	grantID          string
	grantExpiryUnix  int64
	grantErr         error

	// RevokeGrant capture + canned result.
	revokeGrantCalled bool
	revokeGrantReqID  string
	revokeGrantAlias  string
	revokeGrantErr    error

	// ListGrants capture + canned result.
	listGrantsCalled bool
	listGrantsReqID  string
	listGrantsAlias  string
	listGrantsResult []signpkg.GrantInfo
	listGrantsErr    error
}

func (f *fakeSign) Sign(ctx context.Context, requestID string, cmds []signpkg.CmdReq) (signpkg.SignResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signCalled = true
	f.gotReqID = requestID
	f.gotCmds = cmds
	return signpkg.SignResult{Signed: f.signed, AuthMode: f.authMode}, f.err
}

func (f *fakeSign) RequestGrant(ctx context.Context, requestID, alias, scope string, commands []string, durationSec int64) (string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grantCalled = true
	f.grantReqID = requestID
	f.grantAlias = alias
	f.grantScope = scope
	f.grantCommands = commands
	f.grantDurationSec = durationSec
	return f.grantID, f.grantExpiryUnix, f.grantErr
}

func (f *fakeSign) RevokeGrant(ctx context.Context, requestID, alias string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeGrantCalled = true
	f.revokeGrantReqID = requestID
	f.revokeGrantAlias = alias
	return f.revokeGrantErr
}

func (f *fakeSign) ListGrants(ctx context.Context, requestID, alias string) ([]signpkg.GrantInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listGrantsCalled = true
	f.listGrantsReqID = requestID
	f.listGrantsAlias = alias
	return f.listGrantsResult, f.listGrantsErr
}

// fakeSSH is a Runner.SSH stub.
type fakeSSH struct {
	mu          sync.Mutex
	gotCmd      string
	gotHost     string
	gotUser     string
	gotPort     int
	stdout      []byte
	stderr      []byte
	exit        int
	err         error
	callHistory []string
}

func (f *fakeSSH) Run(ctx context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotCmd = cmd
	f.gotHost = host
	f.gotUser = user
	f.gotPort = port
	f.callHistory = append(f.callHistory, cmd)
	return f.stdout, f.stderr, f.exit, f.err
}

func newRegistryWith(t *testing.T, alias string, entry registry.Entry) *registry.Servers {
	t.Helper()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(alias, entry); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRun_ReadCommandGoesDirect(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{stdout: []byte("ok\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sign.signCalled {
		t.Error("sign was called for a read command")
	}
	if ssh.gotCmd != "df -h" {
		t.Errorf("ssh.gotCmd = %q; want %q", ssh.gotCmd, "df -h")
	}
	if ssh.gotHost != "1.2.3.4" || ssh.gotPort != 22 || ssh.gotUser != "u" {
		t.Errorf("ssh got host=%s port=%d user=%s", ssh.gotHost, ssh.gotPort, ssh.gotUser)
	}
	if out.Kind != "read" {
		t.Errorf("Kind = %q; want read", out.Kind)
	}
	if out.Approved {
		t.Error("Approved = true on a read")
	}
	if out.Stdout != "ok\n" {
		t.Errorf("Stdout = %q", out.Stdout)
	}
	if out.ExitCode != 0 {
		t.Errorf("ExitCode = %d", out.ExitCode)
	}
}

func TestRun_WriteCommandSignsThenSSH(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	// Build a realistic signed wire string.
	payload := sigwire.SigPayload{Cmd: "rm /tmp/x", TS: 1, Exp: 60, Nonce: "abc"}
	wire, err := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sign := &fakeSign{
		signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: wire}},
	}
	ssh := &fakeSSH{stdout: []byte("removed\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !sign.signCalled {
		t.Fatal("sign was not called for a write command")
	}
	if len(sign.gotCmds) != 1 || sign.gotCmds[0].Cmd != "rm /tmp/x" {
		t.Errorf("sign.gotCmds = %+v", sign.gotCmds)
	}
	if sign.gotReqID == "" {
		t.Error("sign.gotReqID is empty")
	}
	// The SSH side must receive the wire-prefixed command.
	if !strings.HasPrefix(ssh.gotCmd, "SSHGATE_SIG:") {
		t.Errorf("ssh got cmd %q; expected SSHGATE_SIG: prefix", ssh.gotCmd)
	}
	if !strings.HasSuffix(ssh.gotCmd, " rm /tmp/x") {
		t.Errorf("ssh got cmd %q; expected suffix ' rm /tmp/x'", ssh.gotCmd)
	}
	if !out.Approved {
		t.Error("Approved = false on a write")
	}
	if out.Kind != "write" {
		t.Errorf("Kind = %q; want write", out.Kind)
	}
}

// TestRun_WritePassesRegistryFingerprint pins that the write path binds the
// sign request to the server's host-key fingerprint READ FROM THE REGISTRY,
// not from any agent-supplied value. This is the confused-deputy guard: the
// agent invokes run(alias, command) and can never influence which host the
// approved signature binds to — the MCP sources it from the trusted registry
// entry. A regression that dropped this would let an "approve on X" signature
// be minted unbound (and thus replayable anywhere the gate fails open).
func TestRun_WritePassesRegistryFingerprint(t *testing.T) {
	t.Parallel()
	const wantFP = "SHA256:prodHostKeyFingerprintAAAAAAAAAAAAAAAAAAAAAA"
	r := newRegistryWith(t, "h1", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(),
		Fingerprint: wantFP,
	})
	payload := sigwire.SigPayload{Cmd: "rm /tmp/x", TS: 1, Exp: 60, Nonce: "abc", Host: wantFP}
	wire, err := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: wire}}}
	ssh := &fakeSSH{stdout: []byte("ok\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	if _, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sign.gotCmds) != 1 {
		t.Fatalf("got %d cmds; want 1", len(sign.gotCmds))
	}
	if sign.gotCmds[0].Host != wantFP {
		t.Errorf("sign CmdReq.Host = %q; want %q (must come from the registry entry, not the agent)", sign.gotCmds[0].Host, wantFP)
	}
}

// TestRun_WritePropagatesAuthMode pins F4: the auth_mode the signer returns
// on the sign response (here "grant:g_1") propagates onto RunOutput.AuthMode,
// and a READ carries an empty AuthMode (no sign call, nothing to authorise).
func TestRun_WritePropagatesAuthMode(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	payload := sigwire.SigPayload{Cmd: "rm /tmp/x", TS: 1, Exp: 60, Nonce: "abc"}
	wire, err := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	if err != nil {
		t.Fatal(err)
	}
	sign := &fakeSign{
		signed:   []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: wire}},
		authMode: "grant:g_1",
	}
	ssh := &fakeSSH{stdout: []byte("ok\n")}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	// Write → auth_mode propagates.
	out, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err != nil {
		t.Fatalf("Run write: %v", err)
	}
	if out.AuthMode != "grant:g_1" {
		t.Errorf("write RunOutput.AuthMode = %q; want grant:g_1", out.AuthMode)
	}

	// Read → empty auth_mode (no sign request).
	readOut, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err != nil {
		t.Fatalf("Run read: %v", err)
	}
	if readOut.AuthMode != "" {
		t.Errorf("read RunOutput.AuthMode = %q; want \"\"", readOut.AuthMode)
	}
}

func TestRun_WriteDenied(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrDenied}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on denial")
	}
	if !errors.Is(err, signpkg.ErrDenied) {
		t.Errorf("err = %v; want wrap of ErrDenied", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called after denial")
	}
}

func TestRun_WriteTimeout(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrTimeout}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on timeout")
	}
	if !errors.Is(err, signpkg.ErrTimeout) {
		t.Errorf("err = %v; want wrap of ErrTimeout", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called after timeout")
	}
}

func TestRun_WriteUnreachable(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrUnreachable}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected error on unreachable")
	}
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err = %v; want wrap of ErrUnreachable", err)
	}
}

func TestRun_UnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "nope", Command: "df -h"})
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should mention the alias: %v", err)
	}
}

func TestRun_UnknownCommandKindRoutesAsWrite(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	// `rm` is not in the read allowlist → write.
	sign := &fakeSign{err: signpkg.ErrDenied}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"})
	if err == nil {
		t.Fatal("expected denial error")
	}
}

func TestRun_EmptyCommandRejected(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "   "})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

func TestRun_SSHErrorSurfaces(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sshErr := fmt.Errorf("dial: connection refused")
	sign := &fakeSign{}
	ssh := &fakeSSH{err: sshErr}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err == nil {
		t.Fatal("expected ssh error to surface")
	}
	if !errors.Is(err, sshErr) {
		t.Errorf("err = %v; want wrap of %v", err, sshErr)
	}
}

// TestRun_DefaultWriteTTL pins the default write signature window at 60s.
// A tighter default shrinks the replay window between human approval and gate
// execution; the gate still independently caps it at MaxSigValidity. When the
// Runner's WriteTTLSec is unset, the write path must request exactly this TTL.
func TestRun_DefaultWriteTTL(t *testing.T) {
	t.Parallel()
	if tools.DefaultWriteTTLSec != 60 {
		t.Fatalf("DefaultWriteTTLSec = %d; want 60", tools.DefaultWriteTTLSec)
	}
	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:x"})
	payload := sigwire.SigPayload{Cmd: "rm /tmp/x", TS: 1, Exp: 60, Nonce: "abc", Host: "SHA256:x"}
	wire, _ := sigwire.EncodeSigned([]byte("0123456789012345678901234567890123456789012345678901234567890123"), payload)
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "rm /tmp/x", Sig: wire}}}
	ssh := &fakeSSH{stdout: []byte("ok\n")}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh} // WriteTTLSec unset → default

	if _, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "rm /tmp/x"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sign.gotCmds) != 1 || sign.gotCmds[0].TTLSec != 60 {
		t.Errorf("requested TTLSec = %v; want 60 (the default)", sign.gotCmds)
	}
}
