package tools_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// trackingSSH records per-target probe outcomes. Tests configure the
// canned reply keyed by host so a single fake can serve multiple
// servers in the same Status() call.
type trackingSSH struct {
	mu       sync.Mutex
	stdouts  map[string][]byte
	errs     map[string]error
	gotProbe map[string]string // host -> command observed
}

func newTrackingSSH() *trackingSSH {
	return &trackingSSH{
		stdouts:  make(map[string][]byte),
		errs:     make(map[string]error),
		gotProbe: make(map[string]string),
	}
}

func (t *trackingSSH) setOK(host, body string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stdouts[host] = []byte(body)
}

func (t *trackingSSH) setErr(host string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errs[host] = err
}

func (t *trackingSSH) Run(_ context.Context, host, _ string, _ int, cmd string) ([]byte, []byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gotProbe[host] = cmd
	if err := t.errs[host]; err != nil {
		return nil, nil, 1, err
	}
	body, ok := t.stdouts[host]
	if !ok {
		body = []byte("VELGATE_OK\n")
	}
	return body, nil, 0, nil
}

// startUnixListener boots a one-off unix listener at path and returns
// a cleanup to close it.
func startUnixListener(t *testing.T, path string) func() {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return func() {
		_ = l.Close()
		<-done
	}
}

func TestStatus_VelsignerReachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "velsigner.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:           r,
		Sign:              &fakeSign{},
		SSH:               newTrackingSSH(),
		VelsignerSockPath: sockPath,
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !out.VelsignerSocket.Reachable {
		t.Errorf("VelsignerSocket.Reachable = false; want true (err=%q)", out.VelsignerSocket.Error)
	}
	if out.VelsignerSocket.Path != sockPath {
		t.Errorf("VelsignerSocket.Path = %q; want %q", out.VelsignerSocket.Path, sockPath)
	}
	if out.VelsignerSocket.Error != "" {
		t.Errorf("VelsignerSocket.Error = %q; want empty", out.VelsignerSocket.Error)
	}
	if len(out.Servers) != 0 {
		t.Errorf("Servers len = %d; want 0", len(out.Servers))
	}
}

func TestStatus_VelsignerMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:           r,
		Sign:              &fakeSign{},
		SSH:               newTrackingSSH(),
		VelsignerSockPath: filepath.Join(dir, "missing.sock"),
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.VelsignerSocket.Reachable {
		t.Error("VelsignerSocket.Reachable = true; want false")
	}
	if out.VelsignerSocket.Error == "" {
		t.Error("VelsignerSocket.Error is empty; want a dial-failure message")
	}
}

func TestStatus_MixedServerReachability(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "velsigner.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := r.Add("alive", registry.Entry{Host: "alive.example.com", Port: 22, User: "ops", AddedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("dead", registry.Entry{Host: "dead.example.com", Port: 22, User: "ops", AddedAt: now}); err != nil {
		t.Fatal(err)
	}

	ssh := newTrackingSSH()
	ssh.setOK("alive.example.com", "VELGATE_OK\n")
	ssh.setErr("dead.example.com", fmt.Errorf("dial: connection refused"))

	runner := &tools.Runner{
		Servers:           r,
		Sign:              &fakeSign{},
		SSH:               ssh,
		VelsignerSockPath: sockPath,
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(out.Servers) != 2 {
		t.Fatalf("Servers len = %d; want 2", len(out.Servers))
	}
	// Sorted alphabetically by alias.
	if out.Servers[0].Alias != "alive" || out.Servers[1].Alias != "dead" {
		t.Errorf("server aliases out of order: %+v", out.Servers)
	}
	if !out.Servers[0].Reachable {
		t.Errorf("alive should be reachable; got err=%q", out.Servers[0].Error)
	}
	if out.Servers[1].Reachable {
		t.Errorf("dead should be unreachable")
	}
	if out.Servers[1].Error == "" {
		t.Error("dead.Error is empty; want dial-failure message")
	}
	// Each server's probe is the empty SSH_ORIGINAL_COMMAND.
	if ssh.gotProbe["alive.example.com"] != "" {
		t.Errorf("alive probe cmd = %q; want empty (VELGATE_OK probe)", ssh.gotProbe["alive.example.com"])
	}
}

func TestStatus_ProbeWithoutVelgateOKMarkedUnreachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "velsigner.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add("h1", registry.Entry{Host: "h1.example.com", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	ssh := newTrackingSSH()
	// Probe returns success but body is not VELGATE_OK — treat as unreachable.
	ssh.setOK("h1.example.com", "hello world\n")
	runner := &tools.Runner{
		Servers:           r,
		Sign:              &fakeSign{},
		SSH:               ssh,
		VelsignerSockPath: sockPath,
	}
	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.Servers[0].Reachable {
		t.Errorf("Reachable = true; want false (non-VELGATE_OK probe body)")
	}
}

func TestStatus_NilSSHRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, _ := registry.New(filepath.Join(dir, "servers.json"))
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}}
	_, err := runner.Status(context.Background(), tools.StatusInput{})
	if err == nil {
		t.Fatal("expected error when SSH is nil")
	}
}
