package tools_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestStatus_EmptySignerSockPath asserts that an unconfigured signer
// socket path (empty string — the Tier-1 default before /sshgate:setup)
// is reported with a clear "not configured" Error and Reachable=false,
// rather than attempting a dial against the empty path.
func TestStatus_EmptySignerSockPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: "", // unconfigured
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.SignerSocket.Reachable {
		t.Error("SignerSocket.Reachable = true; want false (path not configured)")
	}
	if out.SignerSocket.Configured {
		t.Error("SignerSocket.Configured = true; want false (path not configured)")
	}
	if !strings.Contains(out.SignerSocket.Error, "not configured") {
		t.Errorf("SignerSocket.Error = %q; want a 'not configured' message", out.SignerSocket.Error)
	}
	if out.SignerSocket.Path != "" {
		t.Errorf("SignerSocket.Path = %q; want empty (echoed verbatim)", out.SignerSocket.Path)
	}
}

// TestStatus_ManyServers_BoundedWorkerPool_Race drives Status against more
// servers than the worker-pool cap (statusServerProbeWorkers = 4) so the
// bounded fan-out is exercised. Run under `-race` this catches data races
// in the per-index status slice writes and the shared probe fake.
//
// Each probe response is keyed by host, mixing reachable and unreachable
// servers so both branches of probeServer run concurrently.
func TestStatus_ManyServers_BoundedWorkerPool_Race(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "signer.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}

	const n = 12 // > 4 (the worker-pool cap) so the pool actually bounds
	ssh := newTrackingSSH()
	now := time.Now()
	wantReachable := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		alias := fmt.Sprintf("srv%02d", i)
		host := fmt.Sprintf("%s.example.com", alias)
		if err := r.Add(alias, registry.Entry{Host: host, Port: 22, User: "u", AddedAt: now}); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			// Unreachable: transport error.
			ssh.setErr(host, fmt.Errorf("dial: connection refused"))
			wantReachable[alias] = false
		} else {
			ssh.setOK(host, "SSHGATE_OK\n")
			wantReachable[alias] = true
		}
	}

	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            ssh,
		SignerSockPath: sockPath,
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(out.Servers) != n {
		t.Fatalf("Servers len = %d; want %d", len(out.Servers), n)
	}
	// Results must be alpha-sorted and each must carry the reachability
	// matching its host — proving the per-index writes landed in the right
	// slot under the bounded pool.
	for i := 1; i < len(out.Servers); i++ {
		if out.Servers[i-1].Alias >= out.Servers[i].Alias {
			t.Errorf("servers not alpha-sorted at %d: %q >= %q",
				i, out.Servers[i-1].Alias, out.Servers[i].Alias)
		}
	}
	for _, s := range out.Servers {
		if want := wantReachable[s.Alias]; s.Reachable != want {
			t.Errorf("server %q Reachable=%v; want %v (slot mis-assignment under the pool?)",
				s.Alias, s.Reachable, want)
		}
	}
	if !out.SignerSocket.Reachable {
		t.Errorf("SignerSocket.Reachable=false; want true (err=%q)", out.SignerSocket.Error)
	}
}
