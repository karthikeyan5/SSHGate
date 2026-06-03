package tools_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestStatus_Tier1SignerNotConfigured asserts that when the signer
// socket does not exist (Tier 1: no daemon installed), status reports
// Configured=false rather than presenting it as a failure. Audit M4.
func TestStatus_Tier1SignerNotConfigured(t *testing.T) {
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
		SignerSockPath: filepath.Join(dir, "nonexistent.sock"),
	}

	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if out.SignerSocket.Reachable {
		t.Error("Reachable = true; want false (socket absent)")
	}
	if out.SignerSocket.Configured {
		t.Error("Configured = true; want false (Tier 1: socket file absent)")
	}
	// The probed path must be reported verbatim.
	if out.SignerSocket.Path != runner.SignerSockPath {
		t.Errorf("Path = %q; want %q", out.SignerSocket.Path, runner.SignerSockPath)
	}
}

// TestStatus_Tier2SignerConfiguredAndReachable asserts that when the
// socket exists and dials, both Configured and Reachable are true.
func TestStatus_Tier2SignerConfiguredAndReachable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "signer.sock")
	cleanup := startUnixListener(t, sockPath)
	t.Cleanup(cleanup)

	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            newTrackingSSH(),
		SignerSockPath: sockPath,
	}
	out, err := runner.Status(context.Background(), tools.StatusInput{})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !out.SignerSocket.Reachable {
		t.Errorf("Reachable = false; want true (err=%q)", out.SignerSocket.Error)
	}
	if !out.SignerSocket.Configured {
		t.Error("Configured = false; want true (socket present and dialable)")
	}
}
