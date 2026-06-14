package redteam

import (
	"os"
	"path/filepath"
	"testing"
)

// TestState_RoundTrip proves Save/Load preserves the standing-target
// connection state, and LoadTarget reconstructs a *Target with the right
// fields WITHOUT any Docker.
func TestState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	want := State{
		ComposeFile:      "/repo/tests/integration/docker-compose.yml",
		KeyPath:          dir + "/keys/id_ed25519",
		KnownHosts:       dir + "/keys/known_hosts",
		Sentinel:         "REDTEAM-SECRET-deadbeef",
		FixturesPub:      "/repo/tests/integration/fixtures/keys/sshgate_ed25519.pub",
		KeyDir:           dir + "/keys",
		WatchLog:         watchLog,
		TripwireFallback: true,
		BroughtUp:        "2026-06-14T00:00:00Z",
	}
	if err := SaveState(path, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	// State file must be 0600 (it names a private-key path).
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %#o; want 0600", perm)
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}

	tgt := LoadTarget(got)
	if tgt.composeFile != want.ComposeFile {
		t.Errorf("LoadTarget composeFile = %q; want %q", tgt.composeFile, want.ComposeFile)
	}
	if tgt.sentinel != want.Sentinel {
		t.Errorf("LoadTarget sentinel = %q; want %q", tgt.sentinel, want.Sentinel)
	}
	if !tgt.tripwireFallback {
		t.Errorf("LoadTarget tripwireFallback = false; want true")
	}
	if tgt.cli == nil || tgt.cli.KeyPath != want.KeyPath {
		t.Errorf("LoadTarget cli not wired with KeyPath %q", want.KeyPath)
	}
	if tgt.Sentinel() != want.Sentinel {
		t.Errorf("Sentinel() = %q; want %q", tgt.Sentinel(), want.Sentinel)
	}
	if tgt.TripwireMode() != "snapshot" {
		t.Errorf("TripwireMode() = %q; want snapshot", tgt.TripwireMode())
	}
}

// TestLoadState_Missing distinguishes "no standing target" from a real
// error via os.IsNotExist.
func TestLoadState_Missing(t *testing.T) {
	_, err := LoadState(filepath.Join(t.TempDir(), "nope.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("LoadState(missing) err = %v; want IsNotExist", err)
	}
}

// TestDownTarget_Idempotent proves `down` with no state file is a clean
// no-op (idempotent + safe).
func TestDownTarget_Idempotent(t *testing.T) {
	actions, err := DownTarget(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("DownTarget(absent): %v", err)
	}
	if len(actions) == 0 {
		t.Errorf("expected a 'nothing to do' action message")
	}
}
