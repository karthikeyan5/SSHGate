package registry_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// TestLoad_CorruptJSONErrors asserts that a malformed servers.json is a
// hard error (not silently treated as empty) — a corrupt registry must
// fail loudly so the operator notices rather than silently losing aliases.
func TestLoad_CorruptJSONErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New(path); err == nil {
		t.Error("New on corrupt JSON returned nil; want error")
	}
}

// TestLoad_EmptyBodyIsEmptyRegistry asserts a zero-byte file loads as an
// empty registry (not an error) — this is the state right after an
// install creates the file but before the first Add.
func TestLoad_EmptyBodyIsEmptyRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on empty body: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Errorf("List len = %d; want 0", got)
	}
}

// TestLoad_JSONNullIsEmptyRegistry asserts that a literal JSON `null`
// body decodes to an empty (non-nil) registry — json.Unmarshal yields a
// nil map for null, which Load normalises so Add does not panic.
func TestLoad_JSONNullIsEmptyRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on null body: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Errorf("List len = %d; want 0", got)
	}
	// Add must succeed (proves the nil-map normalisation worked).
	if err := s.Add("a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Errorf("Add after null load: %v", err)
	}
}

// TestAdd_EmptyAliasRejected asserts Add refuses an empty alias and does
// not write any file (the persist step must never run for a rejected key).
func TestAdd_EmptyAliasRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add("", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err == nil {
		t.Error("Add with empty alias returned nil; want error")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("servers.json was written despite rejected empty-alias Add")
	}
}

// TestReadOnly_RoundTrip asserts the ReadOnly flag persists through a
// marshal/reload cycle. Tier-1 (read-only) aliases must reload as
// read-only so run/run_batch keep short-circuiting writes before
// soliciting a wasted approval.
func TestReadOnly_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	if err := s.Add("ro", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: now, ReadOnly: true}); err != nil {
		t.Fatalf("Add read-only: %v", err)
	}
	if err := s.Add("rw", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: now}); err != nil {
		t.Fatalf("Add read-write: %v", err)
	}

	// The on-disk JSON must carry read_only for "ro" and omit it for "rw".
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if ro, ok := raw["ro"]["read_only"].(bool); !ok || !ro {
		t.Errorf("on-disk ro.read_only = %v; want true", raw["ro"]["read_only"])
	}
	if _, present := raw["rw"]["read_only"]; present {
		t.Errorf("rw entry serialised read_only; want it omitted (omitempty)")
	}

	// Reload and confirm the flag survived.
	s2, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	roEntry, ok := s2.Get("ro")
	if !ok {
		t.Fatal("ro missing after reload")
	}
	if !roEntry.ReadOnly {
		t.Error("ro.ReadOnly = false after reload; want true")
	}
	rwEntry, ok := s2.Get("rw")
	if !ok {
		t.Fatal("rw missing after reload")
	}
	if rwEntry.ReadOnly {
		t.Error("rw.ReadOnly = true after reload; want false")
	}
}

// TestAdd_PersistFailureRollsBack asserts that when persist() fails (here
// because the registry directory is not writable, so CreateTemp can't
// make the tmp file), the in-memory state rolls back: a brand-new alias
// is removed, and a replaced alias's previous value is restored. We skip
// when running as root, since root bypasses the directory-write
// permission check.
func TestAdd_PersistFailureRollsBack(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory perms do not block writes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	s, err := registry.New(path)
	if err != nil {
		t.Fatal(err)
	}
	// Seed an existing alias successfully (dir still writable).
	prev := registry.Entry{Host: "old", Port: 22, User: "u", AddedAt: time.Now()}
	if err := s.Add("existing", prev); err != nil {
		t.Fatalf("seed Add: %v", err)
	}

	// Now make the directory non-writable so persist's CreateTemp fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// Replacing an existing alias: failure must restore the previous value.
	if err := s.Add("existing", registry.Entry{Host: "new", Port: 22, User: "u", AddedAt: time.Now()}); err == nil {
		t.Fatal("Add into non-writable dir returned nil; want error")
	}
	got, ok := s.Get("existing")
	if !ok {
		t.Fatal("existing alias vanished after failed replace; want rollback to keep it")
	}
	if got.Host != "old" {
		t.Errorf("existing.Host = %q after failed replace; want rollback to %q", got.Host, "old")
	}

	// Adding a brand-new alias: failure must remove it entirely.
	if err := s.Add("fresh", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err == nil {
		t.Fatal("Add fresh into non-writable dir returned nil; want error")
	}
	if _, ok := s.Get("fresh"); ok {
		t.Error("fresh alias present after failed Add; want rollback to delete it")
	}
}
