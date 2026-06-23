package registry

// Internal-package tests for the content-hash reload signal. They live in
// `package registry` (not registry_test) because the warn-once assertion needs
// to swap the unexported `warnw` sink for a buffer. Keep them OUT of t.Parallel
// where they touch warnw, so the shared sink is not raced between tests.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReload_EqualSizeSameTickEditPickedUp proves the change signal is
// content-based, not (mtime,size)-based. An out-of-band edit that preserves
// byte length AND lands in the same mtime tick (coarse-resolution FS) must
// still be picked up — otherwise Get/List serve a STALE Host (a trust-boundary
// value). This FAILS under the old (mtime,size) signal.
func TestReload_EqualSizeSameTickEditPickedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")

	// host 10.0.0.1 — note the rewrite below swaps to 10.0.0.9: SAME byte length.
	const before = `{"web1":{"host":"10.0.0.1","port":22,"user":"u","added_at":"2026-01-01T00:00:00Z"}}`
	const after = `{"web1":{"host":"10.0.0.9","port":22,"user":"u","added_at":"2026-01-01T00:00:00Z"}}`
	if len(before) != len(after) {
		t.Fatalf("test bug: before/after must be equal length (%d vs %d)", len(before), len(after))
	}

	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	// Pin a fixed mtime so the rewrite below can be pinned to the SAME tick.
	pin := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, pin, pin); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e, ok := s.Get("web1"); !ok || e.Host != "10.0.0.1" {
		t.Fatalf("initial Get web1 = (%+v, %v); want host 10.0.0.1", e, ok)
	}

	// Out-of-band edit: identical byte length, and re-pin the SAME mtime so the
	// (mtime,size) pair is unchanged — only the CONTENT differs.
	if err := os.WriteFile(path, []byte(after), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, pin, pin); err != nil {
		t.Fatal(err)
	}

	e, ok := s.Get("web1")
	if !ok {
		t.Fatalf("web1 missing after same-tick edit")
	}
	if e.Host != "10.0.0.9" {
		t.Fatalf("Get web1 host = %q; want 10.0.0.9 (same-size same-tick edit not picked up — stale trust-boundary value)", e.Host)
	}
}

// TestReload_WarnsOncePerBadVersion proves a failed reload (corrupt JSON) is
// warned about exactly ONCE per distinct file version, not on every subsequent
// Get/List. Without recording the bad body's identity, each List re-reads,
// re-fails, and re-warns forever — unbounded stderr spam.
func TestReload_WarnsOncePerBadVersion(t *testing.T) {
	// NOT parallel: swaps the shared unexported warnw sink.
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")

	const good = `{"web1":{"host":"10.0.0.1","port":22,"user":"u","added_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Swap the warning sink AFTER New (New's Load on good data emits nothing,
	// but be explicit) so we only capture reload-fail warnings.
	var buf bytes.Buffer
	orig := warnw
	warnw = &buf
	t.Cleanup(func() { warnw = orig })

	// Corrupt the file out-of-band.
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		out := s.List()
		if len(out) != 1 {
			t.Fatalf("List #%d len = %d; want 1 (best-effort reload must keep last-good)", i, len(out))
		}
		if e, ok := s.Get("web1"); !ok || e.Host != "10.0.0.1" {
			t.Fatalf("Get #%d web1 = (%+v, %v); want last-good host 10.0.0.1", i, e, ok)
		}
	}

	got := strings.Count(buf.String(), "reload failed")
	if got != 1 {
		t.Fatalf("reload-fail warning emitted %d times; want exactly 1 per distinct bad version\n---sink---\n%s", got, buf.String())
	}
}
