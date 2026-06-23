package registry_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// registry.New loads the file ONCE at MCP startup; Get/List then read a cached
// map. A human `sshgate add` runs in a SEPARATE process and rewrites the file,
// so the running MCP would never see the new server until relaunch. These
// tests pin that the read path re-reads the file when it changes on disk.

// TestList_ReloadsOnFileChange proves an out-of-band rewrite (a second server
// added by another process) becomes visible through List() WITHOUT an explicit
// Load() call.
func TestList_ReloadsOnFileChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	writeBare := func(m map[string]registry.Entry) {
		t.Helper()
		body, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeBare(map[string]registry.Entry{
		"web1": {Host: "h1", Port: 22, User: "u", AddedAt: now},
	})
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(s.List()); got != 1 {
		t.Fatalf("initial List len = %d; want 1", got)
	}

	// Out-of-band rewrite with a SECOND server. Bump mtime explicitly so the
	// change is detectable even on coarse-grained filesystem clocks (the test
	// would otherwise be flaky if both writes land in the same mtime tick).
	writeBare(map[string]registry.Entry{
		"web1": {Host: "h1", Port: 22, User: "u", AddedAt: now},
		"web2": {Host: "h2", Port: 22, User: "u", AddedAt: now},
	})
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	out := s.List()
	if len(out) != 2 {
		t.Fatalf("List len after out-of-band add = %d; want 2 (reload-on-change failed)", len(out))
	}
	if _, ok := s.Get("web2"); !ok {
		t.Error("web2 not visible after out-of-band add; reload-on-change failed")
	}
}

// TestReload_BadFileKeepsExistingData proves the reload is BEST-EFFORT: if the
// file is rewritten into an unparseable state, List/Get keep serving the last
// good in-memory data instead of clobbering or erroring.
func TestReload_BadFileKeepsExistingData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]registry.Entry{
		"web1": {Host: "h1", Port: 22, User: "u", AddedAt: now},
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Corrupt the file out-of-band.
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	// List must NOT propagate the error and must keep the last good data.
	out := s.List()
	if len(out) != 1 {
		t.Fatalf("List len after corruption = %d; want 1 (best-effort reload must keep last-good)", len(out))
	}
	if _, ok := s.Get("web1"); !ok {
		t.Error("web1 lost after a failed reload; best-effort reload must not clobber")
	}
}

// TestReload_RaceCleanConcurrent stresses concurrent List() while the file is
// rewritten out-of-band, to surface data races under `go test -race`.
func TestReload_RaceCleanConcurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body, _ := json.Marshal(map[string]registry.Entry{
		"web1": {Host: "h1", Port: 22, User: "u", AddedAt: now},
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer goroutine: rewrite the file (atomic enough for the test — the
	// reader sees a complete old or new file via WriteFile's truncate+write;
	// the production writer uses tmp+rename which is strictly safer).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			b, _ := json.Marshal(map[string]registry.Entry{
				"web1": {Host: "h1", Port: 22, User: "u", AddedAt: now},
				"web2": {Host: "h2", Port: 22, User: "u", AddedAt: now},
			})
			_ = os.WriteFile(path, b, 0o600)
		}
	}()

	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = s.List()
				_, _ = s.Get("web1")
			}
		}()
	}

	// Let readers run a bit, then stop the writer and join.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
