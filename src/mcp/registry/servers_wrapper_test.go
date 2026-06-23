package registry_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// The registry is persisted and read as a BARE alias→Entry map: top-level
// JSON keys ARE the aliases. Two historical install snippets, however, seeded
// the file with a WRAPPED shape {"servers":{}} (or {"servers":{...}}). Read as
// a bare map that decodes to ONE alias literally named "servers" whose value
// is a zero-value Entry — a PHANTOM server — or, for a populated wrapper,
// silently drops the real servers. These tests pin the loader's handling of
// the legacy wrapper: empty wrappers normalise to an empty registry (with a
// stderr warning); populated wrappers are a hard error so the MCP refuses to
// start rather than silently losing the fleet.

// TestLoad_WrapperEmptyObjectIsEmptyRegistry is the phantom-alias
// reproduction: {"servers":{}} must load as an EMPTY registry, never as a
// server aliased "servers".
func TestLoad_WrapperEmptyObjectIsEmptyRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte(`{"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on empty wrapper: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Errorf("List len = %d; want 0 (no phantom 'servers' alias)", got)
	}
	if _, ok := s.Get("servers"); ok {
		t.Error("phantom 'servers' alias present; empty wrapper must yield an empty registry")
	}
}

// TestLoad_WrapperNullIsEmptyRegistry pins {"servers":null} → empty, no error.
func TestLoad_WrapperNullIsEmptyRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte(`{"servers":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on null wrapper: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Errorf("List len = %d; want 0", got)
	}
}

// TestLoad_WrapperPopulatedIsHardError is the data-loss guard: a populated
// wrapper would silently drop real servers under a bare-map read, so the
// loader must refuse to start and name the dropped alias.
func TestLoad_WrapperPopulatedIsHardError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	body := `{"servers":{"src-x":{"host":"1.2.3.4","port":22,"user":"deploy","added_at":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := registry.New(path)
	if err == nil {
		t.Fatal("New on populated wrapper returned nil; want error (data-loss guard)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "src-x") {
		t.Errorf("error %q does not name the dropped alias src-x", msg)
	}
	if !strings.Contains(msg, "wrapped") && !strings.Contains(msg, "unsupported") {
		t.Errorf("error %q does not mention the unsupported/wrapped format", msg)
	}
}

// TestLoad_BareEmptyObjectIsEmptyRegistry is a regression guard: a bare {}
// must still load as an empty registry.
func TestLoad_BareEmptyObjectIsEmptyRegistry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on bare {}: %v", err)
	}
	if got := len(s.List()); got != 0 {
		t.Errorf("List len = %d; want 0", got)
	}
}

// TestLoad_BarePopulatedLoads is a regression guard: a normal bare populated
// map loads its aliases.
func TestLoad_BarePopulatedLoads(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	body := `{"web1":{"host":"h","port":22,"user":"u","added_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on bare populated map: %v", err)
	}
	e, ok := s.Get("web1")
	if !ok {
		t.Fatal("web1 missing")
	}
	if e.Host != "h" {
		t.Errorf("web1.Host = %q; want h", e.Host)
	}
}

// TestLoad_RealServerAliasedServers is the disambiguation guard (critical): a
// REAL server literally aliased "servers" WITH a host must load correctly as
// one server, NOT be misfired as the legacy empty wrapper. The trigger keys on
// the Entry being the zero value; a real server has a non-empty Host.
func TestLoad_RealServerAliasedServers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.json")
	body := `{"servers":{"host":"h","port":22,"user":"u","added_at":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := registry.New(path)
	if err != nil {
		t.Fatalf("New on real server aliased 'servers': %v", err)
	}
	if got := len(s.List()); got != 1 {
		t.Fatalf("List len = %d; want 1 (the real 'servers' alias must load)", got)
	}
	e, ok := s.Get("servers")
	if !ok {
		t.Fatal("real 'servers' alias missing; loader misfired the wrapper detection")
	}
	if e.Host != "h" {
		t.Errorf("servers.Host = %q; want h", e.Host)
	}
}
