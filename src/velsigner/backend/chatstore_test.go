package backend_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

func TestMemChatStore_LoadEmpty(t *testing.T) {
	t.Parallel()
	var s backend.MemChatStore
	id, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load err: %v", err)
	}
	if ok {
		t.Errorf("ok = true on empty store; want false")
	}
	if id != 0 {
		t.Errorf("id = %d; want 0", id)
	}
}

func TestMemChatStore_SaveLoadRoundtrip(t *testing.T) {
	t.Parallel()
	var s backend.MemChatStore
	if err := s.Save(123456); err != nil {
		t.Fatalf("Save err: %v", err)
	}
	id, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load err: %v", err)
	}
	if !ok {
		t.Fatal("ok = false after Save")
	}
	if id != 123456 {
		t.Errorf("id = %d; want 123456", id)
	}
}

func TestMemChatStore_SaveOverwrite(t *testing.T) {
	t.Parallel()
	var s backend.MemChatStore
	if err := s.Save(1); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	if err := s.Save(2); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	id, _, _ := s.Load()
	if id != 2 {
		t.Errorf("id = %d; want 2 (overwrite)", id)
	}
}

func TestFileChatStore_LoadMissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := &backend.FileChatStore{Path: filepath.Join(dir, "peer.json")}
	id, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load on missing file err: %v; want nil", err)
	}
	if ok {
		t.Errorf("ok = true on missing file; want false")
	}
	if id != 0 {
		t.Errorf("id = %d; want 0", id)
	}
}

func TestFileChatStore_SaveLoadRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := &backend.FileChatStore{Path: filepath.Join(dir, "peer.json")}
	if err := s.Save(99999999); err != nil {
		t.Fatalf("Save: %v", err)
	}
	id, ok, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("ok = false after Save")
	}
	if id != 99999999 {
		t.Errorf("id = %d; want 99999999", id)
	}
}

func TestFileChatStore_SaveSetsMode0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.json")
	s := &backend.FileChatStore{Path: path}
	if err := s.Save(42); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o; want 0600", perm)
	}
}

func TestFileChatStore_RefusesOverwriteWithWrongMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.json")
	// Pre-create with broader mode.
	if err := os.WriteFile(path, []byte(`{"chat_id":1}`), 0o644); err != nil {
		t.Fatalf("pre-create: %v", err)
	}
	s := &backend.FileChatStore{Path: path}
	err := s.Save(2)
	if err == nil {
		t.Fatal("Save returned nil; want refusal due to broad mode")
	}
}

func TestFileChatStore_AtomicWrite_NoTempLeak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := &backend.FileChatStore{Path: filepath.Join(dir, "peer.json")}
	if err := s.Save(1); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// After successful save, only the target file should remain — no
	// .peer.*.tmp leftovers.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "peer.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir entries = %v; want [peer.json]", names)
	}
}

func TestFileChatStore_LoadCorruptJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := &backend.FileChatStore{Path: path}
	if _, _, err := s.Load(); err == nil {
		t.Fatal("Load returned nil err on corrupt JSON; want parse error")
	}
}

func TestFileChatStore_RefusesSaveZero(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := &backend.FileChatStore{Path: filepath.Join(dir, "peer.json")}
	if err := s.Save(0); err == nil {
		t.Fatal("Save(0) returned nil; want refusal")
	}
}
