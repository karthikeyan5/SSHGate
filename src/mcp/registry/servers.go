package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is the on-disk record for one server alias. AddedAt is
// persisted in JSON so the audit log can correlate "when was this
// alias registered" with the approval timeline.
type Entry struct {
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	User    string    `json:"user"`
	AddedAt time.Time `json:"added_at"`
}

// Servers is the alias → Entry map backed by the file at Path. All
// methods are safe for concurrent calls. A missing file is treated as
// an empty registry; the first Add creates it with mode 0o600.
type Servers struct {
	path string

	mu   sync.Mutex
	data map[string]Entry
}

// New opens the registry at path. It performs the permission check
// (per daemon.md §5.2 — refuses any group- or world-write bit) and
// loads existing contents. A missing file is not an error; the data
// map is initialised empty.
func New(path string) (*Servers, error) {
	s := &Servers{path: path, data: make(map[string]Entry)}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load re-reads the file at Path into memory. Callers normally do not
// invoke this directly — New does it on construction — but tests rely
// on it.
//
// Load returns nil if the file does not exist (empty registry). It
// returns an error if the file is group- or world-writable, or if the
// JSON is malformed.
func (s *Servers) Load() error {
	info, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.mu.Lock()
		s.data = make(map[string]Entry)
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", s.path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("registry %s has insecure mode %#o (group/world writable)", s.path, perm)
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	if len(body) == 0 {
		s.mu.Lock()
		s.data = make(map[string]Entry)
		s.mu.Unlock()
		return nil
	}
	var loaded map[string]Entry
	if err := json.Unmarshal(body, &loaded); err != nil {
		return fmt.Errorf("unmarshal %s: %w", s.path, err)
	}
	if loaded == nil {
		loaded = make(map[string]Entry)
	}
	s.mu.Lock()
	s.data = loaded
	s.mu.Unlock()
	return nil
}

// Get returns the entry for alias, or false if it is not registered.
func (s *Servers) Get(alias string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[alias]
	return e, ok
}

// List returns a copy of the registry. Mutating the returned map does
// not affect the Servers state.
func (s *Servers) List() map[string]Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Entry, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

// Add inserts or replaces alias with e and persists the registry
// atomically (tmp + fsync + rename + fsync(parent), per daemon.md
// §5.1). If the write fails the in-memory state is rolled back so
// callers observing Get see a consistent registry.
func (s *Servers) Add(alias string, e Entry) error {
	if alias == "" {
		return errors.New("registry: alias is empty")
	}
	s.mu.Lock()
	prev, hadPrev := s.data[alias]
	s.data[alias] = e
	snapshot := s.cloneLocked()
	s.mu.Unlock()

	if err := s.persist(snapshot); err != nil {
		s.mu.Lock()
		if hadPrev {
			s.data[alias] = prev
		} else {
			delete(s.data, alias)
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

// Remove deletes the entry for alias. It returns an error if alias is
// not registered (so callers can surface a clean "unknown alias"
// message to operators).
func (s *Servers) Remove(alias string) error {
	s.mu.Lock()
	prev, ok := s.data[alias]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registry: unknown alias %q", alias)
	}
	delete(s.data, alias)
	snapshot := s.cloneLocked()
	s.mu.Unlock()

	if err := s.persist(snapshot); err != nil {
		s.mu.Lock()
		s.data[alias] = prev
		s.mu.Unlock()
		return err
	}
	return nil
}

// cloneLocked returns a copy of s.data; caller must already hold s.mu.
func (s *Servers) cloneLocked() map[string]Entry {
	out := make(map[string]Entry, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

// persist atomically rewrites Path with the contents of m. The write
// pattern is the standard "tmp + fsync + rename + fsync(parent)" so a
// crash mid-write never leaves a partial file at Path.
func (s *Servers) persist(m map[string]Entry) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".servers.*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	// On any subsequent error we want to clean up the tmp file.
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	// Fsync the parent directory so the rename is durable.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}
