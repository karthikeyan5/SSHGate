package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// ChatStore persists the single DM chat_id that signer-bot will post
// approval requests to. The chat_id is captured the first time the
// allowed user sends `/start` to the bot. Implementations MUST be safe
// for concurrent calls; the polling goroutine writes (via Save) while
// the daemon's request goroutines read (via Load).
type ChatStore interface {
	// Load returns the saved chat_id. If no chat_id has been saved yet
	// (first-run case), ok is false and err is nil. An err is returned
	// only when reading the underlying store fails for a non-"missing"
	// reason (e.g. permission denied, JSON parse error).
	Load() (chatID int64, ok bool, err error)
	// Save persists chatID, overwriting any previous value. Save is
	// idempotent — re-saving the same chat_id is a no-op observable
	// only as the same file mtime moving forward.
	Save(chatID int64) error
}

// MemChatStore is an in-memory ChatStore used by tests. The zero value
// is ready to use.
type MemChatStore struct {
	mu     sync.Mutex
	chatID int64
	have   bool
}

// Load implements ChatStore.
func (m *MemChatStore) Load() (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.chatID, m.have, nil
}

// Save implements ChatStore.
func (m *MemChatStore) Save(chatID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chatID = chatID
	m.have = true
	return nil
}

// FileChatStore persists the chat_id to a JSON file at Path. The file
// is created with mode 0600 (peer.json lives in signer's state
// directory and the bot token sits next to it — same blast radius). A
// pre-existing file with broader permissions is refused on Save to
// prevent silent downgrades; an operator who hand-chmod'd the file is
// asked to fix it.
//
// FileChatStore is safe for concurrent use: an internal mutex
// serialises Load/Save against each other.
type FileChatStore struct {
	Path string
	mu   sync.Mutex
}

type fileChatStoreState struct {
	ChatID int64 `json:"chat_id"`
}

// Load implements ChatStore. A missing file is treated as "no chat_id
// captured yet" (first-run); other errors propagate.
func (f *FileChatStore) Load() (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read %s: %w", f.Path, err)
	}
	var st fileChatStoreState
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, false, fmt.Errorf("parse %s: %w", f.Path, err)
	}
	if st.ChatID == 0 {
		// Treat zero as "not set" — a Save would refuse to write zero
		// anyway, so this only happens if the file was hand-edited.
		return 0, false, nil
	}
	return st.ChatID, true, nil
}

// Save implements ChatStore. The write is atomic (write-to-tmp +
// rename) so a crash mid-write cannot leave a half-written peer.json
// on disk. If the destination file already exists with mode broader
// than 0600, Save refuses — protecting against the case where an
// operator chmod'd the file open and a later overwrite would silently
// inherit that mode.
func (f *FileChatStore) Save(chatID int64) error {
	if chatID == 0 {
		return errors.New("refusing to save chat_id 0")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	// Refuse to overwrite a file with too-permissive mode. (A fresh
	// FileChatStore with no existing file is fine.)
	if info, err := os.Stat(f.Path); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return fmt.Errorf("refusing to overwrite %s: mode %o is broader than 0600", f.Path, perm)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", f.Path, err)
	}

	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	body, err := json.Marshal(fileChatStoreState{ChatID: chatID})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".peer.*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below errors before rename.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, f.Path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	return nil
}

// Compile-time interface checks.
var (
	_ ChatStore = (*MemChatStore)(nil)
	_ ChatStore = (*FileChatStore)(nil)
)
