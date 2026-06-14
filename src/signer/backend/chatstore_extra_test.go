package backend_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// TestFileChatStore_LoadPermissionError asserts that an unreadable
// peer.json (mode 0000) surfaces as a Load error — not a silent
// "no chat_id yet". A read failure that ISN'T fs.ErrNotExist must
// propagate so the operator learns the file is broken rather than the
// daemon quietly behaving as if the bot were never linked.
//
// Skipped when running as root, since root bypasses the permission bits
// and the chmod 0000 would not produce an EACCES.
func TestFileChatStore_LoadPermissionError(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 0000 does not deny root, can't exercise EACCES")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.json")
	if err := os.WriteFile(path, []byte(`{"chat_id":99999999}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	// Restore a readable mode so t.TempDir cleanup can remove the file.
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	s := &backend.FileChatStore{Path: path}
	id, ok, err := s.Load()
	if err == nil {
		t.Fatalf("Load on mode-0000 file returned nil err; want a permission error (got id=%d ok=%v)", id, ok)
	}
	if ok {
		t.Errorf("ok = true on unreadable file; want false")
	}
	// It must NOT be misreported as the benign "first-run" missing-file
	// case: Load returns (0,false,nil) only for fs.ErrNotExist.
	if id != 0 {
		t.Errorf("id = %d; want 0 on error", id)
	}
}
