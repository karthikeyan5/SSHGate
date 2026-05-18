package velgate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/src/velgate"
)

// writeKey writes the supplied public key bytes to path with mode.
func writeKey(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// WriteFile honors the umask; ensure exact mode via Chmod.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

func TestLoadPubKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	dir := t.TempDir()

	t.Run("loads raw 32-byte binary at mode 0644", func(t *testing.T) {
		path := filepath.Join(dir, "raw.pub")
		writeKey(t, path, pub, 0o644)
		got, err := velgate.LoadPubKey(path)
		if err != nil {
			t.Fatalf("LoadPubKey: %v", err)
		}
		if len(got) != ed25519.PublicKeySize {
			t.Fatalf("len = %d, want %d", len(got), ed25519.PublicKeySize)
		}
		for i := range pub {
			if pub[i] != got[i] {
				t.Fatalf("byte %d differs", i)
			}
		}
	})

	t.Run("loads at mode 0600", func(t *testing.T) {
		path := filepath.Join(dir, "raw-tight.pub")
		writeKey(t, path, pub, 0o600)
		_, err := velgate.LoadPubKey(path)
		if err != nil {
			t.Fatalf("LoadPubKey: %v", err)
		}
	})

	t.Run("loads PEM-encoded public key", func(t *testing.T) {
		path := filepath.Join(dir, "pem.pub")
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "ED25519 PUBLIC KEY",
			Bytes: pub,
		})
		writeKey(t, path, pemBytes, 0o644)
		got, err := velgate.LoadPubKey(path)
		if err != nil {
			t.Fatalf("LoadPubKey: %v", err)
		}
		if len(got) != ed25519.PublicKeySize {
			t.Fatalf("len = %d", len(got))
		}
	})

	t.Run("refuses world-write 0666", func(t *testing.T) {
		path := filepath.Join(dir, "loose1.pub")
		writeKey(t, path, pub, 0o666)
		_, err := velgate.LoadPubKey(path)
		if err == nil {
			t.Fatal("LoadPubKey accepted mode 0666; want error")
		}
	})

	t.Run("refuses group-write 0664", func(t *testing.T) {
		path := filepath.Join(dir, "loose2.pub")
		writeKey(t, path, pub, 0o664)
		_, err := velgate.LoadPubKey(path)
		if err == nil {
			t.Fatal("LoadPubKey accepted mode 0664; want error")
		}
	})

	t.Run("refuses world-write 0646", func(t *testing.T) {
		path := filepath.Join(dir, "loose3.pub")
		writeKey(t, path, pub, 0o646)
		_, err := velgate.LoadPubKey(path)
		if err == nil {
			t.Fatal("LoadPubKey accepted mode 0646; want error")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		_, err := velgate.LoadPubKey(filepath.Join(dir, "missing.pub"))
		if err == nil {
			t.Fatal("LoadPubKey on missing file: want error")
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want wrapping fs.ErrNotExist", err)
		}
	})

	t.Run("corrupt key data errors", func(t *testing.T) {
		path := filepath.Join(dir, "corrupt.pub")
		writeKey(t, path, []byte("not a key at all"), 0o644)
		_, err := velgate.LoadPubKey(path)
		if err == nil {
			t.Fatal("LoadPubKey on garbage: want error")
		}
	})
}
