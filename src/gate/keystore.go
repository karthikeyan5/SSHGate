package gate

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPubKey reads an Ed25519 public key from path. The file may
// contain either:
//
//   - the raw 32-byte binary public key, or
//   - a PEM-encoded block whose body is the 32-byte raw key.
//
// LoadPubKey refuses to load if the file mode is more permissive than
// 0644 — specifically, it rejects any file with group-write or
// world-write bits set. The public key is, well, public, so its read
// bits do not need to be restricted; what matters is that nothing
// other than the owner can write to it, because the trust anchor for
// the entire signature chain is "this file's contents."
//
// Missing file is NOT an error: LoadPubKey returns (nil, nil) when
// path does not exist. This represents the tier-1 read-only install
// mode — gate is deployed but no signer is set up, so signatures
// cannot be verified. Callers distinguish this from the "key exists
// but is broken" case (which still returns a non-nil error) and
// implement their own policy (typically: allow reads, deny writes).
func LoadPubKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		// Read-only mode: no key configured.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat pubkey: %w", err)
	}
	mode := info.Mode().Perm()
	// Reject group-write (0020) and world-write (0002).
	if mode&0o022 != 0 {
		return nil, fmt.Errorf("pubkey %s has insecure mode %#o (group/world write must be off)", path, mode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}

	// PEM form: try to parse a PEM block first.
	if block, _ := pem.Decode(data); block != nil {
		if len(block.Bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey PEM body is %d bytes, want %d", len(block.Bytes), ed25519.PublicKeySize)
		}
		out := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(out, block.Bytes)
		return out, nil
	}

	// Raw form.
	if len(data) != ed25519.PublicKeySize {
		return nil, errors.New("pubkey is neither PEM nor a 32-byte raw Ed25519 key")
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, data)
	return out, nil
}
