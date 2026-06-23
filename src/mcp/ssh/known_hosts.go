package ssh

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/karthikeyan5/sshgate/src/hostkey"
)

// ErrHostKeyChanged is returned by a TOFU callback when the host key
// for a hostname has changed since the first connection.
var ErrHostKeyChanged = errors.New("ssh: host key mismatch (possible MITM)")

// TOFU returns an ssh.HostKeyCallback that does trust-on-first-use
// against the known_hosts-format file at path:
//
//   - If the file does not exist (or the host is not yet recorded),
//     the callback appends the host's key to the file with mode 0o600
//     and accepts the connection.
//   - If the host is already recorded and the presented key matches,
//     the callback accepts.
//   - If the host is recorded with a different key, the callback
//     refuses with an error wrapping ErrHostKeyChanged that includes
//     both fingerprints.
//
// The callback serialises access internally so concurrent dials to
// different hosts cannot race on a write.
func TOFU(path string) ssh.HostKeyCallback {
	var mu sync.Mutex
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()

		// Try the existing file first. knownhosts.New stat's the file
		// internally and returns an error if it's missing — handle that
		// case by treating "no file" as "no known hosts."
		if _, err := os.Stat(path); err == nil {
			cb, err := knownhosts.New(path)
			if err != nil {
				return fmt.Errorf("ssh: load known_hosts %s: %w", path, err)
			}
			if err := cb(hostname, remote, key); err != nil {
				var kerr *knownhosts.KeyError
				if errors.As(err, &kerr) {
					if len(kerr.Want) == 0 {
						// Hostname not recorded yet; fall through to append.
					} else {
						// Mismatch: build a helpful error with both fingerprints.
						return fmt.Errorf("%w: host=%s presented=%s expected=%s",
							ErrHostKeyChanged, hostname, fingerprint(key), fingerprintFromKnown(kerr.Want))
					}
				} else {
					return fmt.Errorf("ssh: host-key verify: %w", err)
				}
			} else {
				return nil
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("ssh: stat known_hosts: %w", err)
		}

		// First contact (or hostname not recorded): append.
		if err := appendKnownHost(path, hostname, key); err != nil {
			return fmt.Errorf("ssh: pin host key: %w", err)
		}
		return nil
	}
}

// appendKnownHost writes a single known_hosts line for hostname/key.
// The parent directory is created with mode 0o700 if missing; the
// file is created (if needed) with mode 0o600.
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	line := knownhosts.Line([]string{hostname}, key) + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	// Ensure mode is 0o600 even if the file pre-existed with looser perms.
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		return err
	}
	return f.Sync()
}

// Fingerprint returns the SHA256 fingerprint of key in the standard
// OpenSSH "SHA256:..." form (no padding). Exported because the
// add_server tool reports it back to the operator after pinning.
//
// It delegates to the canonical hostkey.Fingerprint so the MCP-side value
// (pinned into the registry and supplied in the sign request's Host field)
// is byte-identical to the gate-side value the gate self-derives and
// enforces. The parity is locked by a test in this package; do NOT reimplement
// the hash here.
func Fingerprint(key ssh.PublicKey) string {
	return hostkey.Fingerprint(key)
}

// fingerprint is kept as a package-local alias to avoid touching the
// existing call sites.
func fingerprint(key ssh.PublicKey) string { return Fingerprint(key) }

// fingerprintFromKnown returns the SHA256 fingerprint of the first
// known key, falling back to a placeholder if the slice is empty.
func fingerprintFromKnown(want []knownhosts.KnownKey) string {
	if len(want) == 0 {
		return "(none)"
	}
	return fingerprint(want[0].Key)
}
