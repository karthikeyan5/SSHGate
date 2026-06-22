package hostkey

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// DefaultHostKeyGlob is the standard location of an OpenSSH server's host
// public keys. A host may run several (ed25519 / rsa / ecdsa); the
// TOFU-pinned key the MCP recorded could be ANY of them, so the gate accepts
// a match against ANY of these.
const DefaultHostKeyGlob = "/etc/ssh/ssh_host_*.pub"

// LoadHostFingerprints loads the gate's own host-key fingerprints from the
// default OpenSSH location (DefaultHostKeyGlob). It is the production entry
// point; the gate calls this once at process start and threads the result
// into VerifySigned. See LoadHostFingerprintsFromGlob for behaviour.
func LoadHostFingerprints() ([]string, error) {
	return LoadHostFingerprintsFromGlob(DefaultHostKeyGlob)
}

// LoadHostFingerprintsFromGlob enumerates the public-key files matching glob,
// parses each as an OpenSSH authorized_keys-format public key, and returns
// the canonical Fingerprint of every one it can parse.
//
// Design notes (the gate is the untrusted-input, fail-closed side):
//
//   - A file that does not parse as a public key is SKIPPED, not fatal: a
//     single garbage or unexpected file in /etc/ssh must not knock out every
//     host key and thereby deny every legitimate write. The gate still
//     enforces — it just enforces against the keys it could read.
//   - A glob that matches nothing returns an empty slice and no error. The
//     CALLER decides policy: an empty set means the gate can match no Host,
//     so every signed write fails closed at VerifySigned (ErrHostMismatch),
//     which is the correct fail-closed outcome when the gate cannot identify
//     itself.
//   - Reading these world-readable static files at process start is identity,
//     not decision state — it does not violate the gate's stateless invariant.
func LoadHostFingerprintsFromGlob(glob string) ([]string, error) {
	matches, err := filepathGlob(glob)
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", glob, err)
	}
	out := make([]string, 0, len(matches))
	for _, path := range matches {
		fp, ok := fingerprintFile(path)
		if !ok {
			continue
		}
		out = append(out, fp)
	}
	return out, nil
}

// fingerprintFile reads a single OpenSSH public-key file and returns its
// canonical fingerprint. It returns ok=false (no error) for any file that
// cannot be read or parsed, so the caller can skip it without aborting the
// whole load.
func fingerprintFile(path string) (fp string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", false
	}
	return Fingerprint(pub), true
}

// filepathGlob is a package var solely so a future test could inject a
// failing glob; production always uses filepath.Glob.
var filepathGlob = globDefault
