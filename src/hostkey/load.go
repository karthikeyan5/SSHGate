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
	// Dedupe: a symlink plus its target (or any two paths) can both match the
	// glob and resolve to the same key. Collapse repeats so the returned set is
	// a clean set of distinct fingerprints. Insertion order is preserved.
	seen := make(map[string]struct{}, len(matches))
	for _, path := range matches {
		fp, ok := fingerprintFile(path)
		if !ok {
			continue
		}
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, fp)
	}
	return out, nil
}

// fingerprintFile reads a single OpenSSH public-key file and returns its
// canonical fingerprint. It returns ok=false (no error) for any file that
// cannot be read or parsed, so the caller can skip it without aborting the
// whole load.
//
// NOTE — deliberate mode-check asymmetry vs gate/keystore.go LoadPubKey:
// LoadPubKey refuses a group/world-WRITABLE gate.pub because that file is the
// signature trust anchor (its bytes decide whether a write is authentic), so a
// writable anchor is a takeover. The host-key files read here are different in
// kind: /etc/ssh/ssh_host_*.pub are root-owned, world-readable STATIC IDENTITY
// files (the machine's own published identity), NOT a trust anchor. The gate
// only ever READS them, and writing /etc/ssh already requires root — i.e. full
// host compromise, at which point the host-binding it protects is moot anyway.
// Worse, a perms-quirk-driven mode-SKIP here could falsely drop a legitimate
// host key from the set and, if it emptied the set, fail every signed write
// closed (a self-inflicted DoS). So the mode check is deliberately OMITTED here
// — this is intentional, not an oversight; do NOT add a mode-skip.
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
