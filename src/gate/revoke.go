package gate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// AuthorizedKeysRevokeBackup is the suffix appended to authorized_keys
// when gate creates the pre-revoke backup. Operators can recover
// from it if the revoke caught the wrong line.
const AuthorizedKeysRevokeBackup = ".sshgate-revoke-backup"

// RevokeResult captures the outcome of Revoke for the caller. It is
// printed in compact form on stdout (so the MCP side can confirm)
// and used by tests to assert specific cleanup steps.
type RevokeResult struct {
	// AuthorizedKeysPath is the absolute path to the file that was
	// inspected (and rewritten if any lines matched).
	AuthorizedKeysPath string
	// LinesRemoved counts authorized_keys entries that were stripped
	// because their command="..." directive named gateBinaryPath.
	LinesRemoved int
	// BackupPath is the absolute path to the pre-revoke
	// authorized_keys backup (empty if no backup was needed because
	// no lines matched).
	BackupPath string
	// GateDirRemoved is true iff gateDir existed and was removed
	// without error.
	GateDirRemoved bool
}

// Revoke performs the on-host teardown half of the spec's revoke
// flow:
//
//  1. Read ~/.ssh/authorized_keys (path derived from homeDir).
//  2. Rewrite the file, stripping every line whose options include a
//     command="<gateBinaryPath>" directive (the spec installer
//     writes the tilde-form "~/.sshgate-gate/gate"; the binary at runtime
//     sees its absolute resolved path — we match BOTH). Keep a backup
//     at authorized_keys.sshgate-revoke-backup so the operator can
//     recover if a key was matched in error.
//  3. Remove the gate install directory (gateDir).
//
// The rewrite is atomic: tmp + fsync + rename + fsync(parent). Mode
// 0600 is enforced on the new file.
//
// Revoke does not return an error if the gate directory is already
// gone, but it does report it via GateDirRemoved=false so the caller
// can tell. Missing authorized_keys is also tolerated — there is
// simply nothing to strip.
func Revoke(homeDir, gateDir, gateBinaryPath string) (RevokeResult, error) {
	if homeDir == "" {
		return RevokeResult{}, errors.New("revoke: homeDir is empty")
	}
	if gateDir == "" {
		return RevokeResult{}, errors.New("revoke: gateDir is empty")
	}
	if gateBinaryPath == "" {
		return RevokeResult{}, errors.New("revoke: gateBinaryPath is empty")
	}

	authPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	res := RevokeResult{AuthorizedKeysPath: authPath}

	candidates := gateBinaryCandidates(homeDir, gateBinaryPath)

	body, err := os.ReadFile(authPath)
	if errors.Is(err, fs.ErrNotExist) {
		// No file → nothing to strip. Fall through to dir removal.
	} else if err != nil {
		return res, fmt.Errorf("revoke: read %s: %w", authPath, err)
	} else {
		rewritten, removed := stripGateLines(body, candidates)
		res.LinesRemoved = removed
		if removed > 0 {
			backupPath := authPath + AuthorizedKeysRevokeBackup
			if err := os.WriteFile(backupPath, body, 0o600); err != nil {
				return res, fmt.Errorf("revoke: write backup %s: %w", backupPath, err)
			}
			res.BackupPath = backupPath

			if err := atomicWriteFile(authPath, rewritten, 0o600); err != nil {
				return res, fmt.Errorf("revoke: rewrite %s: %w", authPath, err)
			}
		}
	}

	// Remove ~/.sshgate-gate/. We tolerate ENOENT so a double-revoke is
	// idempotent rather than an error.
	if _, err := os.Stat(gateDir); err == nil {
		if err := os.RemoveAll(gateDir); err != nil {
			return res, fmt.Errorf("revoke: remove %s: %w", gateDir, err)
		}
		res.GateDirRemoved = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return res, fmt.Errorf("revoke: stat %s: %w", gateDir, err)
	}
	return res, nil
}

// stripGateLines returns body with every line whose options include
// a command="<candidate>" directive (for any candidate in
// gateBinaryCandidates output) removed. removed is the count of
// dropped lines. Comments, blank lines, and unrelated keys are
// preserved verbatim and in order.
//
// The matching is intentionally simple: we look for the substring
// command="<path>" in the line. authorized_keys options are
// double-quoted, comma-separated, and OpenSSH does not allow
// unescaped quotes inside an option value — so the substring match
// is sufficient and avoids pulling in an authorized_keys parser
// just for revoke.
func stripGateLines(body []byte, candidates []string) ([]byte, int) {
	needles := make([][]byte, 0, len(candidates))
	for _, c := range candidates {
		if c == "" {
			continue
		}
		needles = append(needles, []byte(`command="`+c+`"`))
	}

	var out bytes.Buffer
	out.Grow(len(body))
	removed := 0

	sc := bufio.NewScanner(bytes.NewReader(body))
	// Generous buffer: a single options-heavy line can run several KB.
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		matched := false
		for _, n := range needles {
			if bytes.Contains(line, n) {
				matched = true
				break
			}
		}
		if matched {
			removed++
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	// Preserve the trailing-newline shape: if the original ended with
	// no newline, scanner already consumed every byte; our output
	// always ends with \n which is the safe canonical form.
	return out.Bytes(), removed
}

// gateBinaryCandidates returns the set of strings that may appear
// inside the command="..." directive of the SSHGate-restricted line in
// authorized_keys. The installer writes the spec's tilde form
// (~/.sshgate-gate/gate) but the running binary sees its resolved
// absolute path via os.Executable() — Revoke must match both.
//
// Returned candidates are in priority order: absolute, tilde form,
// and (if a symlink resolved away from $HOME) the as-given form.
func gateBinaryCandidates(homeDir, gateBinaryPath string) []string {
	out := []string{gateBinaryPath}
	if homeDir == "" || gateBinaryPath == "" {
		return out
	}
	// If the binary lives under $HOME, also try the ~-prefixed form.
	rel, err := filepath.Rel(homeDir, gateBinaryPath)
	if err == nil && !startsWithDotDot(rel) {
		out = append(out, "~/"+filepath.ToSlash(rel))
	}
	return out
}

// startsWithDotDot reports whether the cleaned path begins with "..",
// indicating filepath.Rel had to walk above its base directory.
func startsWithDotDot(p string) bool {
	if p == ".." {
		return true
	}
	if len(p) >= 3 && p[:3] == ".."+string(filepath.Separator) {
		return true
	}
	return false
}

// atomicWriteFile writes body to path via tmp + fsync + rename. The
// resulting file is chmod'd to mode. The parent directory is fsync'd
// so the rename survives a crash.
func atomicWriteFile(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".authkeys.*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// FormatRevokeStdout renders the single line gate emits on stdout
// after a successful revoke. The MCP side detects "SSHGATE_REVOKED" as
// the success marker; the trailing details are informational.
func FormatRevokeStdout(res RevokeResult) string {
	parts := []string{"SSHGATE_REVOKED"}
	if res.LinesRemoved > 0 {
		parts = append(parts, fmt.Sprintf("lines=%d", res.LinesRemoved))
	}
	if res.GateDirRemoved {
		parts = append(parts, "dir=removed")
	} else {
		parts = append(parts, "dir=absent")
	}
	return strings.Join(parts, " ")
}
