package gate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
)

// seedAuthorizedKeys writes body into home/.ssh/authorized_keys (mode 0600).
func seedAuthorizedKeys(t *testing.T, home, body string) string {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	return path
}

// seedGateDir creates home/.sshgate-gate with a couple of placeholder files.
func seedGateDir(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, ".sshgate-gate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .gate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate"), []byte("binary"), 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate.pub"), []byte("pubkey"), 0o644); err != nil {
		t.Fatalf("seed pubkey: %v", err)
	}
	return dir
}

const (
	otherKeyLine        = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+otherKeyAAAA operator@laptop`
	commentLine         = `# operator's primary access`
	otherRestrictedLine = `command="/usr/local/bin/something-else",no-pty ssh-rsa AAAAB3NzaC1y other`
)

// sshgateRestrictedLineFor builds an authorized_keys entry restricted
// to binPath; tests use this to match whatever path Revoke resolves
// (typically <t.TempDir>/.sshgate-gate/gate).
func sshgateRestrictedLineFor(binPath string) string {
	return `command="` + binPath + `",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN+sshgateKeyB sshgate@laptop`
}

func TestRevoke_RemovesMatchingLineAndDir(t *testing.T) {
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")

	sshgateRestrictedLine := sshgateRestrictedLineFor(binPath)
	original := strings.Join([]string{commentLine, otherKeyLine, sshgateRestrictedLine, otherRestrictedLine}, "\n") + "\n"
	authPath := seedAuthorizedKeys(t, home, original)
	gateDir := seedGateDir(t, home)

	res, err := gate.Revoke(home, gateDir, binPath)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.LinesRemoved != 1 {
		t.Errorf("LinesRemoved = %d; want 1", res.LinesRemoved)
	}
	if !res.GateDirRemoved {
		t.Errorf("GateDirRemoved = false; want true")
	}
	if res.BackupPath == "" {
		t.Error("BackupPath is empty; want a backup since a line was removed")
	}

	// authorized_keys content: comment, otherKey, otherRestricted preserved
	got, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("read rewritten: %v", err)
	}
	gotStr := string(got)
	if strings.Contains(gotStr, "sshgateKeyB") {
		t.Errorf("rewritten file still contains the sshgate key:\n%s", gotStr)
	}
	for _, want := range []string{commentLine, otherKeyLine, otherRestrictedLine} {
		if !strings.Contains(gotStr, want) {
			t.Errorf("rewritten file missing %q:\n%s", want, gotStr)
		}
	}

	// Backup contains the original.
	bk, err := os.ReadFile(res.BackupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bk) != original {
		t.Errorf("backup does not match original:\n  got: %q\n want: %q", bk, original)
	}

	// Mode 0600 enforced.
	info, err := os.Stat(authPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("authorized_keys perm = %#o; want 0600", perm)
	}

	// gate dir gone.
	if _, err := os.Stat(gateDir); !os.IsNotExist(err) {
		t.Errorf("gate dir still present: %v", err)
	}
}

func TestRevoke_NoMatchingLineLeavesFileAlone(t *testing.T) {
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")

	original := strings.Join([]string{commentLine, otherKeyLine, otherRestrictedLine}, "\n") + "\n"
	authPath := seedAuthorizedKeys(t, home, original)
	gateDir := seedGateDir(t, home)

	res, err := gate.Revoke(home, gateDir, binPath)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.LinesRemoved != 0 {
		t.Errorf("LinesRemoved = %d; want 0", res.LinesRemoved)
	}
	if res.BackupPath != "" {
		t.Errorf("BackupPath = %q; want empty since nothing was rewritten", res.BackupPath)
	}
	got, _ := os.ReadFile(authPath)
	if string(got) != original {
		t.Errorf("file unexpectedly changed:\n  got: %q\n want: %q", got, original)
	}
	if !res.GateDirRemoved {
		t.Errorf("GateDirRemoved = false; want true (dir still exists)")
	}
}

func TestRevoke_MissingAuthorizedKeysIsTolerated(t *testing.T) {
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")
	gateDir := seedGateDir(t, home)

	res, err := gate.Revoke(home, gateDir, binPath)
	if err != nil {
		t.Fatalf("Revoke (no authorized_keys): %v", err)
	}
	if res.LinesRemoved != 0 {
		t.Errorf("LinesRemoved = %d; want 0", res.LinesRemoved)
	}
	if !res.GateDirRemoved {
		t.Errorf("GateDirRemoved = false; want true")
	}
}

func TestRevoke_AlreadyAbsentGateDirNotError(t *testing.T) {
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")

	// authorized_keys with the matching line but no gate dir.
	seedAuthorizedKeys(t, home, sshgateRestrictedLineFor(binPath)+"\n")

	res, err := gate.Revoke(home, filepath.Join(home, ".sshgate-gate"), binPath)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.LinesRemoved != 1 {
		t.Errorf("LinesRemoved = %d; want 1", res.LinesRemoved)
	}
	if res.GateDirRemoved {
		t.Errorf("GateDirRemoved = true; want false (dir was already absent)")
	}
}

func TestRevoke_MultipleMatchingLinesAllRemoved(t *testing.T) {
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")

	// Two restricted entries for the same gate binary (e.g. multiple
	// keys were forced through it during testing).
	sshgateRestrictedLine := sshgateRestrictedLineFor(binPath)
	dupLine := `command="` + binPath + `",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAdupkeyKKKK other@host`
	original := strings.Join([]string{otherKeyLine, sshgateRestrictedLine, dupLine}, "\n") + "\n"
	authPath := seedAuthorizedKeys(t, home, original)

	res, err := gate.Revoke(home, filepath.Join(home, ".sshgate-gate"), binPath)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.LinesRemoved != 2 {
		t.Errorf("LinesRemoved = %d; want 2", res.LinesRemoved)
	}
	got, _ := os.ReadFile(authPath)
	if strings.Contains(string(got), `"`+binPath+`"`) {
		t.Errorf("rewritten file still contains gate command directive:\n%s", got)
	}
}

func TestRevoke_MatchesTildeFormWhenBinaryUnderHome(t *testing.T) {
	// The installer writes command="~/.sshgate-gate/gate" but the running
	// gate sees os.Executable() as the absolute path. Revoke must
	// match both. We seed an authorized_keys with the tilde form and
	// pass the absolute path to Revoke.
	home := t.TempDir()
	binPath := filepath.Join(home, ".sshgate-gate", "gate")

	tildeLine := `command="~/.sshgate-gate/gate",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAtilde sshgate@laptop`
	original := otherKeyLine + "\n" + tildeLine + "\n"
	authPath := seedAuthorizedKeys(t, home, original)

	res, err := gate.Revoke(home, filepath.Join(home, ".sshgate-gate"), binPath)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.LinesRemoved != 1 {
		t.Errorf("LinesRemoved = %d; want 1 (tilde-form must match)", res.LinesRemoved)
	}
	got, _ := os.ReadFile(authPath)
	if strings.Contains(string(got), "AAAAtilde") {
		t.Errorf("tilde-form line not removed:\n%s", got)
	}
}

func TestRevoke_RejectsEmptyArgs(t *testing.T) {
	if _, err := gate.Revoke("", "/tmp", "/tmp/gate"); err == nil {
		t.Error("empty homeDir: expected error")
	}
	if _, err := gate.Revoke("/tmp", "", "/tmp/gate"); err == nil {
		t.Error("empty gateDir: expected error")
	}
	if _, err := gate.Revoke("/tmp", "/tmp/.sshgate-gate", ""); err == nil {
		t.Error("empty gateBinaryPath: expected error")
	}
}

func TestFormatRevokeStdout(t *testing.T) {
	got := gate.FormatRevokeStdout(gate.RevokeResult{LinesRemoved: 1, GateDirRemoved: true})
	if !strings.HasPrefix(got, "SSHGATE_REVOKED") {
		t.Errorf("got %q; want SSHGATE_REVOKED prefix", got)
	}
	if !strings.Contains(got, "lines=1") {
		t.Errorf("got %q; want lines=1", got)
	}
	if !strings.Contains(got, "dir=removed") {
		t.Errorf("got %q; want dir=removed", got)
	}
}
