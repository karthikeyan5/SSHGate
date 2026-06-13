package tools_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// missingKeySSH is a fakeSSH variant whose Run returns an error that
// looks exactly like what ssh.Client.Run returns when the key file is
// absent: "ssh: load key: key file <path> does not exist".  We embed
// this in the Runner.SSH field to isolate the tools layer from a real
// ssh.Client without spawning a real SSH server.
type missingKeySSH struct {
	keyPath string
}

func (m *missingKeySSH) Run(ctx context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error) {
	return nil, nil, 0, &fs.PathError{Op: "open", Path: m.keyPath, Err: fs.ErrNotExist}
}

// TestRunRead_MissingKeyGivesActionableError asserts that when the SSH
// key file is absent the read path surfaces an error containing "setup"
// so the user knows to run /sshgate:setup — and does not panic.
func TestRunRead_MissingKeyGivesActionableError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ssh", "sshgate_ed25519")

	r := newRegistryWith(t, "h1", registry.Entry{Host: "1.2.3.4", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{
		Servers: r,
		Sign:    &fakeSign{},
		SSH:     &missingKeySSH{keyPath: keyPath},
		KeyPath: keyPath, // triggers the pre-flight check in runRead
	}

	_, err := runner.Run(context.Background(), tools.RunInput{Alias: "h1", Command: "df -h"})
	if err == nil {
		t.Fatal("expected error when SSH key is missing, got nil")
	}
	if !strings.Contains(err.Error(), "setup") {
		t.Errorf("error %q does not contain %q — not actionable for a fresh user", err.Error(), "setup")
	}
}
