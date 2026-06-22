package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"

	"github.com/karthikeyan5/sshgate/src/mcp/livelog"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// hookFakeSSH returns canned output for the run handlers.
type hookFakeSSH struct {
	stdout, stderr []byte
	exit           int
}

func (f *hookFakeSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	return f.stdout, f.stderr, f.exit, nil
}

// hookFakeSign returns canned signatures for the write path.
type hookFakeSign struct{ signed []signpkg.Signed }

func (f *hookFakeSign) Sign(_ context.Context, _ string, cmds []signpkg.CmdReq) ([]signpkg.Signed, error) {
	// One signature per requested command (matches the runner's
	// expectation).
	out := make([]signpkg.Signed, len(cmds))
	for i := range cmds {
		out[i] = signpkg.Signed{Sig: "SSHGATE_SIG:fake"}
	}
	return out, nil
}

func liveRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var recs []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad json %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return recs
}

func hookRegistry(t *testing.T, alias string) *registry.Servers {
	t.Helper()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(alias, registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRunHandlerWritesLiveLog proves the Tier-6b hook in runHandler
// appends the full command + full output to the rolling live log.
func TestRunHandlerWritesLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("FULL-READ-OUTPUT\n")}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	_, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "cat /etc/hostname"})
	if err != nil {
		t.Fatalf("runHandler: %v", err)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	r0 := recs[0]
	if r0["command"] != "cat /etc/hostname" {
		t.Errorf("command = %v", r0["command"])
	}
	if r0["classification"] != "read" {
		t.Errorf("classification = %v, want read", r0["classification"])
	}
	if !strings.Contains(r0["stdout"].(string), "FULL-READ-OUTPUT") {
		t.Errorf("live log must carry FULL output: %v", r0["stdout"])
	}
}

// TestRunBatchHandlerWritesLiveLog proves runBatchHandler appends one
// live-log entry per (non-skipped) command result.
func TestRunBatchHandlerWritesLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	_, _, err := srv.runBatchHandler(context.Background(), nil, tools.RunBatchInput{
		Alias:    "web1",
		Commands: []string{"ls", "cat /tmp/x"},
	})
	if err != nil {
		t.Fatalf("runBatchHandler: %v", err)
	}
	recs := liveRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("got %d live-log records, want 2 (one per command)", len(recs))
	}
}

// TestNilLiveLogHandlerSafe proves a nil LiveLog (disabled) does not
// break the handlers.
func TestNilLiveLogHandlerSafe(t *testing.T) {
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("ok\n")}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: nil}
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "ls"}); err != nil {
		t.Fatalf("runHandler with nil LiveLog: %v", err)
	}
}
