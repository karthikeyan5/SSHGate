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

// TestRunHandlerRevealExcludesOutputFromLiveLog proves the Tier-6b hook in
// runHandler NEVER persists a revealed command's raw output to the live log:
// the entry records the command, classification, exit and revealed:true, but
// stdout/stderr are blanked. The live log is accountability, not a secret store.
func TestRunHandlerRevealExcludesOutputFromLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	const secret = "SECRET=hunter2-RAW-REVEALED-VALUE"
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte(secret + "\n"), stderr: []byte(secret + "-stderr\n")}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	_, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{
		Alias:   "web1",
		Command: "cat /etc/secret.env",
		Reveal:  true,
		Reason:  "verify the DB password",
	})
	if err != nil {
		t.Fatalf("runHandler: %v", err)
	}

	// The raw secret must appear NOWHERE in the on-disk live log.
	rawFile, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read live log: %v", err)
	}
	if strings.Contains(string(rawFile), secret) {
		t.Fatalf("live log persisted the raw revealed secret:\n%s", rawFile)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	r0 := recs[0]
	if r0["command"] != "cat /etc/secret.env" {
		t.Errorf("command = %v; metadata must still be recorded", r0["command"])
	}
	if r0["revealed"] != true {
		t.Errorf("revealed = %v; want true", r0["revealed"])
	}
	// stdout/stderr carry omitempty — a blanked field is absent, not "".
	if v, ok := r0["stdout"]; ok && v != "" {
		t.Errorf("revealed entry leaked stdout: %v", v)
	}
	if v, ok := r0["stderr"]; ok && v != "" {
		t.Errorf("revealed entry leaked stderr: %v", v)
	}
}

// TestRunHandlerNormalCommandKeepsOutputAndRevealedFalse proves a non-reveal
// command's live-log entry is unchanged: full output present, revealed absent
// (false). This guards against the reveal-exclusion over-blanking normal logs.
func TestRunHandlerNormalCommandKeepsOutputAndRevealedFalse(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{Servers: r, Sign: &hookFakeSign{}, SSH: &hookFakeSSH{stdout: []byte("FULL-READ-OUTPUT\n")}}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "cat /etc/hostname"}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}
	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d live-log records, want 1", len(recs))
	}
	r0 := recs[0]
	if !strings.Contains(r0["stdout"].(string), "FULL-READ-OUTPUT") {
		t.Errorf("normal entry must carry full output: %v", r0["stdout"])
	}
	if v, ok := r0["revealed"]; ok && v != false {
		t.Errorf("normal entry revealed = %v; want false/absent", v)
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
