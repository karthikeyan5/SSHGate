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

// hookFakeSign returns canned signatures for the write path. authMode lets a
// test drive the F4 auth_mode threaded through to the live-log entry.
type hookFakeSign struct {
	signed   []signpkg.Signed
	authMode string
}

func (f *hookFakeSign) Sign(_ context.Context, _ string, cmds []signpkg.CmdReq) (signpkg.SignResult, error) {
	// One signature per requested command (matches the runner's
	// expectation).
	out := make([]signpkg.Signed, len(cmds))
	for i := range cmds {
		out[i] = signpkg.Signed{Sig: "SSHGATE_SIG:fake"}
	}
	return signpkg.SignResult{Signed: out, AuthMode: f.authMode}, nil
}

// RequestGrant / RevokeGrant satisfy SignClient; the live-log hook tests
// never use the grant paths.
func (f *hookFakeSign) RequestGrant(_ context.Context, _, _, _ string, _ []string, _ int64) (string, int64, error) {
	return "", 0, nil
}
func (f *hookFakeSign) RevokeGrant(_ context.Context, _, _ string) error { return nil }
func (f *hookFakeSign) ListGrants(_ context.Context, _, _ string) ([]signpkg.GrantInfo, error) {
	return nil, nil
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

// TestRunHandlerWritesAuthModeToLiveLog proves F4 end-to-end through
// runHandler: a write the signer authorised under a standing grant emits a
// live-log entry whose auth_mode is "grant:<id>" (the value the sign response
// carried), and a read emits an entry with no auth_mode key (omitempty).
func TestRunHandlerWritesAuthModeToLiveLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	runner := &tools.Runner{
		Servers: r,
		Sign:    &hookFakeSign{authMode: "grant:g_42"},
		SSH:     &hookFakeSSH{stdout: []byte("done\n")},
	}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	// A write (rm classifies as a write) → auth_mode = grant:g_42.
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "rm /tmp/x"}); err != nil {
		t.Fatalf("runHandler write: %v", err)
	}
	// A read → no auth_mode.
	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{Alias: "web1", Command: "cat /etc/hostname"}); err != nil {
		t.Fatalf("runHandler read: %v", err)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("got %d live-log records, want 2", len(recs))
	}
	if recs[0]["auth_mode"] != "grant:g_42" {
		t.Errorf("write entry auth_mode = %v; want grant:g_42", recs[0]["auth_mode"])
	}
	if v, ok := recs[1]["auth_mode"]; ok {
		t.Errorf("read entry has auth_mode = %v; want the key omitted", v)
	}
}

// TestRunHandlerRevealKeepsAuthModeBlanksOutput proves a SECRET-REVEAL write
// still records its auth_mode (metadata, not secret) while blanking the raw
// stdout/stderr (which carry the revealed secret). A reveal always prompts a
// human, so auth_mode is "human".
func TestRunHandlerRevealKeepsAuthModeBlanksOutput(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit-live.log")
	ll := livelog.New(logPath, 1<<20)
	r := hookRegistry(t, "web1")
	const secret = "SECRET=hunter2-RAW"
	runner := &tools.Runner{
		Servers: r,
		Sign:    &hookFakeSign{authMode: "human"},
		SSH:     &hookFakeSSH{stdout: []byte(secret + "\n")},
	}
	srv := &Server{Runner: runner, Logger: log.New(io.Discard, "", 0), LiveLog: ll}

	if _, _, err := srv.runHandler(context.Background(), nil, tools.RunInput{
		Alias:   "web1",
		Command: "cat /etc/secret.env",
		Reveal:  true,
		Reason:  "verify db password",
	}); err != nil {
		t.Fatalf("runHandler: %v", err)
	}

	// The raw secret must not be on disk.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read live log: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("live log persisted the raw revealed secret:\n%s", raw)
	}

	recs := liveRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records; want 1", len(recs))
	}
	r0 := recs[0]
	if r0["revealed"] != true {
		t.Errorf("revealed = %v; want true", r0["revealed"])
	}
	// auth_mode is metadata — KEPT even though output was blanked.
	if r0["auth_mode"] != "human" {
		t.Errorf("revealed entry auth_mode = %v; want human (metadata kept while output blanked)", r0["auth_mode"])
	}
	if v, ok := r0["stdout"]; ok && v != "" {
		t.Errorf("revealed entry leaked stdout: %v", v)
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
