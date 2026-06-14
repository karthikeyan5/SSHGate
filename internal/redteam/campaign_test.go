package redteam

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeWorld is a stateful stand-in for the container: it holds a probe
// file's content, the runner mutates it when a "successful unsigned
// write" command runs, and the snapshotter reads the current state.
// This models reality (a real write persists) so the campaign test
// exercises the same before/Run/after flow as the live path.
type fakeWorld struct {
	decide     func(cmd string) RunResult
	mutating   map[string]bool
	probeSha   string
	probeMtime int64
}

func (w *fakeWorld) Run(ctx context.Context, cmd string) RunResult {
	res := w.decide(cmd)
	// A "successful unsigned write" actually changes the world.
	if w.mutating[cmd] && res.ExitCode == 0 {
		w.probeSha = "mutated-" + cmd
		w.probeMtime++
	}
	return res
}

func (w *fakeWorld) Snapshot(ctx context.Context) (Snapshot, error) {
	return mkSnap(FileState{
		Path:    CanaryRoot + "/probe",
		Exists:  true,
		Sha256:  w.probeSha,
		MtimeNs: w.probeMtime,
	}), nil
}

// TestRunCampaign_AggregatesAndWritesJSONL drives a campaign over a fake
// gate where exactly one command "mutates while executed" (a simulated
// bypass) and confirms: the bypass is counted, a denied write is counted
// as denied (not bypass), and every verdict is appended to the JSONL.
func TestRunCampaign_AggregatesAndWritesJSONL(t *testing.T) {
	// The one command we treat as a successful unsigned write. It MUST
	// be a real member of the corpus (the newline-separator hole), so
	// the campaign actually runs it.
	bypassCmd := "ls\nrm -rf " + CanaryRoot + "/" + canaryProbeName

	world := &fakeWorld{
		mutating:   map[string]bool{bypassCmd: true},
		probeSha:   "base",
		probeMtime: 1,
	}
	world.decide = func(cmd string) RunResult {
		switch {
		case cmd == bypassCmd:
			// Gate executed it (exit 0, no refusal) — and the world will
			// show the probe mutated.
			return RunResult{ExitCode: 0, Stdout: "listing"}
		case isDeniedShape(cmd):
			// Simulate the gate refusing writes.
			return RunResult{ExitCode: 77, Stderr: "gate: no signing key configured"}
		default:
			// Reads execute cleanly with no fs change.
			return RunResult{ExitCode: 0, Stdout: "ok"}
		}
	}
	d := &Detector{Runner: world, Snapshotter: world, Sentinel: "SENT"}

	dir := t.TempDir()
	report := filepath.Join(dir, "report.jsonl")
	var out bytes.Buffer
	cfg := CampaignConfig{
		CanaryRoot:  CanaryRoot,
		SecretPath:  SecretPath,
		Iterations:  1,
		FuzzPerPass: 0, // deterministic: corpus only
		ReportPath:  report,
		Out:         &out,
	}
	res, err := RunCampaign(context.Background(), d, nil, cfg)
	if err != nil {
		t.Fatalf("RunCampaign: %v", err)
	}

	if res.Bypasses != 1 {
		t.Errorf("Bypasses = %d; want exactly 1 (the simulated escape)", res.Bypasses)
	}
	if res.Tested == 0 {
		t.Fatalf("Tested = 0; campaign did nothing")
	}
	if res.Denied == 0 {
		t.Errorf("Denied = 0; expected the simulated gate to refuse some writes")
	}

	// JSONL is append-only, one verdict per line, parseable, and the
	// bypass line carries BYPASS:true.
	f, err := os.Open(report)
	if err != nil {
		t.Fatalf("open report: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lines, bypassLines := 0, 0
	for sc.Scan() {
		var v Verdict
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("report line not valid JSON: %v\n%s", err, sc.Text())
		}
		lines++
		if v.BYPASS {
			bypassLines++
		}
	}
	if lines != res.Tested {
		t.Errorf("JSONL lines = %d; want %d (one per tested candidate)", lines, res.Tested)
	}
	if bypassLines != 1 {
		t.Errorf("JSONL bypass lines = %d; want 1", bypassLines)
	}
	if !bytes.Contains(out.Bytes(), []byte("BYPASS")) {
		t.Errorf("human summary missing BYPASS callout")
	}
}

// isDeniedShape is a crude stand-in for "the real gate would refuse
// this" used only by the campaign test's fake: any command that looks
// like a write head and is NOT the single simulated-bypass command.
// It does NOT need to match the real classifier — it just gives the
// aggregation test a mix of denied/executed verdicts.
func isDeniedShape(cmd string) bool {
	for _, w := range []string{"rm ", "rm\t", "rm-", "> ", ">>", "touch ", "sed -i", "cp ",
		"mv ", "ln ", "mkdir", "truncate", "tee ", "dd ", "eval", "git init",
		"python", "perl", "ruby", "node ", "chmod", "chown", "install ", "ex ",
		"vi ", "awk 'BEGIN{system", "find ", "xargs", "env ", "sh -c", "bash -c"} {
		if contains(cmd, w) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
