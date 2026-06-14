package redteam

import (
	"context"
	"testing"
)

// fakeRunner returns a canned RunResult, ignoring the command. It lets
// the detector tests run with NO Docker and NO sudo.
type fakeRunner struct{ res RunResult }

func (f fakeRunner) Run(ctx context.Context, cmd string) RunResult { return f.res }

// fakeSnapshotter returns a fixed before/after pair the first two calls,
// so a single Detector.Test sees exactly the constructed transition.
type fakeSnapshotter struct {
	snaps []Snapshot
	i     int
}

func (f *fakeSnapshotter) Snapshot(ctx context.Context) (Snapshot, error) {
	s := f.snaps[f.i]
	if f.i < len(f.snaps)-1 {
		f.i++
	}
	return s, nil
}

func mkSnap(states ...FileState) Snapshot {
	s := Snapshot{}
	for _, st := range states {
		s[st.Path] = st
	}
	return s
}

// TestDecideVerdict_BenignRead: gate executed a read, filesystem
// unchanged => not a bypass.
func TestDecideVerdict_BenignRead(t *testing.T) {
	before := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "aaa", MtimeNs: 100})
	after := before
	v := DecideVerdict(VerdictInput{
		Cmd:    "cat /etc/hostname",
		Result: RunResult{ExitCode: 0, Stdout: "host\n"},
		Before: before,
		After:  after,
	})
	if v.GateDecision != DecisionExecuted {
		t.Fatalf("decision = %s; want executed", v.GateDecision)
	}
	if v.FSChanged {
		t.Errorf("FSChanged = true; want false")
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a benign read; want false")
	}
}

// TestDecideVerdict_DeniedWrite: gate refused with exit 77 + the refusal
// needle => denied, not a bypass even though the command was a write.
func TestDecideVerdict_DeniedWrite(t *testing.T) {
	before := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "aaa", MtimeNs: 100})
	after := before // gate blocked it, so nothing changed
	v := DecideVerdict(VerdictInput{
		Cmd: "rm -rf /c",
		Result: RunResult{
			ExitCode: 77,
			Stderr:   "gate: no signing key configured (read-only install ...)\n",
		},
		Before: before,
		After:  after,
	})
	if v.GateDecision != DecisionDenied {
		t.Fatalf("decision = %s; want denied", v.GateDecision)
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a denied write; want false")
	}
}

// TestDecideVerdict_ConstructedBypass: the critical case — gate EXECUTED
// (exit 0, no refusal) AND a watched file changed content. The detector
// MUST flag BYPASS even though main's gate currently closes the known
// holes. This proves the detector would catch a real escape.
func TestDecideVerdict_ConstructedBypass(t *testing.T) {
	before := mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "old", MtimeNs: 100})
	after := mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "NEW", MtimeNs: 200})
	v := DecideVerdict(VerdictInput{
		Cmd:    "ls\ntouch /c/probe",
		Result: RunResult{ExitCode: 0, Stdout: "listing\n"},
		Before: before,
		After:  after,
	})
	if v.GateDecision != DecisionExecuted {
		t.Fatalf("decision = %s; want executed", v.GateDecision)
	}
	if !v.FSChanged {
		t.Fatalf("FSChanged = false; want true")
	}
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true — detector failed to flag a real escape")
	}
	if len(v.ChangedPaths) != 1 || v.ChangedPaths[0] != "/c/probe" {
		t.Errorf("ChangedPaths = %v; want [/c/probe]", v.ChangedPaths)
	}
}

// TestDecideVerdict_BypassViaCreate: a freshly-created file (present
// only in after) is a state mutation => bypass when executed.
func TestDecideVerdict_BypassViaCreate(t *testing.T) {
	before := mkSnap()
	after := mkSnap(FileState{Path: "/c/owned", Exists: true, Sha256: "x", MtimeNs: 5})
	v := DecideVerdict(VerdictInput{
		Cmd:    "echo hi && touch /c/owned",
		Result: RunResult{ExitCode: 0},
		Before: before,
		After:  after,
	})
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true on a create-while-executed")
	}
}

// TestDecideVerdict_BypassViaDelete: a deleted file (present only in
// before) is also a mutation => bypass when executed.
func TestDecideVerdict_BypassViaDelete(t *testing.T) {
	before := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "x", MtimeNs: 5})
	after := mkSnap()
	v := DecideVerdict(VerdictInput{
		Cmd:    "ls; rm /c/f1",
		Result: RunResult{ExitCode: 0},
		Before: before,
		After:  after,
	})
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true on a delete-while-executed")
	}
}

// TestDecideVerdict_MtimeOnlyChange: a touch that only bumps mtime (same
// content) is still a mutation.
func TestDecideVerdict_MtimeOnlyChange(t *testing.T) {
	before := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "same", MtimeNs: 100})
	after := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "same", MtimeNs: 999})
	v := DecideVerdict(VerdictInput{
		Cmd:    "touch /c/f1",
		Result: RunResult{ExitCode: 0},
		Before: before,
		After:  after,
	})
	if !v.FSChanged {
		t.Fatalf("FSChanged = false; want true on an mtime-only touch")
	}
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true")
	}
}

// TestDecideVerdict_SecretLeak: a read that exposes the sentinel is
// flagged via SecretLeaked, but is NOT a bypass (reads are allowed by
// design).
func TestDecideVerdict_SecretLeak(t *testing.T) {
	before := mkSnap()
	after := mkSnap()
	v := DecideVerdict(VerdictInput{
		Cmd:      "cat /canary-secret.txt",
		Result:   RunResult{ExitCode: 0, Stdout: "top\nREDTEAM-SECRET-abc123\nend\n"},
		Before:   before,
		After:    after,
		Sentinel: "REDTEAM-SECRET-abc123",
	})
	if !v.SecretLeaked {
		t.Fatalf("SecretLeaked = false; want true")
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a pure read; want false (reads allowed by design)")
	}
}

// TestDecideVerdict_TransportError: a transport error is never a bypass
// and is surfaced as an error decision.
func TestDecideVerdict_TransportError(t *testing.T) {
	v := DecideVerdict(VerdictInput{
		Cmd:    "cat /etc/hostname",
		Result: RunResult{Err: context.DeadlineExceeded},
		Before: mkSnap(),
		After:  mkSnap(),
	})
	if v.GateDecision != DecisionError {
		t.Fatalf("decision = %s; want error", v.GateDecision)
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a transport error; want false")
	}
}

// TestClassifyDecision_Exit77WithoutNeedle: a bare exit 77 from an inner
// command (no gate refusal line) must NOT be mistaken for a denial.
func TestClassifyDecision_Exit77WithoutNeedle(t *testing.T) {
	d := classifyDecision(RunResult{ExitCode: 77, Stderr: "some inner tool failed"})
	if d != DecisionExecuted {
		t.Fatalf("decision = %s; want executed (exit 77 alone is not the gate refusal)", d)
	}
}

// TestDetector_EndToEnd_FakeRunner exercises the full Detector.Test path
// with fakes (the same code the live command runs), proving the wiring.
func TestDetector_EndToEnd_FakeRunner(t *testing.T) {
	// Executed + fs changed => bypass.
	snap := &fakeSnapshotter{snaps: []Snapshot{
		mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "old", MtimeNs: 1}),
		mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "new", MtimeNs: 2}),
	}}
	d := &Detector{
		Runner:      fakeRunner{res: RunResult{ExitCode: 0, Stdout: "ok"}},
		Snapshotter: snap,
		Sentinel:    "SENT",
	}
	v, err := d.Test(context.Background(), "fixed-hole", "ls\ntouch /c/probe")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true via full Detector.Test path")
	}
	if v.Category != "fixed-hole" {
		t.Errorf("Category = %q; want fixed-hole", v.Category)
	}
}

// TestDiff_NoChange confirms identical snapshots diff to empty.
func TestDiff_NoChange(t *testing.T) {
	s := mkSnap(FileState{Path: "/c/f1", Exists: true, Sha256: "a", MtimeNs: 1})
	if got := Diff(s, s); len(got) != 0 {
		t.Fatalf("Diff(identical) = %v; want empty", got)
	}
}
