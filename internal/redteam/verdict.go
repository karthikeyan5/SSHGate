// Package redteam is the standing red-team rig for the SSHGate gate.
//
// It points attack commands at a REAL gate binary running in READ-ONLY
// mode (no gate.pub) inside a disposable container, and decides — for
// each command — whether the gate UPHELD its purpose or was DEFEATED.
//
// The gate's purpose in read-only mode (see
// src/gate/cmd/sshgate-gate/main.go): classify SSH_ORIGINAL_COMMAND and
// EXECUTE it via /bin/sh -c only if classify.Classify says READ; else
// deny with exit 77 and "no signing key configured". A bypass is any
// command that mutates state without a signature — i.e. the gate let a
// real write slip through as a "read".
//
// This package is deliberately split so the DETECTOR logic
// (snapshot/diff + verdict) is testable with a fake gate-runner and a
// fake snapshotter, with NO Docker and NO sudo (see verdict_test.go).
// The live container plumbing lives in container.go and is only reached
// by the gate-redteam command at runtime when Docker is present.
package redteam

import (
	"sort"
	"strings"
)

// GateDecision is the rig's read of what the gate did with a command.
type GateDecision string

const (
	// DecisionDenied means the gate refused to run the command: it
	// returned the read-only write-refusal (exit 77 + the
	// "no signing key configured" log line). This is the gate working
	// as intended for a write.
	DecisionDenied GateDecision = "denied"

	// DecisionExecuted means the gate let the command run under
	// /bin/sh -c. For a genuine read this is fine; for anything that
	// mutates state or executes arbitrary code it is the door the rig
	// is trying to find.
	DecisionExecuted GateDecision = "executed"

	// DecisionError means neither outcome could be established (SSH
	// transport failure, gate crash with an unexpected exit code, etc).
	// An error verdict is never a bypass — it is a rig problem to
	// investigate, surfaced loudly so a long run does not silently
	// count failures as "safe".
	DecisionError GateDecision = "error"
)

// gateRefusalExit is the exit code the gate returns for a write it will
// not run without a signature (EX_NOPERM). Mirrors exitNoPermVal in
// src/gate/cmd/sshgate-gate/main.go. The rig hard-codes the observable
// contract rather than importing the (package main) constant.
const gateRefusalExit = 77

// gateRefusalNeedle is a stable fragment of the gate's read-only
// write-refusal log line ("gate: no signing key configured ..."). The
// gate writes it to stderr. We match a fragment, not the whole line,
// so wording tweaks on the production side do not silently turn a
// denial into a (mis-classified) "executed".
const gateRefusalNeedle = "no signing key configured"

// RunResult is the raw observable outcome of sending one command to the
// gate over SSH: the gate's process exit code and its two streams.
// stdout carries the inner command's output; stderr carries the gate's
// own "gate: ..." log lines plus any inner-command stderr.
type RunResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	// Err is a transport-level error (dial/auth/exec failure). A
	// non-zero gate exit is NOT an error here — it is reported via
	// ExitCode, matching ssh/client.go semantics.
	Err error
}

// FileState is the snapshot of one path: its sha256 (hex) and mtime
// (unix nanos). A path that does not exist is represented by Exists
// false and zeroed fields, so create/delete both show up as diffs.
type FileState struct {
	Path    string `json:"path"`
	Exists  bool   `json:"exists"`
	Sha256  string `json:"sha256,omitempty"`
	MtimeNs int64  `json:"mtime_ns,omitempty"`
	// Size is recorded for human triage; it does not drive the diff
	// (sha256 already covers content), but a size delta on an unreadable
	// file is a useful breadcrumb.
	Size int64 `json:"size,omitempty"`
}

// Snapshot maps every watched path to its FileState. It is produced by
// a Snapshotter before and after a candidate command runs.
type Snapshot map[string]FileState

// Diff compares a before/after snapshot and returns the sorted list of
// paths whose state changed (content, existence, or mtime). The union
// of both key sets is considered, so a path that appears only in
// "after" (a freshly-created file) is reported, as is one that vanished.
func Diff(before, after Snapshot) []string {
	seen := map[string]struct{}{}
	for p := range before {
		seen[p] = struct{}{}
	}
	for p := range after {
		seen[p] = struct{}{}
	}
	var changed []string
	for p := range seen {
		b, bok := before[p]
		a, aok := after[p]
		switch {
		case bok != aok:
			// Path appeared in only one snapshot — created or removed.
			changed = append(changed, p)
		case !bok && !aok:
			// Impossible (p came from one of the maps), defensive only.
		default:
			if fileStateChanged(b, a) {
				changed = append(changed, p)
			}
		}
	}
	sort.Strings(changed)
	return changed
}

// fileStateChanged reports whether two FileStates for the same path
// differ in a way that indicates a write. Existence flip, content
// (sha256) change, or mtime change all count. mtime is included because
// a "touch" or a rewrite-with-identical-content is still a state
// mutation the gate should have blocked.
func fileStateChanged(b, a FileState) bool {
	if b.Exists != a.Exists {
		return true
	}
	if b.Sha256 != a.Sha256 {
		return true
	}
	if b.MtimeNs != a.MtimeNs {
		return true
	}
	return false
}

// Verdict is the per-command JSON record the rig emits. It is the
// contract an agent reads to decide whether it found a bypass. Field
// names are the stable schema documented in the README.
type Verdict struct {
	Cmd           string       `json:"cmd"`
	Category      string       `json:"category,omitempty"`
	GateDecision  GateDecision `json:"gate_decision"`
	ExitCode      int          `json:"exit_code"`
	StdoutExcerpt string       `json:"stdout_excerpt"`
	StderrExcerpt string       `json:"stderr_excerpt"`
	FSChanged     bool         `json:"fs_changed"`
	ChangedPaths  []string     `json:"changed_paths"`
	SecretLeaked  bool         `json:"secret_leaked"`
	// WriteAlert is the in-container tripwire's INDEPENDENT, broader
	// signal: a create/modify/move/delete fired under the curated clean
	// zone (CanaryRoot, the beacon, /etc, /root, /home, /usr/local/bin,
	// /var/spool/cron) — by ANY mechanism, even outside the canary tree
	// the corpus aimed at. It is stronger than fs_changed (which is
	// canary-scoped). A write_alert while the gate said "executed" is a
	// bypass.
	WriteAlert bool `json:"write_alert"`
	// WriteEvents are the absolute paths the tripwire saw change. Empty
	// when WriteAlert is false.
	WriteEvents []string `json:"write_events"`
	// BYPASS is the headline: the gate EXECUTED a command that changed
	// filesystem state — detected EITHER by the canary diff (fs_changed)
	// OR the in-container tripwire (write_alert). A state mutation slipped
	// through unsigned. Uppercase in JSON on purpose — it is the field an
	// agent (or a grep) scans for.
	BYPASS bool `json:"BYPASS"`
	// Note is a short human-readable explanation of the verdict.
	Note string `json:"note"`
	// Timestamp is RFC3339; set by the campaign runner so a long
	// append-only report is chronologically ordered.
	Timestamp string `json:"ts,omitempty"`
}

// excerptLimit bounds how much of each stream we embed in a verdict so a
// noisy command (e.g. `cat` of a big file) does not bloat the JSONL.
const excerptLimit = 2000

// VerdictInput bundles everything DecideVerdict needs. Keeping it a
// struct (rather than a long arg list) makes the unit tests legible.
type VerdictInput struct {
	Cmd      string
	Category string
	Result   RunResult
	Before   Snapshot
	After    Snapshot
	// Sentinel is the secret-canary marker; if it appears in stdout (or
	// stderr) the read exposed the secret. Empty disables the check.
	Sentinel string
	// WriteEvents are the in-container tripwire observations for this
	// candidate (paths under the clean zone that changed during the run).
	// Empty/nil means the tripwire saw nothing. Independent of
	// Before/After (which are canary-scoped).
	WriteEvents []WriteEvent
}

// DecideVerdict is the pure heart of the detector: given the raw run
// result and before/after snapshots, classify the gate decision, diff
// the filesystem, check for secret exposure, and set the BYPASS flag.
//
// It is intentionally free of any I/O so verdict_test.go can drive it
// with constructed inputs and prove the bypass logic without Docker.
func DecideVerdict(in VerdictInput) Verdict {
	v := Verdict{
		Cmd:           in.Cmd,
		Category:      in.Category,
		ExitCode:      in.Result.ExitCode,
		StdoutExcerpt: excerpt(in.Result.Stdout),
		StderrExcerpt: excerpt(in.Result.Stderr),
	}

	v.GateDecision = classifyDecision(in.Result)

	v.ChangedPaths = Diff(in.Before, in.After)
	v.FSChanged = len(v.ChangedPaths) > 0

	v.WriteEvents = sortedPaths(in.WriteEvents)
	v.WriteAlert = len(v.WriteEvents) > 0

	if in.Sentinel != "" {
		if strings.Contains(in.Result.Stdout, in.Sentinel) ||
			strings.Contains(in.Result.Stderr, in.Sentinel) {
			v.SecretLeaked = true
		}
	}

	// THE headline bypass: the gate let it run AND state changed — by the
	// canary diff (precise) OR the in-container tripwire (broad). The
	// tripwire is the conservative backstop: a write to an UNPREDICTED
	// location the canary diff never sees still trips BYPASS.
	v.BYPASS = v.GateDecision == DecisionExecuted && (v.FSChanged || v.WriteAlert)

	v.Note = buildNote(v)
	return v
}

// classifyDecision reads the raw RunResult and decides whether the gate
// denied or executed the command.
//
// The gate's read-only write-refusal is the pair (exit 77, stderr
// containing the refusal needle). We require BOTH: a bare exit 77 from
// some inner command without the gate's log line would otherwise be
// mis-read as a denial. Anything that is not a transport error and not
// the refusal pair is treated as EXECUTED — the gate ran the inner
// command (whatever its exit code).
func classifyDecision(r RunResult) GateDecision {
	if r.Err != nil {
		return DecisionError
	}
	if r.ExitCode == gateRefusalExit && strings.Contains(r.Stderr, gateRefusalNeedle) {
		return DecisionDenied
	}
	return DecisionExecuted
}

// buildNote produces a short human-readable summary for the verdict.
func buildNote(v Verdict) string {
	switch {
	case v.GateDecision == DecisionError:
		return "transport/gate error — investigate; not counted as a bypass"
	case v.BYPASS && v.WriteAlert && !v.FSChanged:
		return "BYPASS: gate executed an unsigned command; in-container tripwire fired on a write OUTSIDE the canary tree (write_events)"
	case v.BYPASS:
		return "BYPASS: gate executed an unsigned command that mutated filesystem state"
	case v.GateDecision == DecisionExecuted && v.WriteAlert:
		// Defensive: tripwire fired but the gate denied — should not
		// happen (a denied write does not run), surface for triage.
		return "gate executed (classified read); tripwire fired (write_events) — investigate"
	case v.GateDecision == DecisionDenied:
		return "gate denied (write refused, exit 77) — working as intended"
	case v.GateDecision == DecisionExecuted && v.SecretLeaked:
		return "gate executed (classified read); secret sentinel appeared in output (reads are allowed by design — exposure quantified)"
	case v.GateDecision == DecisionExecuted:
		return "gate executed (classified read); no filesystem mutation detected"
	default:
		return ""
	}
}

// excerpt trims s to excerptLimit bytes, appending a truncation marker
// so a reader knows output was clipped.
func excerpt(s string) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= excerptLimit {
		return s
	}
	return s[:excerptLimit] + "...[truncated]"
}
