package redteam

import "context"

// GateRunner sends a single command to the gate as SSH_ORIGINAL_COMMAND
// (i.e. over SSH on the forced dedicated key) and returns the raw
// observable result. The real implementation (sshGateRunner in
// container.go) dials the container; tests supply a fake.
type GateRunner interface {
	Run(ctx context.Context, cmd string) RunResult
}

// Snapshotter captures the state of the watched paths inside the target.
// The real implementation enumerates the canary tree + watched writable
// dirs via docker exec; tests supply a fake that returns constructed
// snapshots.
type Snapshotter interface {
	Snapshot(ctx context.Context) (Snapshot, error)
}

// Tripwirer is the in-container write tripwire: a cursor primitive that
// reads, deterministically, every write under the curated clean zone
// between a mark and a read. The real implementation (*Target) reads the
// inotify event-log delta (or the snapshot fallback); tests supply a
// fake. Optional on the Detector — nil disables the tripwire and the
// verdict falls back to the canary-scoped fs_changed signal alone.
type Tripwirer interface {
	WriteMark(ctx context.Context) (Marker, error)
	WriteEventsSince(ctx context.Context, m Marker) ([]WriteEvent, error)
}

// Detector is the trustworthy core: snapshot -> run -> snapshot -> diff
// -> verdict. It depends only on the two interfaces above plus the
// sentinel, so it runs identically against a fake (unit tests) and the
// live container (the command).
type Detector struct {
	Runner      GateRunner
	Snapshotter Snapshotter
	// Tripwire, if non-nil, is the in-container write tripwire. The
	// detector takes a mark before Run and reads events after, surfacing
	// write_alert/write_events on the verdict — an independent, broader
	// bypass signal than the canary-scoped fs_changed. nil disables it.
	Tripwire Tripwirer
	// Sentinel is the secret-canary marker checked against stdout/stderr.
	Sentinel string
	// Resetter, if non-nil, is called before each Test to restore the
	// canary tree to a known-good baseline so consecutive candidates do
	// not contaminate each other. May be nil (campaign mode resets
	// periodically instead).
	Resetter func(ctx context.Context) error
}

// Test runs one candidate command end to end and returns its verdict.
// The category is carried through onto the verdict for reporting; pass
// "" for ad-hoc single tests.
func (d *Detector) Test(ctx context.Context, category, cmd string) (Verdict, error) {
	if d.Resetter != nil {
		if err := d.Resetter(ctx); err != nil {
			return Verdict{}, err
		}
	}

	// Mark the tripwire BEFORE the canary snapshot + run, so it captures
	// every write the command triggers regardless of where it lands.
	var (
		mark   Marker
		haveTW bool
	)
	if d.Tripwire != nil {
		m, err := d.Tripwire.WriteMark(ctx)
		if err != nil {
			return Verdict{}, err
		}
		mark, haveTW = m, true
	}

	before, err := d.Snapshotter.Snapshot(ctx)
	if err != nil {
		return Verdict{}, err
	}
	res := d.Runner.Run(ctx, cmd)
	after, err := d.Snapshotter.Snapshot(ctx)
	if err != nil {
		return Verdict{}, err
	}

	var writeEvents []WriteEvent
	if haveTW {
		writeEvents, err = d.Tripwire.WriteEventsSince(ctx, mark)
		if err != nil {
			return Verdict{}, err
		}
	}

	return DecideVerdict(VerdictInput{
		Cmd:         cmd,
		Category:    category,
		Result:      res,
		Before:      before,
		After:       after,
		Sentinel:    d.Sentinel,
		WriteEvents: writeEvents,
	}), nil
}
