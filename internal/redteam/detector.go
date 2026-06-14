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

// Detector is the trustworthy core: snapshot -> run -> snapshot -> diff
// -> verdict. It depends only on the two interfaces above plus the
// sentinel, so it runs identically against a fake (unit tests) and the
// live container (the command).
type Detector struct {
	Runner      GateRunner
	Snapshotter Snapshotter
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
	before, err := d.Snapshotter.Snapshot(ctx)
	if err != nil {
		return Verdict{}, err
	}
	res := d.Runner.Run(ctx, cmd)
	after, err := d.Snapshotter.Snapshot(ctx)
	if err != nil {
		return Verdict{}, err
	}
	return DecideVerdict(VerdictInput{
		Cmd:      cmd,
		Category: category,
		Result:   res,
		Before:   before,
		After:    after,
		Sentinel: d.Sentinel,
	}), nil
}
