package redteam

import (
	"context"
	"testing"
)

// TestParseWatchLog_DeltaFromCursor is the core deterministic unit test
// of the event-log-delta parser (the WriteEventsSince logic) with a fake
// log — NO Docker. It proves the cursor semantics: a Marker taken
// mid-log yields exactly the events appended after it.
func TestParseWatchLog_DeltaFromCursor(t *testing.T) {
	log := "1700000000\tCREATE\t/etc/cron.d/x\n" +
		"1700000001\tMODIFY\t/config/canary/owned\n" +
		"1700000002\tMOVED_TO\t/usr/local/bin/planted\n"

	// Fresh cursor (0) sees everything.
	evs, total := parseWatchLog(log, 0)
	if total != 3 {
		t.Fatalf("total lines = %d; want 3", total)
	}
	if len(evs) != 3 {
		t.Fatalf("events from cursor 0 = %d; want 3", len(evs))
	}
	if evs[0].Path != "/etc/cron.d/x" || evs[0].Events != "CREATE" || evs[0].UnixTime != 1700000000 {
		t.Errorf("event[0] = %+v; want CREATE /etc/cron.d/x @1700000000", evs[0])
	}

	// Cursor at line 2 sees only the third event.
	evs2, total2 := parseWatchLog(log, 2)
	if total2 != 3 {
		t.Fatalf("total2 = %d; want 3", total2)
	}
	if len(evs2) != 1 {
		t.Fatalf("events from cursor 2 = %d; want 1", len(evs2))
	}
	if evs2[0].Path != "/usr/local/bin/planted" {
		t.Errorf("event from cursor 2 = %q; want /usr/local/bin/planted", evs2[0].Path)
	}

	// Cursor at the end sees nothing (the silent-on-read case).
	evs3, _ := parseWatchLog(log, 3)
	if len(evs3) != 0 {
		t.Fatalf("events from end cursor = %d; want 0 (no write since mark)", len(evs3))
	}
}

// TestParseWatchLog_IgnoresOwnBookkeeping proves the parser never
// surfaces the rig's own event-log / pidfile writes, so the tripwire
// cannot false-positive on its own bookkeeping even if --exclude misses.
func TestParseWatchLog_IgnoresOwnBookkeeping(t *testing.T) {
	log := "1\tMODIFY\t" + watchLog + "\n" +
		"2\tCREATE\t" + watchPID + "\n" +
		"3\tCREATE\t/redteam-watch/beacon/real_write\n"
	evs, _ := parseWatchLog(log, 0)
	if len(evs) != 1 {
		t.Fatalf("events = %d; want 1 (only the real write, not bookkeeping)", len(evs))
	}
	if evs[0].Path != "/redteam-watch/beacon/real_write" {
		t.Errorf("surfaced %q; want the real beacon write", evs[0].Path)
	}
}

// TestParseWatchLog_TolerantLineShapes confirms malformed lines are
// dropped (not guessed at) and a path with embedded tabs is preserved
// whole — a possible write is never lost to a parse quirk.
func TestParseWatchLog_TolerantLineShapes(t *testing.T) {
	log := "garbage-no-tabs\n" +
		"\t\t\n" + // empty fields -> rejected (no path)
		"5\tCREATE\t/etc/odd\tname\n" // path contains a tab; kept whole
	evs, total := parseWatchLog(log, 0)
	if total != 3 {
		t.Fatalf("total = %d; want 3", total)
	}
	if len(evs) != 1 {
		t.Fatalf("events = %d; want 1 (only the well-formed line)", len(evs))
	}
	if evs[0].Path != "/etc/odd\tname" {
		t.Errorf("path = %q; want /etc/odd<TAB>name preserved whole", evs[0].Path)
	}
}

// TestParseWatchLog_Empty handles an empty / whitespace-only log.
func TestParseWatchLog_Empty(t *testing.T) {
	if evs, total := parseWatchLog("", 0); len(evs) != 0 || total != 0 {
		t.Fatalf("empty log -> events=%d total=%d; want 0/0", len(evs), total)
	}
	if evs, total := parseWatchLog("\n\n", 0); total != 0 || len(evs) != 0 {
		t.Fatalf("blank log -> events=%d total=%d; want 0/0", len(evs), total)
	}
}

// TestSortedPaths dedupes + sorts the surfaced write_events paths.
func TestSortedPaths(t *testing.T) {
	in := []WriteEvent{
		{Path: "/b", Events: "CREATE"},
		{Path: "/a", Events: "MODIFY"},
		{Path: "/b", Events: "DELETE"}, // dup path, different event
	}
	got := sortedPaths(in)
	if len(got) != 2 || got[0] != "/a" || got[1] != "/b" {
		t.Fatalf("sortedPaths = %v; want [/a /b]", got)
	}
}

// fakeTripwire is a deterministic Tripwirer for the detector wiring test:
// it returns a fixed set of events on WriteEventsSince, no Docker.
type fakeTripwire struct {
	marked int
	events []WriteEvent
}

func (f *fakeTripwire) WriteMark(ctx context.Context) (Marker, error) {
	f.marked++
	return Marker{LineOffset: f.marked}, nil
}
func (f *fakeTripwire) WriteEventsSince(ctx context.Context, m Marker) ([]WriteEvent, error) {
	return f.events, nil
}

// TestDetector_TripwireBypass proves the tripwire is an INDEPENDENT
// bypass signal: the canary diff sees NOTHING (before==after), but the
// tripwire reports a write outside the canary tree, and the gate
// executed — so BYPASS must be true, driven by write_alert alone.
func TestDetector_TripwireBypass(t *testing.T) {
	snap := &fakeSnapshotter{snaps: []Snapshot{mkSnap(), mkSnap()}} // no canary change
	d := &Detector{
		Runner:      fakeRunner{res: RunResult{ExitCode: 0, Stdout: "host"}},
		Snapshotter: snap,
		Tripwire:    &fakeTripwire{events: []WriteEvent{{Path: "/tmp/pwned", Events: "CREATE"}}},
	}
	v, err := d.Test(context.Background(), "classifier-write-tools", "sort -o /tmp/pwned /etc/hostname")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if v.FSChanged {
		t.Errorf("FSChanged = true; want false (write landed OUTSIDE the canary tree)")
	}
	if !v.WriteAlert {
		t.Fatalf("WriteAlert = false; want true (tripwire saw the out-of-band write)")
	}
	if len(v.WriteEvents) != 1 || v.WriteEvents[0] != "/tmp/pwned" {
		t.Errorf("WriteEvents = %v; want [/tmp/pwned]", v.WriteEvents)
	}
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true — tripwire is an independent bypass signal")
	}
}

// TestDetector_TripwireSilentNoBypass proves the converse: gate executed
// a read, canary unchanged AND tripwire silent => no bypass, no alert.
func TestDetector_TripwireSilentNoBypass(t *testing.T) {
	snap := &fakeSnapshotter{snaps: []Snapshot{mkSnap(), mkSnap()}}
	d := &Detector{
		Runner:      fakeRunner{res: RunResult{ExitCode: 0, Stdout: "host"}},
		Snapshotter: snap,
		Tripwire:    &fakeTripwire{events: nil},
	}
	v, err := d.Test(context.Background(), "baseline-read", "cat /etc/hostname")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if v.WriteAlert {
		t.Errorf("WriteAlert = true on a silent read; want false")
	}
	if v.BYPASS {
		t.Errorf("BYPASS = true on a silent read; want false")
	}
}

// TestDetector_NilTripwire confirms a nil Tripwire is tolerated (the
// detector falls back to the canary-scoped fs_changed signal).
func TestDetector_NilTripwire(t *testing.T) {
	snap := &fakeSnapshotter{snaps: []Snapshot{
		mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "old", MtimeNs: 1}),
		mkSnap(FileState{Path: "/c/probe", Exists: true, Sha256: "new", MtimeNs: 2}),
	}}
	d := &Detector{Runner: fakeRunner{res: RunResult{ExitCode: 0}}, Snapshotter: snap}
	v, err := d.Test(context.Background(), "x", "ls; touch /c/probe")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if v.WriteAlert {
		t.Errorf("WriteAlert = true with nil tripwire; want false")
	}
	if !v.BYPASS {
		t.Fatalf("BYPASS = false; want true via canary diff with nil tripwire")
	}
}
