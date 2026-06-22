package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auditRecords reads the gate-side audit log from gateDir/audit.log (or
// the path override) and returns the decoded JSON-Lines records. Returns
// an empty slice when the file is absent (the off-level case).
func auditRecords(t *testing.T, gateDir string) []map[string]any {
	t.Helper()
	path := filepath.Join(gateDir, "audit.log")
	if override, err := os.ReadFile(filepath.Join(gateDir, "audit-path")); err == nil {
		if p := strings.TrimSpace(string(override)); p != "" {
			path = p
		}
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("open audit log: %v", err)
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
			t.Fatalf("bad json line %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return recs
}

// setAuditLevel writes gateDir/audit-level. Use "" to leave it absent
// (which exercises the all+meta default).
func setAuditLevel(t *testing.T, gateDir, level string) {
	t.Helper()
	if level == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(gateDir, "audit-level"), []byte(level), 0o600); err != nil {
		t.Fatalf("write audit-level: %v", err)
	}
}

// TestGateAuditDefaultLevel proves the gate-side authoritative log
// records a read at the DEFAULT level (no audit-level file => all+meta),
// with output metadata present and NO raw output.
func TestGateAuditDefaultLevel(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	// No audit-level file: default all+meta.

	f := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(f, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	line := signedLine(t, priv, freshPayload("cat "+f))
	code, _, _ := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}

	recs := auditRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d audit records, want 1", len(recs))
	}
	r := recs[0]
	if r["classification"] != "read" {
		t.Errorf("classification = %v, want read", r["classification"])
	}
	if r["approval_status"] != "signed" {
		t.Errorf("approval_status = %v, want signed", r["approval_status"])
	}
	meta, ok := r["meta"].(map[string]any)
	if !ok {
		t.Fatalf("default all+meta must include meta: %v", r)
	}
	if meta["stdout_bytes"].(float64) <= 0 {
		t.Errorf("meta.stdout_bytes = %v, want > 0", meta["stdout_bytes"])
	}
	if meta["lines"].(float64) != 2 {
		t.Errorf("meta.lines = %v, want 2", meta["lines"])
	}
	if _, leaked := r["stdout"]; leaked {
		t.Errorf("all+meta leaked raw stdout: %v", r)
	}
}

// TestGateAuditLevelMatrix drives run() at each level and asserts the
// right records are emitted.
func TestGateAuditLevelMatrix(t *testing.T) {
	t.Run("off emits nothing", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		setAuditLevel(t, dir, "off")

		f := filepath.Join(dir, "x.txt")
		_ = os.WriteFile(f, []byte("hi\n"), 0o644)
		line := signedLine(t, priv, freshPayload("cat "+f))
		runWith(t, line)
		if recs := auditRecords(t, dir); len(recs) != 0 {
			t.Errorf("off level emitted %d records, want 0", len(recs))
		}
	})

	t.Run("writes emits a rejection but not a read", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		setAuditLevel(t, dir, "writes")

		// An unsigned read (cat) — must NOT be logged at the writes level.
		f := filepath.Join(dir, "x.txt")
		_ = os.WriteFile(f, []byte("hi\n"), 0o644)
		runWith(t, "cat "+f)
		// An unsigned write (rm) — a denial, logged from writes up.
		runWith(t, "rm -rf /tmp/whatever")

		recs := auditRecords(t, dir)
		if len(recs) != 1 {
			t.Fatalf("writes level: got %d records, want 1 (the rejection)", len(recs))
		}
		if recs[0]["approval_status"] != "denied" {
			t.Errorf("expected denied rejection record, got %v", recs[0])
		}
		if recs[0]["classification"] == "read" {
			t.Errorf("writes level leaked a read: %v", recs[0])
		}
	})

	t.Run("all emits reads and writes", func(t *testing.T) {
		dir := t.TempDir()
		pub, _ := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		setAuditLevel(t, dir, "all")

		f := filepath.Join(dir, "x.txt")
		_ = os.WriteFile(f, []byte("hi\n"), 0o644)
		runWith(t, "cat "+f)           // unsigned read
		runWith(t, "rm -rf /tmp/nope") // unsigned write -> denial

		recs := auditRecords(t, dir)
		if len(recs) != 2 {
			t.Fatalf("all level: got %d records, want 2", len(recs))
		}
		var sawRead, sawDeny bool
		for _, r := range recs {
			if r["classification"] == "read" {
				sawRead = true
			}
			if r["approval_status"] == "denied" {
				sawDeny = true
			}
			// `all` (below all+meta) carries no meta and no raw output.
			if _, ok := r["meta"]; ok {
				t.Errorf("all level must not include meta: %v", r)
			}
		}
		if !sawRead || !sawDeny {
			t.Errorf("all level: sawRead=%v sawDeny=%v, want both", sawRead, sawDeny)
		}
	})

	t.Run("all+full includes raw output", func(t *testing.T) {
		dir := t.TempDir()
		pub, priv := genKey(t)
		seedPub(t, dir, pub, 0o644)
		withGateDir(t, dir)
		setAuditLevel(t, dir, "all+full")

		const marker = "AUDIT-FULL-OUTPUT-MARKER"
		f := filepath.Join(dir, "x.txt")
		_ = os.WriteFile(f, []byte(marker+"\n"), 0o644)
		line := signedLine(t, priv, freshPayload("cat "+f))
		runWith(t, line)

		recs := auditRecords(t, dir)
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "audit.log"))
		if !strings.Contains(string(raw), marker) {
			t.Errorf("all+full must capture raw output; log=%s", raw)
		}
	})
}

// TestGateAuditAppendsAcrossInvocations proves records accumulate (the
// log is append-only across separate gate spawns / run() calls).
func TestGateAuditAppendsAcrossInvocations(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)
	// default all+meta

	f := filepath.Join(dir, "x.txt")
	_ = os.WriteFile(f, []byte("hi\n"), 0o644)
	for i := 0; i < 3; i++ {
		line := signedLine(t, priv, freshPayload("cat "+f))
		runWith(t, line)
	}
	if recs := auditRecords(t, dir); len(recs) != 3 {
		t.Errorf("append-only across invocations: got %d, want 3", len(recs))
	}
}

// TestGateAuditFailOpen proves an unwritable audit path does NOT block
// the command — the read still runs and returns its output.
func TestGateAuditFailOpen(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	// Point audit-path at an unwritable location (a file used as a dir
	// component => ENOTDIR on open).
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit-path"), []byte(filepath.Join(blocker, "audit.log")), 0o600); err != nil {
		t.Fatal(err)
	}

	f := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(f, []byte("still-runs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	line := signedLine(t, priv, freshPayload("cat "+f))
	code, out, _ := runWith(t, line)
	if code != exitOK {
		t.Errorf("exit = %d, want 0 (audit failure must not block the command)", code)
	}
	if !strings.Contains(out, "still-runs") {
		t.Errorf("command output missing; audit failure blocked it? out=%q", out)
	}
}

// TestGateAuditMetricsPopulatedAndPlausible asserts the metrics on a
// signed write are present and plausible (non-zero duration; byte/line
// counts match the child output).
func TestGateAuditMetricsPopulated(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)
	seedPub(t, dir, pub, 0o644)
	withGateDir(t, dir)

	// A signed write that prints 3 lines then exits 0. `sh -c ...`
	// classifies as a write (the classifier treats sh -c as a write head),
	// so this exercises the signed-write exec+audit path.
	line := signedLine(t, priv, freshPayload(`sh -c "printf 'a\nbb\nccc\n'"`))
	code, _, _ := runWith(t, line)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	recs := auditRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r["classification"] != "write" {
		t.Errorf("classification = %v, want write", r["classification"])
	}
	meta := r["meta"].(map[string]any)
	if meta["stdout_bytes"].(float64) != 9 {
		t.Errorf("meta.stdout_bytes = %v, want 9", meta["stdout_bytes"])
	}
	if meta["lines"].(float64) != 3 {
		t.Errorf("meta.lines = %v, want 3", meta["lines"])
	}
	// duration_ms may be 0 for a sub-millisecond command — that's still
	// plausible; assert it is present and non-negative.
	if meta["duration_ms"].(float64) < 0 {
		t.Errorf("meta.duration_ms = %v, want >= 0", meta["duration_ms"])
	}
}
