package velsigner_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/velsigner"
)

func TestAuditLog_WriteAndReopenParses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")

	log, err := velsigner.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ev1 := velsigner.AuditEvent{
		TS:        time.Now().UTC(),
		RequestID: "r_1",
		Status:    "approved",
		Commands:  []string{"systemctl restart nginx"},
		Servers:   []string{"prod-db"},
	}
	ev2 := velsigner.AuditEvent{
		TS:        time.Now().UTC(),
		RequestID: "r_2",
		Status:    "denied",
		Commands:  []string{"rm -rf /"},
		Servers:   []string{"prod-db"},
	}
	if err := log.Write(ev1); err != nil {
		t.Fatalf("Write ev1: %v", err)
	}
	if err := log.Write(ev2); err != nil {
		t.Fatalf("Write ev2: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen + parse
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	var got []velsigner.AuditEvent
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev velsigner.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("parse %q: %v", sc.Text(), err)
		}
		got = append(got, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events; want 2", len(got))
	}
	if got[0].RequestID != "r_1" || got[1].RequestID != "r_2" {
		t.Errorf("got request IDs %v; want [r_1 r_2]", []string{got[0].RequestID, got[1].RequestID})
	}
	if got[0].Status != "approved" || got[1].Status != "denied" {
		t.Errorf("statuses = %v / %v; want approved / denied", got[0].Status, got[1].Status)
	}
}

func TestAuditLog_FileMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	log, err := velsigner.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// We accept 0640 or 0600 — umask may strip group bits — but reject
	// any world-readable mode.
	if got := info.Mode().Perm(); got&0o007 != 0 {
		t.Errorf("audit log mode = %#o; world bits must be off", got)
	}
}

func TestAuditLog_ConcurrentWritesDontInterleave(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	log, err := velsigner.OpenAuditLog(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			ev := velsigner.AuditEvent{
				TS:        time.Now().UTC(),
				RequestID: "r_" + itoaPad(i),
				Status:    "approved",
				Commands:  []string{"echo " + itoaPad(i)},
				Servers:   []string{"s"},
			}
			if err := log.Write(ev); err != nil {
				t.Errorf("write %d: %v", i, err)
			}
		}()
	}
	wg.Wait()
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every line must parse as a complete JSON object. If concurrent
	// writes interleaved, json.Unmarshal will fail on at least one line.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		var ev velsigner.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d failed to parse: %v\nline=%q", count, err, sc.Text())
		}
		count++
	}
	if count != N {
		t.Errorf("got %d lines; want %d", count, N)
	}
}

func TestAuditLog_PersistsAcrossClose(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.log")
	// Three writes through three separate OpenAuditLog/Write/Close
	// cycles emulate a daemon that crashes and is restarted between
	// each event. With fsync-per-write, all three lines must survive.
	for i := 0; i < 3; i++ {
		log, err := velsigner.OpenAuditLog(path)
		if err != nil {
			t.Fatalf("Open[%d]: %v", i, err)
		}
		ev := velsigner.AuditEvent{
			TS:        time.Now().UTC(),
			RequestID: "r_" + itoaPad(i),
			Status:    "approved",
			Commands:  []string{"x"},
			Servers:   []string{"s"},
		}
		if err := log.Write(ev); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
		if err := log.Close(); err != nil {
			t.Fatalf("Close[%d]: %v", i, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLines(data); got != 3 {
		t.Errorf("line count = %d; want 3", got)
	}
}

// helpers
func itoaPad(i int) string {
	// fixed-width tag so request IDs sort and the test diagnostic is
	// human readable; not load-bearing.
	const digits = "0123456789"
	hi := i / 10
	lo := i % 10
	return string([]byte{digits[hi%10], digits[lo]})
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
