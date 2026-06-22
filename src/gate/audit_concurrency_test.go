package gate_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/karthikeyan5/sshgate/src/gate"
)

// TestAuditConcurrentLargeAppendsStayIntact is the regression guard for the
// gate-audit "concurrent audit-append corruption at all+full" finding.
//
// THE CLAIM: AuditLogger.Record writes one marshaled JSON line via O_APPEND,
// and O_APPEND is "atomic only for writes <= PIPE_BUF (4 KiB)", so an
// all+full record carrying large captured output (>4 KiB) would interleave
// under concurrent gate processes.
//
// THE FINDING (why no production change was made): PIPE_BUF bounds atomicity
// for PIPES/FIFOs, NOT regular files. On a local filesystem the Linux kernel
// holds the inode lock for the whole O_APPEND write(2) regardless of size, so
// concurrent appends of arbitrarily large records do NOT interleave. (See
// open(2): the documented O_APPEND corruption caveat is specific to NFS,
// where the protocol lacks native append and the client must emulate it.)
// Each Record call also issues exactly ONE Write of the full line, so the
// kernel sees one append per record.
//
// This test pins that behavior: many concurrent loggers (each modelling a
// separate gate PROCESS — Record opens its own FD per call) append records
// far larger than PIPE_BUF at all+full, and every resulting line must be a
// single intact, valid JSON record with no interleaving and none lost.
//
// It ALSO acts as a tripwire on the implementation: if Record is ever changed
// to write a record across multiple Write calls (breaking single-write
// atomicity), this test will start failing — which is the right signal to add
// an advisory file lock (flock) at that point.
func TestAuditConcurrentLargeAppendsStayIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	const N = 64
	// ~32 KiB of captured output per record => marshaled line >> PIPE_BUF.
	big := strings.Repeat("Z", 32*1024)

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// A fresh logger per goroutine models a fresh per-command gate
			// process; Record does its own open/append/fsync/close.
			lg := gate.NewAuditLogger(gate.AuditAllFull, path)
			lg.Record(gate.AuditRecord{
				TS:             int64(i),
				Command:        "big-output-cmd",
				Classification: "read",
				ApprovalStatus: "unsigned",
				ExitCode:       0,
				Stdout:         big,
			})
		}(i)
	}
	wg.Wait()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
	lines, invalid := 0, 0
	for sc.Scan() {
		lines++
		var r gate.AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			invalid++
			continue
		}
		// A correctly-written record carries the full big payload intact —
		// an interleaved/truncated line would unmarshal-fail or have a short
		// Stdout.
		if len(r.Stdout) != len(big) {
			invalid++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if invalid != 0 {
		t.Errorf("found %d corrupt/interleaved audit lines; O_APPEND atomicity violated", invalid)
	}
	if lines != N {
		t.Errorf("got %d audit lines, want %d (records lost or merged under concurrency)", lines, N)
	}
}
