// Package livelog implements Tier 6b of the SSHGate audit trail: the
// MCP-side rolling live log.
//
// This is the CONVENIENCE / observability surface, NOT the system of
// record. The system of record is the gate-side authoritative log
// (src/gate/audit.go, Tier 6a), which the agent cannot reach because it
// only speaks through the gate. THIS log lives in the MCP's trust domain
// — the same domain the agent shares — so it is intentionally treated as
// erasable/transient and is never relied on for the tamper-resistant
// record.
//
// It is a SIZE-CAPPED ROLLING buffer (terminal-scrollback style): older
// lines are auto-dropped once the file would exceed the cap, so it stays
// bounded and transient. It carries the WHOLE command + full output by
// design — it is what a human watches with `tail -f` for a live operator
// view, subsuming the old "Live Command View" idea.
//
// On by default with a sane cap; both the cap and on/off are
// configurable via a setting under ~/.config/sshgate/ (see the MCP
// wiring). A logging failure is fail-open (swallowed) — like Tier 6a,
// observability must never block a command.
package livelog

import (
	"encoding/json"
	"os"
	"sync"
)

// Entry is one MCP-side live-log record. It carries the full command and
// full output (the convenience surface), unlike the gate-side log which
// defaults to metadata only.
type Entry struct {
	// TS is UTC epoch seconds (set by Log if zero).
	TS int64 `json:"ts"`
	// Server is the registered alias the command ran against.
	Server string `json:"server"`
	// Command is the full shell command.
	Command string `json:"command"`
	// Classification is "read" or "write".
	Classification string `json:"classification"`
	// ExitCode is the command's exit code.
	ExitCode int `json:"exit_code"`
	// Approved is true when the command was a write the signer approved —
	// by EITHER a real-time human Telegram tap OR a standing-grant
	// auto-sign. It does NOT by itself mean a human approved this specific
	// write (a live grant auto-signs without a tap), so it cannot
	// distinguish the two. Use AuthMode for that human-vs-grant distinction.
	Approved bool `json:"approved"`
	// AuthMode records HOW an approved write was authorised, decoupled from
	// the Approved bool: "human" = a real-time Telegram approval; "grant:<id>"
	// = a standing-grant auto-sign (no tap); empty for reads and any
	// non-approved outcome. omitempty keeps a read entry's wire shape
	// unchanged.
	AuthMode string `json:"auth_mode,omitempty"`
	// Revealed is true when the command ran as a SECRET-REVEAL (its output
	// bypassed the gate redactor). For a revealed entry the caller MUST leave
	// Stdout/Stderr empty: the live log records THAT a reveal ran (command,
	// classification, exit, revealed:true) but is never a secret store, so the
	// raw revealed output is excluded here. reveal's accepted exposure is the
	// agent + transcript + approval chat — not this on-disk log.
	Revealed bool `json:"revealed,omitempty"`
	// Stdout / Stderr carry the FULL output (no redaction-metadata
	// substitution here — this is the live view). They are blanked for a
	// revealed entry (see Revealed).
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	// Seq is an optional monotonic counter used by tests to detect which
	// entries survived a roll; harmless in production.
	Seq int `json:"seq,omitempty"`
}

// Log is the rolling MCP-side live log. The zero value is not usable;
// call New. A nil *Log is a valid no-op target (Log does nothing), so
// callers can keep an always-non-nil field and disable via cap=0.
type Log struct {
	mu       sync.Mutex
	path     string
	capBytes int64
	nowFn    func() int64
}

// New returns a rolling live log at path with the given byte cap. A cap
// of 0 (or negative) disables the log entirely (Log is a no-op and the
// file is never created) — that is the "off" setting.
func New(path string, capBytes int64) *Log {
	return &Log{path: path, capBytes: capBytes, nowFn: nowUnix}
}

// Log appends e as one JSON line, then rolls the file if it now exceeds
// the cap (dropping the oldest lines, terminal-scrollback style). All
// errors are swallowed (fail-open): the live log is observability, never
// a gate. A nil *Log or a cap<=0 is a silent no-op.
func (l *Log) Log(e Entry) {
	if l == nil || l.capBytes <= 0 {
		return
	}
	if e.TS == 0 {
		e.TS = l.nowFn()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return // fail-open
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return // fail-open
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return // fail-open
	}
	_ = f.Close()

	l.rollIfNeeded()
}

// rollIfNeeded trims the file from the FRONT (oldest lines) until it fits
// within capBytes. It reads the whole file, keeps the newest suffix of
// complete lines that fits, and atomically rewrites. Errors are swallowed
// (fail-open).
//
// A single line larger than the cap is kept whole (we never split a
// record); the file may momentarily exceed the cap by that one line,
// which the tests tolerate.
func (l *Log) rollIfNeeded() {
	info, err := os.Stat(l.path)
	if err != nil || info.Size() <= l.capBytes {
		return
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	// Split into lines, each retaining its trailing '\n'. A trailing
	// empty segment (after the final '\n') is ignored.
	lines := splitKeepNewline(data)

	// Keep the newest suffix of lines whose total size fits the cap. Walk
	// from the newest (end) backwards, always keeping at least one line.
	var total int64
	startIdx := len(lines)
	for i := len(lines) - 1; i >= 0; i-- {
		size := int64(len(lines[i]))
		if total+size > l.capBytes && startIdx < len(lines) {
			break
		}
		total += size
		startIdx = i
	}
	var kept []byte
	for _, ln := range lines[startIdx:] {
		kept = append(kept, ln...)
	}

	// Atomic replace: write to a temp file in the same dir, then rename.
	tmp, err := os.CreateTemp(dirOf(l.path), ".audit-live-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(kept); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, l.path)
}
