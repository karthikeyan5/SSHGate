package redact

import "bytes"

// PEM-armoured private keys are the longest plausible single secret
// in command output (RSA-2048 ≈ 1.6 KB, RSA-4096 ≈ 3.4 KB). The
// sliding-window scanner's safe-prefix (4 KiB) is enough for most
// PEM blocks, but a multi-key blob or a particularly large key can
// exceed the safe prefix. The PEM accumulator special-cases this:
// when the scanner sees `-----BEGIN ` it switches into accumulate
// mode and buffers verbatim until `-----END ...-----` (the matching
// END line) appears, then redacts the entire span.
//
// If END does not appear within pemMaxBuffer bytes (8 KiB), the
// accumulator aborts: the buffered bytes flush through unchanged,
// and the scanner resumes normal Layer 1 sliding-window mode at
// the byte after the BEGIN. This is "false BEGIN" recovery — e.g.
// a log line that happens to contain the literal `-----BEGIN ` is
// not a leak, and we must not hold its bytes forever.

const (
	pemBegin     = "-----BEGIN "
	pemEndPrefix = "-----END "
	pemEndSuffix = "-----"

	// pemMaxBuffer is the abort threshold. RSA-8192 PEM is ~6.5 KB;
	// 8 KiB covers it with room for a header comment. Beyond that
	// we declare false-BEGIN and flush.
	pemMaxBuffer = 8 * 1024
)

// pemAccumulator is the state machine the writer uses while inside
// a PEM block. Construction is via newPEMAccumulator; the writer
// drives it one chunk at a time.
type pemAccumulator struct {
	buf []byte
}

// newPEMAccumulator returns an accumulator pre-seeded with the BEGIN
// line bytes already observed by the scanner. start is the slice of
// bytes from `-----BEGIN ` up to wherever the writer's current chunk
// ends.
func newPEMAccumulator(start []byte) *pemAccumulator {
	// Defensive copy — the caller's slice may be reused.
	a := &pemAccumulator{buf: make([]byte, 0, len(start)+512)}
	a.buf = append(a.buf, start...)
	return a
}

// pemFeedResult describes what the writer should do after feeding
// bytes into the accumulator.
type pemFeedResult struct {
	// Complete is true when the accumulator found a matching END line
	// and the entire PEM span (Buffered) should be redacted as one
	// secret. The Tail is the unconsumed bytes after the END line —
	// the writer continues scanning Tail in normal mode.
	Complete bool
	// Aborted is true when the buffer hit pemMaxBuffer without ever
	// finding END. The Buffered bytes must pass through unchanged;
	// Tail is the unconsumed bytes the writer should re-feed to the
	// scanner.
	Aborted bool
	// Buffered is the full span the accumulator owned. On Complete
	// this is what gets replaced with a marker. On Aborted this is
	// what passes through.
	Buffered []byte
	// Tail is bytes from the input chunk that lie past the closing
	// END line (Complete) or past pemMaxBuffer (Aborted). The writer
	// resumes scanning these in normal mode.
	Tail []byte
}

// feed appends chunk into the accumulator and reports whether the
// PEM span is complete, aborted, or still in progress. While in
// progress all three Buffered/Tail/Complete/Aborted fields are zero.
func (a *pemAccumulator) feed(chunk []byte) pemFeedResult {
	// Append, then look for the END marker in the freshly-merged
	// buffer. We must scan the join because END could straddle the
	// previous chunk boundary.
	a.buf = append(a.buf, chunk...)

	if idx := findPEMEnd(a.buf); idx >= 0 {
		// Find the newline that terminates the END line; the span
		// includes the trailing newline so the wire stays clean.
		lineEnd := idx
		for lineEnd < len(a.buf) && a.buf[lineEnd] != '\n' {
			lineEnd++
		}
		if lineEnd < len(a.buf) {
			lineEnd++ // include the '\n'
		}
		span := make([]byte, lineEnd)
		copy(span, a.buf[:lineEnd])
		tail := append([]byte(nil), a.buf[lineEnd:]...)
		return pemFeedResult{Complete: true, Buffered: span, Tail: tail}
	}

	if len(a.buf) >= pemMaxBuffer {
		// False BEGIN: flush. Treat the BEGIN line itself as already
		// emitted-by-the-fact-of-buffering; the writer passes Buffered
		// through unchanged.
		buffered := append([]byte(nil), a.buf...)
		return pemFeedResult{Aborted: true, Buffered: buffered}
	}

	return pemFeedResult{}
}

// findPEMEnd locates the start of the first `-----END ...-----`
// marker in buf, or -1 if none is present. The match requires the
// `-----` suffix on the same line, so a stray `-----END ` inside an
// unrelated stream does not falsely trigger.
func findPEMEnd(buf []byte) int {
	off := 0
	for {
		idx := bytes.Index(buf[off:], []byte(pemEndPrefix))
		if idx < 0 {
			return -1
		}
		start := off + idx
		// Find the end of this line.
		lineEnd := start
		for lineEnd < len(buf) && buf[lineEnd] != '\n' {
			lineEnd++
		}
		line := buf[start:lineEnd]
		// Require the closing `-----` suffix (possibly with trailing
		// whitespace before the newline).
		trimmed := bytes.TrimRight(line, " \t\r")
		if bytes.HasSuffix(trimmed, []byte(pemEndSuffix)) {
			return start
		}
		off = lineEnd
		if off >= len(buf) {
			return -1
		}
	}
}

// findPEMBegin locates the first `-----BEGIN ` substring in buf, or
// -1 if absent. It is the writer's signal to enter accumulate mode.
func findPEMBegin(buf []byte) int {
	return bytes.Index(buf, []byte(pemBegin))
}
