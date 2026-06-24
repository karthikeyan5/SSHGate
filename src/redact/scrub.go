package redact

import "bytes"

// RedactString runs the streaming Layer-1 redactor over s in one shot and
// returns the scrubbed result. It is the canonical way to scrub a string
// that is about to be LOGGED (a command string, an audit field) — the
// SAME ruleset that scrubs command OUTPUT, applied to text at rest, so the
// assignment/Authorization/PGPASSWORD/URL cases are caught identically to
// how they are caught in output today.
//
// It is pure: (salt, rules, s) in, scrubbed string out; no shared state,
// no goroutine concerns (each call builds its own Writer). Benign input
// (no rule matches) passes through byte-for-byte unchanged.
//
// Fail-OPEN: on any internal Write/Close error it returns s unchanged AND
// ok=false, so the caller can log the raw string rather than DROP the
// audit line. Observability of "what ran" must never be blocked by the
// redactor; a missing audit line is worse than a rare un-redacted one.
//
// SCOPE NOTE: RedactString does NOT close the password-as-CLI-flag ruleset
// gap (e.g. `mysql -p<secret>`) — it reuses the existing Combined()
// ruleset, which only covers the URL-userinfo form of those secrets. See
// scrub_test.go's pinned XFAIL.
func RedactString(s string, salt [32]byte, rules []Rule) (string, bool) {
	if s == "" || len(rules) == 0 {
		return s, true
	}
	var buf bytes.Buffer
	w := NewWriter(&buf, salt, rules)
	if _, err := w.Write([]byte(s)); err != nil {
		return s, false
	}
	if err := w.Close(); err != nil {
		return s, false
	}
	return buf.String(), true
}
