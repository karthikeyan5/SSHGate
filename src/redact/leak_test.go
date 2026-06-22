package redact_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

// leakWriter builds a writer over the full combined ruleset with a
// fixed non-zero salt so markers are reproducible across runs.
func leakWriter(t *testing.T, dst *bytes.Buffer) *redact.Writer {
	t.Helper()
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	return redact.NewWriter(dst, salt, rules.Combined())
}

// ---------------------------------------------------------------------
// BLOCKER 1 — aborted-PEM span must be re-scanned, not flushed raw.
//
// When an accumulated `-----BEGIN` block exceeds pemMaxBuffer (8 KiB)
// without ever seeing `-----END`, the writer historically wrote the
// buffered span RAW to dst, bypassing the Layer-1 scanner. Any secret
// living inside that span leaked verbatim. After the fix the aborted
// span (and its tail) must pass back through scanAndEmit so embedded
// secrets are still redacted.
// ---------------------------------------------------------------------
func TestAbortedPEMSpanIsScannedNotFlushedRaw(t *testing.T) {
	var out bytes.Buffer
	w := leakWriter(t, &out)

	awsKey := "AKIA" + strings.Repeat("Q", 16) // valid AWS access-key shape
	pat := "ghp_" + strings.Repeat("a", 40)    // GitHub PAT

	// A false BEGIN line, two real secrets, then >8 KiB of padding and
	// NO END marker — forces the accumulator to abort.
	var in bytes.Buffer
	in.WriteString("log noise\n")
	in.WriteString("-----BEGIN FAKE-----\n")
	in.WriteString("aws=" + awsKey + "\n")
	in.WriteString("pat=" + pat + "\n")
	in.Write(bytes.Repeat([]byte("Z"), 9*1024)) // padding, no END
	in.WriteString("\nstill-no-end\n")

	if _, err := w.Write(in.Bytes()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	if strings.Contains(s, awsKey) {
		t.Errorf("BLOCKER1: AWS key leaked through aborted-PEM raw flush")
	}
	if strings.Contains(s, pat) {
		t.Errorf("BLOCKER1: GitHub PAT leaked through aborted-PEM raw flush")
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("BLOCKER1: expected redaction markers in aborted span; out had none")
	}
	// The benign false-BEGIN framing and tail should still survive.
	if !strings.Contains(s, "still-no-end") {
		t.Errorf("BLOCKER1: post-abort tail was lost")
	}
}

// ---------------------------------------------------------------------
// BLOCKER 2 — unterminated PEM key at EOF must be scanned, not flushed
// raw.
//
// If output ends mid-key (a real `-----BEGIN ... PRIVATE KEY-----` with
// body but no closing `-----END`), Close historically flushed the
// buffered PEM bytes RAW. The body must instead be treated as a
// redaction at EOF.
// ---------------------------------------------------------------------
func TestUnterminatedPEMAtEOFIsRedacted(t *testing.T) {
	var out bytes.Buffer
	w := leakWriter(t, &out)

	// A real-shaped OpenSSH key block with a body but no END line.
	body := strings.Repeat("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB", 6)
	var in bytes.Buffer
	in.WriteString("here is a key:\n")
	in.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	in.WriteString(body + "\n")
	// EOF — no -----END line.

	if _, err := w.Write(in.Bytes()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	if strings.Contains(s, body) {
		t.Errorf("BLOCKER2: unterminated PEM key body leaked raw at EOF:\n%q", s)
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("BLOCKER2: expected a redaction marker for the unterminated key; got %q", s)
	}
	if !strings.HasPrefix(s, "here is a key:\n") {
		t.Errorf("BLOCKER2: benign prefix lost or altered: %q", s)
	}
}

// ---------------------------------------------------------------------
// BLOCKER 3 — common secret classes the ruleset historically missed.
//
// (a) secret VALUES behind common assignment shapes
// (b) URL-embedded credentials  scheme://user:pass@host
// (c) modern provider prefixes the vendored gitleaks predates
//
// In every case the VALUE must be redacted (a marker present, secret
// absent); the surrounding key-name / framing should survive where
// reasonable. Bias is toward redacting.
// ---------------------------------------------------------------------

// redactString feeds s through a combined-ruleset writer and returns
// the scrubbed output. Mirrors the helper in scanner_test.go but uses
// the leak-test salt so the two files don't collide on a name.
func redactString(t *testing.T, s string) string {
	t.Helper()
	var out bytes.Buffer
	w := leakWriter(t, &out)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.String()
}

func TestAssignmentShapeValuesRedacted(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string
	}{
		{"API_KEY", "API_KEY=sk_supersecretvalue_12345", "sk_supersecretvalue_12345"},
		{"bare KEY", "MY_KEY=abcdef0123456789ZZ", "abcdef0123456789ZZ"},
		{"TOKEN", "ACCESS_TOKEN=tok_abcdef1234567890", "tok_abcdef1234567890"},
		{"SECRET", "CLIENT_SECRET=s3cr3t-value-here-9999", "s3cr3t-value-here-9999"},
		{"DB_PASSWORD", "DB_PASSWORD=hunter2-prod-pw", "hunter2-prod-pw"},
		{"FOO_PASS", "MYSQL_PASS=rootpassword123", "rootpassword123"},
		{"PGPASSWORD", "PGPASSWORD=postgres-secret-pw", "postgres-secret-pw"},
		{"quoted with spaces", `PASSWORD="my secret pass phrase"`, "my secret pass phrase"},
		{"single-quoted spaces", `ADMIN_PASSWORD='another secret here'`, "another secret here"},
		{"export form", "export API_TOKEN=ghx_realtokenvalue_xyz789", "ghx_realtokenvalue_xyz789"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out := redactString(t, tc.in+"\n")
			if strings.Contains(out, tc.secret) {
				t.Errorf("BLOCKER3a: value leaked.\nin:  %q\nout: %q", tc.in, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("BLOCKER3a: no marker emitted; out=%q", out)
			}
		})
	}
}

func TestURLEmbeddedCredentialsRedacted(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		secret string // the password portion that must not survive
	}{
		{"postgres", "DATABASE_URL=postgres://admin:s3cr3tpw@db.host:5432/app", "s3cr3tpw"},
		{"redis", "redis://default:redispassword@cache:6379/0", "redispassword"},
		{"mysql", "mysql://root:my-mysql-pw@127.0.0.1:3306/db", "my-mysql-pw"},
		{"mongodb", "mongodb://svc:mongoSecret123@cluster0/db", "mongoSecret123"},
		{"https", "https://user:httpsecretpw@api.example.com/v1", "httpsecretpw"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out := redactString(t, tc.in+"\n")
			if strings.Contains(out, tc.secret) {
				t.Errorf("BLOCKER3b: URL password leaked.\nin:  %q\nout: %q", tc.in, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("BLOCKER3b: no marker; out=%q", out)
			}
		})
	}
}

// ---------------------------------------------------------------------
// MAJOR 5 — ringMax (64 KiB) must actually bound the safe-prefix
// buffer. The writer's straddler logic retreats emitUpTo to the start
// of any match crossing the prefix/tail boundary; an adversarial stream
// that keeps a single match perpetually open (a long bearer-token body
// fed in chunks, never terminated) makes emitUpTo retreat to ~0 every
// round, so the buffer accumulates every byte ever written — unbounded.
// ringMax forces an unconditional head-flush once the buffer crosses
// the cap, bounding memory at the documented invariant. A straddling
// secret near the cap must still not leak.
// ---------------------------------------------------------------------
func TestRingMaxBoundsBuffer(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 7)
	}

	// A pathological rule: an open-ended secret with a huge MaxLen. Its
	// regex keeps matching a span that ends at the buffer tail, so every
	// processBuffer round the match straddles the prefix/tail boundary
	// and emitUpTo retreats toward the match start. Without an
	// unconditional ringMax flush the buffer accumulates EVERY byte ever
	// written — the unbounded-growth bug ringMax is supposed to prevent.
	bigRule := redact.CompileRule(
		"test-open-secret",
		"open-ended high-MaxLen secret",
		`SECRETSTART([A-Za-z0-9]+)`,
		[]string{"SECRETSTART"},
		1, 0, 10*1024*1024, // 10 MB MaxLen — far past ringMax
	)

	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, []redact.Rule{bigRule})

	if _, err := w.Write([]byte("prefix SECRETSTART")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Stream 1 MiB of secret-body bytes in 4 KiB chunks. The match never
	// terminates within a Write, so it perpetually straddles.
	chunk := bytes.Repeat([]byte("A"), 4*1024)
	for i := 0; i < 256; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		if got := w.Buffered(); got > redact.RingMax()+len(chunk) {
			t.Fatalf("MAJOR5: buffer grew to %d bytes (> ringMax %d + one chunk %d) — cap NOT enforced",
				got, redact.RingMax(), len(chunk))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// And the straddling secret body must not have leaked at the cap
	// boundary — a forced head-flush must redact, not emit raw.
	if bytes.Contains(out.Bytes(), bytes.Repeat([]byte("A"), 2048)) {
		t.Errorf("MAJOR5: secret body leaked raw across the ringMax flush boundary")
	}
}

func TestModernProviderPrefixesRedacted(t *testing.T) {
	cases := []struct {
		name   string
		secret string
	}{
		{"openai-proj", "sk-proj-" + strings.Repeat("A", 48)},
		{"anthropic", "sk-ant-api03-" + strings.Repeat("B", 80) + "-" + strings.Repeat("C", 8)},
		{"digitalocean", "dop_v1_" + strings.Repeat("d", 64)},
		{"xai", "xai-" + strings.Repeat("e", 64)},
		{"groq", "gsk_" + strings.Repeat("f", 52)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			in := "KEY here -> " + tc.secret + " <- end\n"
			out := redactString(t, in)
			if strings.Contains(out, tc.secret) {
				t.Errorf("BLOCKER3c: %s token leaked.\nin:  %q\nout: %q", tc.name, in, out)
			}
			if !strings.Contains(out, redact.MarkerPrefix) {
				t.Errorf("BLOCKER3c: no marker; out=%q", out)
			}
		})
	}
}
