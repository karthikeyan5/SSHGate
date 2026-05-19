package redact_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
	"github.com/karthikeyan5/sshgate/src/redact/rules"
)

func writerWithCombinedRules(t *testing.T, dst io.Writer, salt [32]byte) *redact.Writer {
	t.Helper()
	return redact.NewWriter(dst, salt, rules.Combined())
}

func TestWriterRedactsAWSKey(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	in := []byte("export AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF\n")
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := out.String()
	if strings.Contains(s, "AKIA1234567890ABCDEF") {
		t.Errorf("AWS key leaked: %q", s)
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("no marker: %q", s)
	}
}

func TestWriterChunkBoundary(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i)
	}
	// Embed a known AWS access key in a 20 KB buffer of noise so the
	// secret lands in different positions across chunk sizes.
	noise := bytes.Repeat([]byte("padding-padding-padding\n"), 800)
	secret := []byte("AKIAABCDEFGHIJKLMNOP")
	input := append([]byte(nil), noise...)
	input = append(input, []byte("before ")...)
	input = append(input, secret...)
	input = append(input, []byte(" after\n")...)
	input = append(input, noise...)

	for _, chunk := range []int{8, 16, 32, 256, 1024, 8 * 1024, 64 * 1024} {
		chunk := chunk
		t.Run("chunk-"+itoa(chunk), func(t *testing.T) {
			var out bytes.Buffer
			w := writerWithCombinedRules(t, &out, salt)
			for i := 0; i < len(input); i += chunk {
				end := i + chunk
				if end > len(input) {
					end = len(input)
				}
				if _, err := w.Write(input[i:end]); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			s := out.String()
			if bytes.Contains(out.Bytes(), secret) {
				t.Errorf("chunk=%d: secret leaked at offset %d", chunk, bytes.Index(out.Bytes(), secret))
			}
			if !strings.Contains(s, redact.MarkerPrefix) {
				t.Errorf("chunk=%d: no marker; out len=%d", chunk, len(s))
			}
		})
	}
}

func TestWriterSafePrefixBufferGrowsAndCaps(t *testing.T) {
	var salt [32]byte
	// 200 KB of plain text — no rules should fire, but the writer
	// must not buffer all 200 KB before emitting anything (it'd OOM
	// in practice). Verify we see output before Close.
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	for i := 0; i < 200; i++ {
		if _, err := w.Write(bytes.Repeat([]byte("a"), 1024)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	// We expect at least (200 KB - 64 KiB) emitted before Close.
	if out.Len() < 100*1024 {
		t.Errorf("emitted %d bytes before close; expected at least 100 KiB (writer must flush past ring cap)", out.Len())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if out.Len() != 200*1024 {
		t.Errorf("after close: emitted %d bytes; want %d", out.Len(), 200*1024)
	}
}

func TestWriterPassesThroughBenignBytes(t *testing.T) {
	var salt [32]byte
	in := []byte("ls -la /etc/\ntotal 1.2K\nfile1\nfile2\n")
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(out.Bytes(), in) {
		t.Errorf("benign bytes altered.\n got: %q\nwant: %q", out.String(), in)
	}
}

func TestWriterDeterministicWithinSession(t *testing.T) {
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	in := []byte("AKIA1234567890ABCDEF AKIA1234567890ABCDEF\n")
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s := out.String()
	// Both occurrences must produce the same marker (same secret, same salt).
	first := strings.Index(s, redact.MarkerPrefix)
	last := strings.LastIndex(s, redact.MarkerPrefix)
	if first == -1 || first == last {
		t.Fatalf("expected two markers, got %q", s)
	}
	end1 := strings.Index(s[first:], redact.MarkerSuffix) + first + len(redact.MarkerSuffix)
	end2 := strings.Index(s[last:], redact.MarkerSuffix) + last + len(redact.MarkerSuffix)
	m1 := s[first:end1]
	m2 := s[last:end2]
	if m1 != m2 {
		t.Errorf("same secret produced different markers: %q vs %q", m1, m2)
	}
}

func TestWriterFreshnessAcrossSessions(t *testing.T) {
	in := []byte("AKIA1234567890ABCDEF\n")
	mk := func() string {
		var salt [32]byte
		if _, err := rand.Read(salt[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		var out bytes.Buffer
		w := writerWithCombinedRules(t, &out, salt)
		if _, err := w.Write(in); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		return out.String()
	}
	a := mk()
	b := mk()
	if a == b {
		t.Errorf("two sessions produced identical output (freshness violated):\n%q\n%q", a, b)
	}
}

func TestWriterClosed(t *testing.T) {
	var salt [32]byte
	w := redact.NewWriter(io.Discard, salt, nil)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, redact.ErrWriterClosed) {
		t.Errorf("Write after Close = %v, want ErrWriterClosed", err)
	}
	// Idempotent close.
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestWriterRedactionCounter(t *testing.T) {
	var salt [32]byte
	in := []byte("AKIA1234567890ABCDEF and ghp_" + strings.Repeat("a", 40) + "\n")
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c := w.Redactions(); c < 2 {
		t.Errorf("Redactions() = %d, want >= 2", c)
	}
}

func TestWriterSingleByteWrites(t *testing.T) {
	var salt [32]byte
	in := []byte("noise AKIAABCDEFGHIJKLMNOP noise\n")
	var out bytes.Buffer
	w := writerWithCombinedRules(t, &out, salt)
	for i := 0; i < len(in); i++ {
		if _, err := w.Write(in[i : i+1]); err != nil {
			t.Fatalf("Write byte %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("AKIAABCDEFGHIJKLMNOP")) {
		t.Errorf("byte-at-a-time: secret leaked: %q", out.String())
	}
	if !strings.Contains(out.String(), redact.MarkerPrefix) {
		t.Errorf("byte-at-a-time: no marker: %q", out.String())
	}
}
