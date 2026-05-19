package redact_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

// pemKey generates a real RSA-2048 PEM block — 1.7-1.9 KB depending
// on the exact key. We use it for the small-chunk write tests so
// the fixture is structurally identical to what we'd see in the wild.
func pemKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestPEMFullBlockRedactedAsOneSpan(t *testing.T) {
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	key := pemKey(t)
	input := []byte("prefix-line\n")
	input = append(input, key...)
	input = append(input, []byte("suffix-line\n")...)

	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil) // no rules — PEM accumulator owns this
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	if strings.Contains(s, "BEGIN PRIVATE KEY") {
		t.Errorf("output still contains the PEM block:\n%s", s)
	}
	if !strings.HasPrefix(s, "prefix-line\n") {
		t.Errorf("prefix line missing or altered: %q", s[:min(len(s), 30)])
	}
	if !strings.Contains(s, "suffix-line") {
		t.Errorf("suffix line missing")
	}
	if !strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("no inline marker present: %q", s)
	}
}

func TestPEMSpanningSmallChunkWrites(t *testing.T) {
	var salt [32]byte
	key := pemKey(t)
	input := []byte("warmup\n")
	input = append(input, key...)
	input = append(input, []byte("tail\n")...)

	for _, chunk := range []int{8, 32, 256, 1024} {
		chunk := chunk
		t.Run("chunk-"+itoa(chunk), func(t *testing.T) {
			var out bytes.Buffer
			w := redact.NewWriter(&out, salt, nil)
			for i := 0; i < len(input); i += chunk {
				end := i + chunk
				if end > len(input) {
					end = len(input)
				}
				if _, err := w.Write(input[i:end]); err != nil {
					t.Fatalf("Write at %d: %v", i, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			s := out.String()
			if strings.Contains(s, "BEGIN PRIVATE KEY") {
				t.Errorf("chunk=%d: PEM block leaked through", chunk)
			}
			if !strings.Contains(s, redact.MarkerPrefix) {
				t.Errorf("chunk=%d: no marker emitted; out=%q", chunk, s)
			}
			if !strings.HasPrefix(s, "warmup\n") {
				t.Errorf("chunk=%d: warmup line lost; out prefix=%q", chunk, s[:min(len(s), 40)])
			}
			if !strings.Contains(s, "tail\n") {
				t.Errorf("chunk=%d: tail line lost", chunk)
			}
		})
	}
}

func TestPEMAbortedFalseBeginPassesThrough(t *testing.T) {
	var salt [32]byte

	// 9 KiB of bytes after a -----BEGIN line, with NO matching END.
	// Should hit the 8 KiB abort threshold and flush untouched.
	junk := bytes.Repeat([]byte("Z"), 9*1024)
	input := []byte("noise\n-----BEGIN FAKE STUFF-----\n")
	input = append(input, junk...)
	input = append(input, []byte("\nstill-no-end-marker\n")...)

	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil)
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := out.String()
	// The false BEGIN bytes must appear verbatim.
	if !strings.Contains(s, "-----BEGIN FAKE STUFF-----") {
		t.Errorf("false BEGIN bytes should pass through, got %q (truncated)", s[:min(len(s), 80)])
	}
	if !strings.Contains(s, "still-no-end-marker") {
		t.Errorf("post-aborted tail lost")
	}
	if strings.Contains(s, redact.MarkerPrefix) {
		t.Errorf("false BEGIN should not produce a redaction marker; got %q", s)
	}
}

func TestPEMEndWithoutBeginIsPassthrough(t *testing.T) {
	var salt [32]byte
	input := []byte("orphan -----END PRIVATE KEY----- in the middle of logs\n")
	var out bytes.Buffer
	w := redact.NewWriter(&out, salt, nil)
	if _, err := w.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if string(out.Bytes()) != string(input) {
		t.Errorf("out = %q, want verbatim %q", out.String(), input)
	}
}

// itoa avoids strconv import bloat in this single use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
