package redact_test

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

func TestMarkerKey(t *testing.T) {
	var salt [32]byte
	copy(salt[:], "salt-for-deterministic-tests----")

	t.Run("deterministic within same salt", func(t *testing.T) {
		k1 := redact.MarkerKey(salt, []byte("AKIA1234567890ABCDEF"))
		k2 := redact.MarkerKey(salt, []byte("AKIA1234567890ABCDEF"))
		if k1 != k2 {
			t.Errorf("same (salt, secret) produced different keys: %q vs %q", k1, k2)
		}
	})

	t.Run("8 hex characters lowercase", func(t *testing.T) {
		k := redact.MarkerKey(salt, []byte("secret"))
		if len(k) != 8 {
			t.Errorf("len = %d, want 8: %q", len(k), k)
		}
		for _, c := range k {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("non-hex char %q in key %q", c, k)
			}
		}
	})

	t.Run("different secrets produce different keys", func(t *testing.T) {
		k1 := redact.MarkerKey(salt, []byte("secret-A"))
		k2 := redact.MarkerKey(salt, []byte("secret-B"))
		if k1 == k2 {
			t.Errorf("different secrets collided: both produced %q", k1)
		}
	})

	t.Run("different salts produce different keys (freshness)", func(t *testing.T) {
		var s2 [32]byte
		if _, err := rand.Read(s2[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		k1 := redact.MarkerKey(salt, []byte("same-secret-bytes"))
		k2 := redact.MarkerKey(s2, []byte("same-secret-bytes"))
		if k1 == k2 {
			t.Fatalf("freshness violated: same secret under different salts produced same key %q", k1)
		}
	})

	t.Run("marker contains key, no plaintext leakage", func(t *testing.T) {
		secret := []byte("super-secret-token-do-not-leak")
		marker := redact.FormatMarker(salt, secret)
		if !strings.HasPrefix(marker, redact.MarkerPrefix) {
			t.Errorf("marker = %q, want prefix %q", marker, redact.MarkerPrefix)
		}
		if !strings.HasSuffix(marker, redact.MarkerSuffix) {
			t.Errorf("marker = %q, want suffix %q", marker, redact.MarkerSuffix)
		}
		if strings.Contains(marker, string(secret)) {
			t.Errorf("marker leaked secret bytes: %q", marker)
		}
	})
}

func TestFormatFileMarker(t *testing.T) {
	got := redact.FormatFileMarker("/etc/shadow", 0o600, [4]byte{0xde, 0xad, 0xbe, 0xef})
	want := "[SSHGATE_REDACTED_FILE path=/etc/shadow mode=0600 sha256=deadbeef]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
