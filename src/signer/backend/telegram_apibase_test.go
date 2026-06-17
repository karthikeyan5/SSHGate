package backend_test

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/signer/backend"
)

// TestAPIEndpointForBase covers the Bot-API base->endpoint conversion and
// its token-safety validation: the production hook for routing the signer
// approval bot through a reverse proxy when api.telegram.org is IP-blocked.
func TestAPIEndpointForBase(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		want    string
		wantErr bool
	}{
		{"empty -> default", "", "", false},
		{"whitespace -> default", "   ", "", false},
		{"https host", "https://tg.example.com", "https://tg.example.com/bot%s/%s", false},
		{"https trailing slash trimmed", "https://tg.example.com/", "https://tg.example.com/bot%s/%s", false},
		{"https with path prefix", "https://tg.example.com/proxy", "https://tg.example.com/proxy/bot%s/%s", false},
		{"http localhost ok", "http://localhost:8081", "http://localhost:8081/bot%s/%s", false},
		{"http 127.0.0.1 ok", "http://127.0.0.1:8081", "http://127.0.0.1:8081/bot%s/%s", false},
		{"http ::1 ok", "http://[::1]:8081", "http://[::1]:8081/bot%s/%s", false},
		{"http remote rejected", "http://tg.example.com", "", true},
		{"ftp scheme rejected", "ftp://tg.example.com", "", true},
		{"missing host rejected", "https://", "", true},
		{"garbage rejected", "://nope", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := backend.APIEndpointForBase(tt.base)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("APIEndpointForBase(%q) = %q, nil; want error", tt.base, got)
				}
				// The error must never embed a bot token — it only ever
				// sees the base URL. (Belt-and-suspenders: no token is in
				// scope here, but assert the base-only contract.)
				if strings.Contains(err.Error(), "bot%s") {
					t.Errorf("error leaked endpoint pattern: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("APIEndpointForBase(%q): unexpected error: %v", tt.base, err)
			}
			if got != tt.want {
				t.Errorf("APIEndpointForBase(%q) = %q; want %q", tt.base, got, tt.want)
			}
			// A non-empty endpoint must carry exactly the two %s slots
			// tgbotapi formats with (token, method).
			if got != "" && strings.Count(got, "%s") != 2 {
				t.Errorf("endpoint %q must carry exactly two %%s slots", got)
			}
		})
	}
}
