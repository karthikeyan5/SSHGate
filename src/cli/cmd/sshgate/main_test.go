package main

import "testing"

func TestParseUserHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantUser string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"deploy@host.example.com", "deploy", "host.example.com", 22, false},
		{"deploy@host.example.com:2222", "deploy", "host.example.com", 2222, false},
		{"u@10.0.0.5", "u", "10.0.0.5", 22, false},
		{"u@10.0.0.5:22", "u", "10.0.0.5", 22, false},
		// Errors.
		{"host.example.com", "", "", 0, true}, // no user@
		{"@host", "", "", 0, true},            // empty user
		{"u@", "", "", 0, true},               // empty host
		{"u@host:0", "", "", 0, true},         // port out of range
		{"u@host:99999", "", "", 0, true},     // port out of range
		{"u@host:abc", "", "", 0, true},       // non-numeric port
		{"", "", "", 0, true},                 // empty
	}
	for _, c := range cases {
		user, host, port, err := parseUserHostPort(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseUserHostPort(%q) = (%q,%q,%d,nil); want error", c.in, user, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUserHostPort(%q) error = %v; want nil", c.in, err)
			continue
		}
		if user != c.wantUser || host != c.wantHost || port != c.wantPort {
			t.Errorf("parseUserHostPort(%q) = (%q,%q,%d); want (%q,%q,%d)",
				c.in, user, host, port, c.wantUser, c.wantHost, c.wantPort)
		}
	}
}

// TestRunDispatch covers the top-level subcommand routing for the no-arg and
// unknown-subcommand error paths (exit code 2) and help (exit code 0).
func TestRunDispatch(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Errorf("run(nil) = %d; want 2 (usage error)", code)
	}
	if code := run([]string{"bogus"}); code != 2 {
		t.Errorf("run(bogus) = %d; want 2 (unknown subcommand)", code)
	}
	if code := run([]string{"help"}); code != 0 {
		t.Errorf("run(help) = %d; want 0", code)
	}
	// `add` with the wrong number of positionals is a usage error.
	if code := run([]string{"add", "onlyalias"}); code != 2 {
		t.Errorf("run(add onlyalias) = %d; want 2 (usage error)", code)
	}
	if code := run([]string{"add", "alias", "u@host", "--bogus"}); code != 2 {
		t.Errorf("run(add ... --bogus) = %d; want 2 (unknown flag)", code)
	}
}
