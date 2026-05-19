package tools

import (
	"strings"
	"testing"
)

// TestValidateHost covers the RFC1123-DNS-ish + IP-literal acceptance
// surface of the host validator added per code-review Mi9. It does not
// dial — purely string-shape validation at the input boundary.
func TestValidateHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// Valid forms
		{"simple dns", "example.com", false},
		{"single label", "host", false},
		{"subdomain", "db1.prod.example.com", false},
		{"hyphen interior", "foo-bar.example.com", false},
		{"digits ok", "host01.example.com", false},
		{"ipv4", "192.168.1.1", false},
		{"ipv4 zero pad ok", "10.0.0.1", false},
		{"ipv6 literal", "2001:db8::1", false},
		{"ipv6 loopback", "::1", false},
		{"leading/trailing space trimmed", "  example.com  ", false},

		// Invalid forms
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"trailing newline (audit-log poisoning)", "example.com\necho hacked", true},
		{"embedded space", "evil .com", true},
		{"shell metachar pipe", "a|b", true},
		{"shell metachar semicolon", "a;b", true},
		{"shell metachar backtick", "a`b`", true},
		{"unicode confusable", "exаmple.com", true}, // cyrillic a
		{"label starts with hyphen", "-bad.example.com", true},
		{"label ends with hyphen", "bad-.example.com", true},
		{"trailing dot", "example.com.", true},
		{"leading dot", ".example.com", true},
		{"underscore (sometimes accepted, we reject)", "host_name.example.com", true},
		{"over 253 chars", strings.Repeat("a", 254), true},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := validateHost(c.host)
			if c.wantErr && err == nil {
				t.Errorf("validateHost(%q) = nil; want error", c.host)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateHost(%q) = %v; want nil", c.host, err)
			}
		})
	}
}

// TestValidateUser covers POSIX-username shape validation per Mi9.
func TestValidateUser(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		user    string
		wantErr bool
	}{
		// Valid
		{"plain", "ubuntu", false},
		{"underscore start", "_svc", false},
		{"digits after start", "user01", false},
		{"hyphen interior", "deploy-bot", false},
		{"underscore interior", "deploy_bot", false},
		{"max 32 chars", strings.Repeat("a", 32), false},

		// Invalid
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"starts with digit", "1user", true},
		{"starts with hyphen", "-user", true},
		{"contains uppercase", "Ubuntu", true},
		{"contains space", "two words", true},
		{"contains dot", "foo.bar", true},
		{"contains shell metachar", "user;rm -rf", true},
		{"unicode", "userя", true},
		{"33 chars (over cap)", strings.Repeat("a", 33), true},
		{"trailing newline", "user\necho", true},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := validateUser(c.user)
			if c.wantErr && err == nil {
				t.Errorf("validateUser(%q) = nil; want error", c.user)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateUser(%q) = %v; want nil", c.user, err)
			}
		})
	}
}
