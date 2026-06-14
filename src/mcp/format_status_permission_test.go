package mcp

import (
	"strings"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestFormatStatusSummary_Permission pins that a permission-denied signer
// socket renders the actionable group/relaunch guidance and is NOT labelled
// "UNREACHABLE" (which would misdirect to debugging a healthy daemon).
func TestFormatStatusSummary_Permission(t *testing.T) {
	out := tools.StatusOutput{
		SignerSocket: tools.SignerStatus{
			Path:       "/run/sshgatesigner/sock",
			Configured: true,
			Permission: true,
		},
	}
	got := formatStatusSummary(out)
	for _, want := range []string{"sshgatesigner group", "relaunch", "NOT a dead daemon"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatStatusSummary() = %q\n  missing %q", got, want)
		}
	}
	if strings.Contains(got, "UNREACHABLE") {
		t.Errorf("permission case must not say UNREACHABLE; got %q", got)
	}
}
