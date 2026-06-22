package tools_test

import (
	"context"
	"testing"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestRunBatch_NeverReveals pins the NO-BULK-REVEAL invariant: run_batch has
// no reveal input field, and every CmdReq it sends to the signer is
// reveal=false (with an empty reason). Bulk reveal is forbidden by design — a
// single scary Telegram tap must never authorise un-redacted output for many
// commands at once. If a reveal field is ever added to the batch input or the
// batch sign path, this test must fail.
func TestRunBatch_NeverReveals(t *testing.T) {
	t.Parallel()
	r := newRegistryForBatch(t)
	writes := []string{"systemctl restart nginx", "rm /tmp/a"}
	sign := &batchSign{signed: makeSignedFor(t, writes)}
	ssh := &batchSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RunBatch(context.Background(), tools.RunBatchInput{
		Alias:    "h1",
		Commands: writes,
	})
	if err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	if sign.calls != 1 {
		t.Fatalf("sign.calls = %d; want 1", sign.calls)
	}
	if len(sign.gotCmds) != 2 {
		t.Fatalf("got %d sign cmds; want 2", len(sign.gotCmds))
	}
	for i, c := range sign.gotCmds {
		if c.Reveal {
			t.Errorf("batch CmdReq[%d].Reveal = true; bulk reveal must be impossible", i)
		}
		if c.Reason != "" {
			t.Errorf("batch CmdReq[%d].Reason = %q; want empty (batch carries no reveal reason)", i, c.Reason)
		}
	}
}
