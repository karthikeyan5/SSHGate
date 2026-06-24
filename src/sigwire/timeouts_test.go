package sigwire

import "testing"

// TestTimeoutLayering pins the deadline-layering invariant the signer
// connection lifecycle depends on. The wait budget (SignerHandlerTimeout -
// ResponseWriteGrace) must still leave room for a FULL ApprovalWindow, and
// the whole connection must stay strictly inside ClientSignTimeout so the
// daemon's authoritative verdict wins the race:
//
//	ApprovalWindow + ResponseWriteGrace <= SignerHandlerTimeout < ClientSignTimeout
//
// The "<=" on the inner bound is what guarantees a verdict that resolves at
// the very end of the approval window still has the reserved grace left to
// WRITE the response (F1: a near-deadline deny must remain deliverable).
func TestTimeoutLayering(t *testing.T) {
	if ResponseWriteGrace <= 0 {
		t.Fatalf("ResponseWriteGrace = %v; must be > 0 (a verdict write needs reserved budget)", ResponseWriteGrace)
	}
	if ApprovalWindow+ResponseWriteGrace > SignerHandlerTimeout {
		t.Errorf("ApprovalWindow(%v) + ResponseWriteGrace(%v) = %v > SignerHandlerTimeout(%v); the write grace would eat into the approval window",
			ApprovalWindow, ResponseWriteGrace, ApprovalWindow+ResponseWriteGrace, SignerHandlerTimeout)
	}
	if SignerHandlerTimeout >= ClientSignTimeout {
		t.Errorf("SignerHandlerTimeout(%v) >= ClientSignTimeout(%v); the client must outlive the daemon handler so the verdict wins the race",
			SignerHandlerTimeout, ClientSignTimeout)
	}
	// The wait budget the daemon actually applies must still exceed the full
	// approval window — otherwise a human who taps at the last second is cut
	// short before the verdict resolves.
	waitBudget := SignerHandlerTimeout - ResponseWriteGrace
	if waitBudget < ApprovalWindow {
		t.Errorf("waitBudget(%v) < ApprovalWindow(%v); a full-window approval would be cut short", waitBudget, ApprovalWindow)
	}
}
