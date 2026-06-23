package sigwire

import "time"

// The signer approval path crosses three processes — the MCP client, the
// signer daemon's connection handler, and the approval backend — each with
// its own timeout. They MUST be ordered
//
//	ClientSignTimeout > SignerHandlerTimeout > ApprovalWindow
//
// or a human approval that lands late becomes "approved-undelivered": the
// master key signs, but a deadline-expired connection (or an
// already-abandoned client) means the signature is never returned to the
// MCP. These consts are the single source of truth for that ordering; each
// outer bound is defined as the next inner bound plus slack, so the ordering
// holds by construction. Raise ApprovalWindow and the other two track it.
const (
	// ApprovalWindow is how long the Telegram backend waits for the human
	// tap before resolving the request as timed-out (the "Expires in ..."
	// the operator sees in the approval message). Independent of
	// MaxSigValidity, which bounds the signed token's lifetime once minted.
	ApprovalWindow time.Duration = 5 * time.Minute

	// ResponseWriteGrace is the budget RESERVED, out of the connection's
	// total lifetime, purely for writing the verdict line back to the MCP.
	// serveOne bounds the approval-WAIT to SignerHandlerTimeout -
	// ResponseWriteGrace and the daemon resets the connection's write
	// deadline to now()+ResponseWriteGrace immediately before each response
	// write. That guarantees a verdict resolving at the very end of the wait
	// window (a human's last-second DENY) still has a fresh, non-racing
	// budget to reach the client, instead of racing one shared absolute
	// deadline to zero (F1: verdict-undelivered). It is carved from the
	// existing 30s slack between ApprovalWindow and SignerHandlerTimeout, so
	// no timeout value changes and ApprovalWindow + ResponseWriteGrace still
	// fits inside SignerHandlerTimeout by construction.
	ResponseWriteGrace = 5 * time.Second

	// SignerHandlerTimeout bounds the whole signer connection — request
	// read + ApprovalWindow + response write — under serveOne's deadlines.
	// It must exceed ApprovalWindow + ResponseWriteGrace so a tap near the
	// limit still has both the wait budget to resolve AND the reserved grace
	// left to deliver the response (see timeouts_test.go's layering check).
	SignerHandlerTimeout = ApprovalWindow + 30*time.Second

	// ClientSignTimeout is the MCP-side total budget for one sign call
	// (dial + write + read). It must exceed SignerHandlerTimeout so the
	// daemon's authoritative verdict wins the race rather than the client
	// abandoning early (which would also strand an approved signature).
	ClientSignTimeout = SignerHandlerTimeout + 30*time.Second
)
