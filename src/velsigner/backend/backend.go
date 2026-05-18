package backend

import (
	"context"
	"time"
)

// ApprovalRequest is the unit of work submitted to a Backend. The
// RequestID is opaque to the backend — the daemon generates it and uses
// it both to correlate the result and as the audit-log key. Submitted is
// the wall-clock timestamp at which the daemon received the request from
// the MCP; backends include it in their UI when relevant.
type ApprovalRequest struct {
	RequestID string
	Commands  []CommandReq
	Submitted time.Time
}

// CommandReq is a single command awaiting approval. Server is the human-
// readable alias from the MCP's registry (e.g. "prod-db"); Cmd is the
// literal shell command line; TTLSec is the spec's signature validity
// window (`exp - ts`), bounded by sigwire.MaxSigValidity (5 minutes).
type CommandReq struct {
	Server string
	Cmd    string
	TTLSec int64
}

// ResultStatus is the outcome of an ApprovalRequest. The zero value is
// StatusApproved deliberately: this is a "secure by default" inversion
// avoided here — callers MUST check the explicit value, never rely on
// the zero. (We accept the zero-is-approved risk because StubBackend
// returns StatusDenied as a constant and the daemon checks the status
// explicitly before signing.)
type ResultStatus int

const (
	// StatusApproved means the human (or the stub policy) authorised
	// signing every command in the request.
	StatusApproved ResultStatus = iota
	// StatusDenied means the human explicitly rejected the request.
	StatusDenied
	// StatusTimeout means no decision arrived within the backend's
	// implementation-defined wait window.
	StatusTimeout
)

// String returns the lowercase wire-format spelling of the status:
// "approved", "denied", "timeout". Used by the audit log and the
// socket response encoder; keep it stable.
func (s ResultStatus) String() string {
	switch s {
	case StatusApproved:
		return "approved"
	case StatusDenied:
		return "denied"
	case StatusTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// Result is the resolution of a single ApprovalRequest. ApprovedBy is
// populated when the backend can identify the approver (e.g. Telegram's
// from.id) — used purely for the audit log. Stub and mock leave it
// empty.
type Result struct {
	Status     ResultStatus
	ApprovedBy string
}

// Backend abstracts the approval-channel mechanism (Telegram in v1.2,
// hosted HTTPS server in v2, plus the test-only Stub and Mock).
//
// Implementations MUST be safe for concurrent calls: the daemon serves
// multiple sign requests in parallel.
//
// Request submits the approval request and returns a channel that will
// yield exactly one Result. On a hard error during submission, Request
// returns the error and no channel; once a channel has been returned,
// the daemon's only contract with the caller is to read one Result from
// it. Implementations decide their own timeout policy independent of
// ctx; they SHOULD honour ctx cancellation by yielding StatusTimeout (or
// a more specific status if defined later).
type Backend interface {
	Request(ctx context.Context, req ApprovalRequest) (<-chan Result, error)
}
