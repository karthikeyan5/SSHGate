package backend

import (
	"context"
	"sync"
)

// MockBackend is a test fixture. Tests inject it into the daemon and
// then call Approve / Deny / Timeout (keyed by RequestID) to drive the
// outcome for a specific in-flight request. Each method is safe to call
// before OR after the daemon calls Request — early calls are buffered.
//
// MockBackend is intentionally simple: it does not validate the request
// payload, log, or rate-limit. Tests that need those properties write
// their own fixture.
//
// Construction: use the zero value or NewMockBackend (they are
// equivalent; NewMockBackend exists for readability at test sites).
type MockBackend struct {
	mu      sync.Mutex
	pending map[string]chan Result // pre-arranged outcomes or live channels
}

// NewMockBackend returns a ready-to-use MockBackend. The zero value
// works identically; this constructor is for callers who prefer the
// explicit form.
func NewMockBackend() *MockBackend {
	return &MockBackend{}
}

// Request implements Backend. If the test pre-arranged an outcome for
// req.RequestID (via Approve/Deny/Timeout before Request was called),
// Request returns that channel. Otherwise it registers a new pending
// channel that a later Approve/Deny/Timeout call will resolve. Each
// channel has capacity 1 so the resolver never blocks.
func (m *MockBackend) Request(_ context.Context, req ApprovalRequest) (<-chan Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.pending[req.RequestID]; ok {
		return ch, nil
	}
	ch := make(chan Result, 1)
	if m.pending == nil {
		m.pending = make(map[string]chan Result)
	}
	m.pending[req.RequestID] = ch
	return ch, nil
}

// Approve resolves reqID with StatusApproved. The optional approvedBy
// is recorded on the Result (mirrors how TelegramBackend populates the
// approver's name for the audit log). Unknown reqIDs are stored as
// pre-arranged outcomes for a later Request call.
func (m *MockBackend) Approve(reqID, approvedBy string) {
	m.resolve(reqID, Result{Status: StatusApproved, ApprovedBy: approvedBy})
}

// ApproveWithSignatures resolves reqID with StatusApproved AND a
// pre-canned list of remote-style signatures, simulating a
// HostedServerBackend approval. The daemon's response path will pass
// the signatures through verbatim (after validating length + per-entry
// Cmd match) instead of signing locally with d.Key.
func (m *MockBackend) ApproveWithSignatures(reqID string, sigs []SignedCmd, approvedBy string) {
	m.resolve(reqID, Result{Status: StatusApproved, ApprovedBy: approvedBy, Signatures: sigs})
}

// Deny resolves reqID with StatusDenied.
func (m *MockBackend) Deny(reqID string) {
	m.resolve(reqID, Result{Status: StatusDenied})
}

// Timeout resolves reqID with StatusTimeout.
func (m *MockBackend) Timeout(reqID string) {
	m.resolve(reqID, Result{Status: StatusTimeout})
}

// resolve sends r on the channel for reqID, creating one if necessary
// (so tests can pre-arrange an outcome before the daemon calls
// Request). A double-resolve is a test bug but is silently ignored
// (channel is buffered to 1, so the second send would deadlock — we
// use a non-blocking send to keep the test from hanging on a bug).
func (m *MockBackend) resolve(reqID string, r Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		m.pending = make(map[string]chan Result)
	}
	ch, ok := m.pending[reqID]
	if !ok {
		ch = make(chan Result, 1)
		m.pending[reqID] = ch
	}
	select {
	case ch <- r:
	default:
		// already resolved — silently drop; tests that care should
		// fail explicitly via their own assertions.
	}
}

// Compile-time interface check.
var _ Backend = (*MockBackend)(nil)
