// Package store is the persistence layer for signer-server. It owns
// the SQLite schema, the wire-shape of stored sign requests, and the
// long-poll primitive that handler /v1/poll/{id} blocks on.
//
// v2.0 scaffold exposes one concrete implementation (sqlite.go); v2.1
// may add a Postgres backend for multi-instance deployments. The
// Store interface is the abstraction boundary.
//
// Concurrency model: one *DB instance backs an arbitrary number of
// concurrent callers. modernc.org/sqlite serialises writes internally
// (SQLite WAL mode), so callers don't need their own mutex.
package store

import (
	"context"
	"errors"
	"time"
)

// Status is one of the spec's resolution states. The wire form (the
// JSON string in poll responses and audit rows) is identical to the
// String() output below so the handlers and the store never need a
// mapping table.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusTimeout  Status = "timeout"
	StatusError    Status = "error"
)

// IsValid reports whether s is one of the recognised values. Used at
// the store boundary so a typo in a future caller surfaces as a
// validation error rather than silent data corruption.
func (s Status) IsValid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusDenied, StatusTimeout, StatusError:
		return true
	}
	return false
}

// Request is one row in the requests table. The wire-shape it implies
// (commands as JSON, signatures as JSON, status as a string) matches
// the schema in sqlite.go.
//
// Commands and Signatures are stored as raw []byte (JSON) rather than
// typed slices because the audit consumers (and the eventual web UI)
// only want to render them as opaque blobs; the store does not need
// to crack them open.
type Request struct {
	RequestID   string
	Status      Status
	ClientID    string
	Commands    []byte // JSON-encoded []signRequestCmd from the handlers package
	Signatures  []byte // JSON-encoded []signedCmd; populated on approval
	CreatedAt   time.Time
	ResolvedAt  *time.Time
	ApprovedBy  string
}

// Store is the persistence interface. All methods MUST be safe for
// concurrent calls.
//
// WaitForResolution is the long-poll primitive: it blocks until the
// stored Status transitions to a non-pending value or until timeout
// fires, whichever happens first. v2.0 ships a polling implementation
// (sleep 100ms, re-read); v2.1 should upgrade to per-request channel
// wakeups once write QPS justifies it.
type Store interface {
	// Insert writes r as a new pending row. RequestID is the primary
	// key; a duplicate ID is a programming error and returns
	// ErrDuplicateID.
	Insert(ctx context.Context, r *Request) error

	// GetByID returns the row with the given ID. ErrNotFound if no
	// row exists.
	GetByID(ctx context.Context, id string) (*Request, error)

	// UpdateStatus transitions a row from pending to a terminal
	// status. signatures may be nil for non-approved transitions.
	// approvedBy is the human identifier (or "" if not applicable).
	// Calling UpdateStatus on an already-resolved row is a no-op
	// (idempotent — useful in the WaitForResolution timeout path).
	UpdateStatus(ctx context.Context, id string, status Status, signatures []byte, approvedBy string) error

	// WaitForResolution blocks until the row's status is non-pending
	// or timeout fires. Returns the final row (with whatever Status
	// it has at return time, including "pending" if timeout won).
	// On timeout the row is NOT mutated — callers that want to mark
	// the row as timed-out must call UpdateStatus themselves.
	WaitForResolution(ctx context.Context, id string, timeout time.Duration) (*Request, error)

	// ListPending returns all rows currently in StatusPending.
	// Ordered by created_at ascending so the oldest unresolved
	// request surfaces first.
	ListPending(ctx context.Context) ([]*Request, error)

	// RecentAudit returns up to limit most-recent rows regardless of
	// status, ordered by created_at descending. Limit <= 0 is
	// treated as 100.
	RecentAudit(ctx context.Context, limit int) ([]*Request, error)

	// Close releases the underlying database handle. Idempotent.
	Close() error
}

// ErrNotFound is returned by GetByID and WaitForResolution when the
// requested row does not exist. Callers should errors.Is-check
// against this sentinel.
var ErrNotFound = errors.New("store: request not found")

// ErrDuplicateID is returned by Insert when the RequestID collides
// with an existing row.
var ErrDuplicateID = errors.New("store: duplicate request_id")
