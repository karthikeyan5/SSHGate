// Package backend defines the abstract approval-channel interface used
// by the signer daemon, plus the concrete implementations the daemon
// can be wired to.
//
// The Backend interface is the v1→v2 swap point: v1 ships StubBackend
// (always denies, used by the phase-1 end-to-end test that proves the
// signing loop without a human in the loop) and — landing in task 2.1 —
// TelegramBackend, which posts the request to Karthi's DM and waits for
// an inline-keyboard tap. v2's HostedServerBackend implements the same
// interface against a remote HTTPS approval service.
//
// MockBackend is a test fixture: tests inject it into the daemon and
// drive specific outcomes (Approve / Deny / Timeout) by request ID.
//
// Implementations MUST be safe for concurrent calls — the daemon serves
// multiple sign requests in parallel and a backend that serialises
// internally is acceptable, but one that races on shared state is not.
package backend
