package sign

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// ErrDenied is returned by Sign when signer replied with
// status="denied".
var ErrDenied = errors.New("sign: denied by operator")

// ErrTimeout is returned by Sign when signer replied with
// status="timeout" (or the Client.Timeout elapsed before a reply).
var ErrTimeout = errors.New("sign: approval timed out")

// ErrUnreachable is returned by Sign when the signer socket file
// is missing, refusing connections, or unreachable for some other
// transport-layer reason.
var ErrUnreachable = errors.New("sign: signer unreachable")

// ErrSignerPermission is returned by Sign when the signer socket file
// is present but the dial is refused with a permission error (EACCES /
// EPERM). The socket is mode 0660 owned by the sshgatesigner group; a
// shell/session that has not yet picked up that group membership hits
// this — the daemon is alive, the caller just lacks access. Distinct
// from ErrUnreachable so the user gets "log out and back in" guidance
// instead of "the daemon is dead".
var ErrSignerPermission = errors.New("sign: signer socket permission denied")

// Client is the signer socket client. SocketPath is the absolute
// path to the Unix socket; Timeout is the total per-request budget
// (dial + write + read). It must exceed the signer daemon's handler
// timeout so the daemon's authoritative verdict wins the race rather
// than the client abandoning early (which would strand an approved
// signature). Defaults to sigwire.ClientSignTimeout when zero.
type Client struct {
	SocketPath string
	Timeout    time.Duration
}

// CmdReq is a single command in a sign request. Server is the alias
// from the MCP registry (recorded in the audit log); Cmd is the
// literal shell command; TTLSec is the signature validity window in
// seconds (bounded by sigwire.MaxSigValidity on the daemon side).
type CmdReq struct {
	Server string
	Cmd    string
	TTLSec int64
}

// Signed is one signed result returned from signer on approval.
// Cmd is the original command (echoed back so the caller can match
// signatures to requests in order); Sig is the wire-encoded
// "SSHGATE_SIG:<sigB64>:<payloadB64>" string ready to prefix on the
// remote command line.
type Signed struct {
	Cmd string
	Sig string
}

// signRequestCmd is the JSON shape of a single command on the wire.
// It must mirror signer's signRequestCmd exactly.
type signRequestCmd struct {
	Server string `json:"server"`
	Cmd    string `json:"cmd"`
	TTLSec int64  `json:"ttl_seconds"`
}

type signRequest struct {
	Kind      string           `json:"kind"`
	RequestID string           `json:"request_id"`
	Commands  []signRequestCmd `json:"commands"`
}

type signResponseSig struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

type signResponse struct {
	RequestID  string            `json:"request_id"`
	Status     string            `json:"status"`
	Signatures []signResponseSig `json:"signatures,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// Sign sends a sign request for cmds and returns the signed wire
// strings on approval, or one of {ErrDenied, ErrTimeout,
// ErrUnreachable, ErrSignerPermission, fmt.Errorf("...")} on any other
// outcome.
//
// The request body is constructed locally (so the daemon never has
// to trust the wire-level shape from the MCP).
func (c *Client) Sign(ctx context.Context, requestID string, cmds []CmdReq) ([]Signed, error) {
	if c.SocketPath == "" {
		return nil, fmt.Errorf("sign: SocketPath is empty")
	}
	if requestID == "" {
		return nil, fmt.Errorf("sign: requestID is empty")
	}
	if len(cmds) == 0 {
		return nil, fmt.Errorf("sign: no commands")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = sigwire.ClientSignTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialWithCtx(dialCtx, c.SocketPath)
	if err != nil {
		return nil, classifyDialError(err)
	}
	defer conn.Close()

	// Apply the overall deadline to the connection.
	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	// Propagate ctx cancellation: close the conn so any blocked
	// Read/Write returns immediately. The watcher exits when the
	// connection closes (the deferred Close above).
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
		}
	}()

	body := signRequest{
		Kind:      "sign",
		RequestID: requestID,
		Commands:  make([]signRequestCmd, len(cmds)),
	}
	for i, cmd := range cmds {
		body.Commands[i] = signRequestCmd{Server: cmd.Server, Cmd: cmd.Cmd, TTLSec: cmd.TTLSec}
	}
	wire, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("sign: marshal: %w", err)
	}
	wire = append(wire, '\n')
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("sign: write: %w", err)
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil {
		// If ctx is the root cause, surface it verbatim so callers
		// can distinguish cancellation from a malformed reply.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("sign: %w", ctxErr)
		}
		return nil, fmt.Errorf("sign: read response: %w", err)
	}

	var resp signResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("sign: malformed response: %w", err)
	}
	if resp.RequestID != requestID {
		return nil, fmt.Errorf("sign: response request_id %q != %q", resp.RequestID, requestID)
	}

	switch resp.Status {
	case "approved":
		out := make([]Signed, len(resp.Signatures))
		for i, s := range resp.Signatures {
			out[i] = Signed{Cmd: s.Cmd, Sig: s.Sig}
		}
		return out, nil
	case "denied":
		return nil, ErrDenied
	case "timeout":
		return nil, ErrTimeout
	case "error":
		if resp.Error == "" {
			return nil, fmt.Errorf("sign: daemon reported error (no detail)")
		}
		return nil, fmt.Errorf("sign: daemon error: %s", resp.Error)
	default:
		return nil, fmt.Errorf("sign: unknown status %q", resp.Status)
	}
}

// dialWithCtx wraps net.Dialer.DialContext with a "unix" network so
// ctx cancellation aborts the dial.
//
// It is a package-level var (not a plain func) solely so in-package
// tests can substitute a dialer that returns a controlled net.Conn —
// e.g. one whose Write fails — to exercise transport error paths that
// are not deterministically reproducible against a real socket. Tests
// restore the original via defer. Production callers always use the
// default below; no public API or env var is involved, so production
// behaviour and attack surface are unchanged.
var dialWithCtx = func(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// classifyDialError maps a dial failure to a sentinel:
//   - ErrUnreachable when the socket file is missing or the kernel
//     returned "connection refused" (no daemon listening);
//   - ErrSignerPermission when the dial is refused with a permission
//     error (EACCES / EPERM) — the socket is present but the caller's
//     session is not yet in the sshgatesigner group.
//
// Any other error (e.g. ctx cancellation) is wrapped without a
// sentinel.
func classifyDialError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: socket missing: %v", ErrUnreachable, err)
	}
	// ENOENT on the socket path comes back as *net.OpError wrapping
	// *os.PathError on some kernels — check the message as a fallback.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, fs.ErrNotExist) {
		return fmt.Errorf("%w: socket missing: %v", ErrUnreachable, err)
	}
	// Permission denied on the 0660 socket: the daemon is alive but the
	// caller's session has not picked up the sshgatesigner group yet.
	// This must be detected BEFORE the *net.OpError catch-all below,
	// because an EACCES dial also surfaces as an *net.OpError — without
	// this branch it would be mis-reported as "unreachable" (a dead
	// daemon). We match both the portable fs.ErrPermission and an
	// unwrapped syscall.Errno of EACCES/EPERM.
	if errors.Is(err, fs.ErrPermission) || isPermErrno(err) {
		return fmt.Errorf("%w: %v", ErrSignerPermission, err)
	}
	// ECONNREFUSED indicates the socket file exists but no process
	// is listening — classify as unreachable.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("%w: dial: %v", ErrUnreachable, err)
	}
	return fmt.Errorf("sign: dial: %w", err)
}

// isPermErrno unwraps err to a syscall.Errno and reports whether it is
// EACCES or EPERM. fs.ErrPermission does not always match an EACCES
// that arrives wrapped in *net.OpError → *os.SyscallError, so we check
// the raw errno as a belt-and-braces fallback.
func isPermErrno(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EACCES || errno == syscall.EPERM
	}
	return false
}
