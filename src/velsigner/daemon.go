package velsigner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/karthikeyan5/sshgate/src/sigwire"
	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

// Daemon is the velsigner core. It owns the Ed25519 private key, the
// pluggable approval Backend, and the audit log. One Daemon instance
// serves an arbitrary number of concurrent connections; HandleSignRequest
// is safe for concurrent calls because:
//
//   - Key is read-only after construction.
//   - Backend.Request is documented as concurrency-safe.
//   - AuditLog.Write is mutex-protected.
//
// NowFunc is the injected clock used to compute the signed payload's
// TS / Exp fields. Tests inject a fixed clock; main wiring leaves it
// nil, in which case the daemon falls back to time.Now.
type Daemon struct {
	Key     ed25519.PrivateKey
	Backend backend.Backend
	Audit   *AuditLog
	NowFunc func() time.Time
}

// signRequest is the wire-format request sent over the Unix socket.
type signRequest struct {
	Kind      string           `json:"kind"`
	RequestID string           `json:"request_id"`
	Commands  []signRequestCmd `json:"commands"`
}

type signRequestCmd struct {
	Server  string `json:"server"`
	Cmd     string `json:"cmd"`
	TTLSec  int64  `json:"ttl_seconds"`
}

// signResponse is the wire-format response. Status is one of "approved",
// "denied", "timeout", "error". Signatures is populated only on
// approved; Error is populated only on error.
type signResponse struct {
	RequestID  string          `json:"request_id"`
	Status     string          `json:"status"`
	Signatures []signResponseSig `json:"signatures,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type signResponseSig struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// HandleSignRequest implements the one-request-per-connection protocol:
// read one JSON line, dispatch to the Backend, sign each command on
// approval, write one JSON line back. The function always writes a
// response and always records an audit event (the "error" status
// covers malformed input so operators can spot mischief at the
// protocol layer).
//
// The returned error is non-nil only on a hard I/O failure where no
// response was written (e.g. read EOF before any bytes, or a write
// failed mid-response). All protocol- and policy-level outcomes are
// represented in the JSON response and the audit log; they do not
// surface as a Go error.
func (d *Daemon) HandleSignRequest(ctx context.Context, conn io.ReadWriter) error {
	br := bufio.NewReader(conn)
	line, err := br.ReadBytes('\n')
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		// Read errored before we got any input — there's no request
		// ID we can pin the error to, so surface to the caller.
		return fmt.Errorf("read request: %w", err)
	}

	var req signRequest
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if jerr := dec.Decode(&req); jerr != nil {
		// Malformed: respond with "error", audit with "error".
		return d.respondError(conn, "", fmt.Sprintf("malformed request: %v", jerr))
	}
	if req.Kind != "sign" {
		return d.respondError(conn, req.RequestID, fmt.Sprintf("unsupported kind %q", req.Kind))
	}
	if req.RequestID == "" {
		return d.respondError(conn, "", "missing request_id")
	}
	if len(req.Commands) == 0 {
		return d.respondError(conn, req.RequestID, "no commands in request")
	}

	apReq := backend.ApprovalRequest{
		RequestID: req.RequestID,
		Submitted: d.now(),
		Commands:  make([]backend.CommandReq, len(req.Commands)),
	}
	for i, c := range req.Commands {
		if c.Cmd == "" {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].cmd is empty", i))
		}
		ttl := c.TTLSec
		if ttl <= 0 {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].ttl_seconds must be > 0", i))
		}
		if time.Duration(ttl)*time.Second > sigwire.MaxSigValidity {
			return d.respondError(conn, req.RequestID, fmt.Sprintf("commands[%d].ttl_seconds %d exceeds max %d", i, ttl, int64(sigwire.MaxSigValidity/time.Second)))
		}
		apReq.Commands[i] = backend.CommandReq{Server: c.Server, Cmd: c.Cmd, TTLSec: ttl}
	}

	resultCh, err := d.Backend.Request(ctx, apReq)
	if err != nil {
		return d.respondError(conn, req.RequestID, fmt.Sprintf("backend: %v", err))
	}

	var result backend.Result
	select {
	case r, ok := <-resultCh:
		if !ok {
			result = backend.Result{Status: backend.StatusTimeout}
		} else {
			result = r
		}
	case <-ctx.Done():
		result = backend.Result{Status: backend.StatusTimeout}
	}

	return d.respond(conn, req, result)
}

// respond produces the appropriate signed-or-not response based on the
// backend's verdict, writes it, and records the audit event. The
// response/audit pair is intentionally produced inside one function so
// the two cannot drift.
func (d *Daemon) respond(conn io.Writer, req signRequest, result backend.Result) error {
	resp := signResponse{RequestID: req.RequestID, Status: result.Status.String()}

	if result.Status == backend.StatusApproved {
		sigs, err := d.signAll(req.Commands)
		if err != nil {
			// A signing failure is a "we ran into the kernel's RNG
			// being broken" event — surface as error.
			return d.respondError(conn, req.RequestID, fmt.Sprintf("sign: %v", err))
		}
		resp.Signatures = sigs
	}

	if err := writeJSONLine(conn, resp); err != nil {
		// Audit-on-write-failure: the daemon signed and decided
		// "approved" but the MCP never received the signatures, so
		// from the operator's perspective the action was not
		// delivered. Record this asymmetry explicitly rather than
		// folding it into "approved" — daemon.md §5.1/§6 treat the
		// audit log as authoritative; a row that says "approved" must
		// imply "signatures left the daemon."
		auditStatus := result.Status.String()
		if result.Status == backend.StatusApproved {
			auditStatus = "approved-undelivered"
		}
		if auditErr := d.audit(req, auditStatus, result.ApprovedBy); auditErr != nil {
			// Surface the audit error to operators rather than dropping
			// it on the floor; the write-response error is the more
			// useful one for the caller, so it stays the return value.
			fmt.Fprintf(os.Stderr, "velsigner: audit write failed: %v\n", auditErr)
		}
		return fmt.Errorf("write response: %w", err)
	}
	return d.audit(req, result.Status.String(), result.ApprovedBy)
}

// respondError writes an {status: error} response with the given
// reason, records an audit event with status "error", and returns nil
// to the caller (the protocol level always writes a line; the caller
// only sees a non-nil error on hard I/O failure).
func (d *Daemon) respondError(conn io.Writer, reqID, reason string) error {
	resp := signResponse{RequestID: reqID, Status: "error", Error: reason}
	if err := writeJSONLine(conn, resp); err != nil {
		if auditErr := d.audit(signRequest{RequestID: reqID}, "error", ""); auditErr != nil {
			fmt.Fprintf(os.Stderr, "velsigner: audit write failed: %v\n", auditErr)
		}
		return fmt.Errorf("write error response: %w", err)
	}
	return d.audit(signRequest{RequestID: reqID}, "error", "")
}

// signAll signs each command in cmds with d.Key and returns the wire-
// encoded signed strings. Each signature uses an independent random
// nonce.
func (d *Daemon) signAll(cmds []signRequestCmd) ([]signResponseSig, error) {
	out := make([]signResponseSig, len(cmds))
	now := d.now().Unix()
	for i, c := range cmds {
		nonce, err := newNonce()
		if err != nil {
			return nil, fmt.Errorf("nonce: %w", err)
		}
		payload := sigwire.SigPayload{
			Cmd:   c.Cmd,
			TS:    now,
			Exp:   now + c.TTLSec,
			Nonce: nonce,
		}
		// Sign the exact bytes that DecodeSigned will reconstruct on
		// the verifier side; sigwire.EncodeSigned + verify.go both go
		// through json.Marshal of SigPayload, so the byte sequence is
		// stable.
		signedBytes, err := jsonMarshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		sig := ed25519.Sign(d.Key, signedBytes)
		wire, err := sigwire.EncodeSigned(sig, payload)
		if err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}
		out[i] = signResponseSig{Cmd: c.Cmd, Sig: wire}
	}
	return out, nil
}

// audit writes a single AuditEvent for req with status / approvedBy.
// d.Audit MUST be non-nil; the daemon contract is "every request
// produces an audit row." Tests that want a no-op sink should
// construct one via velsigner.NewMemAuditLog rather than passing
// nil — that keeps the audit code path on every test.
func (d *Daemon) audit(req signRequest, status, approvedBy string) error {
	cmds := make([]string, len(req.Commands))
	servers := make([]string, len(req.Commands))
	for i, c := range req.Commands {
		cmds[i] = c.Cmd
		servers[i] = c.Server
	}
	ev := AuditEvent{
		TS:         d.now().UTC(),
		RequestID:  req.RequestID,
		Status:     status,
		Commands:   cmds,
		Servers:    servers,
		ApprovedBy: approvedBy,
	}
	if err := d.Audit.Write(ev); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}

func (d *Daemon) now() time.Time {
	if d.NowFunc != nil {
		return d.NowFunc()
	}
	return time.Now()
}

// newNonce returns a 16-byte URL-safe-base64 random string. 128 bits
// of entropy is plenty for replay-protection within the 5-minute
// validity window.
func newNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// writeJSONLine marshals v and writes it followed by a newline.
func writeJSONLine(w io.Writer, v any) error {
	b, err := jsonMarshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// jsonMarshal is a thin alias kept so the daemon imports encoding/json
// in exactly one place, easing future swaps if needed.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
