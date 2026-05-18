package velsignerserver

import (
	"encoding/json"
	"net/http"
	"time"
)

// signRequest is the body shape of POST /v1/sign. It mirrors the
// design spec §"v2 vision → Wire protocol" exactly so the
// HostedServerBackend client (commit 3 of the scaffold series) can
// encode/decode the same struct on both ends.
//
// Context is intentionally a free-form map for v2.0; v2.1 will define
// a typed shape (claude_session_id, user_intent, etc.) once the LLM
// explainer is wired up on the server side.
type signRequest struct {
	ClientID string                 `json:"client_id"`
	Commands []signRequestCmd       `json:"commands"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

// signRequestCmd is one queued command. Field names match the v1 Unix-
// socket wire format (server, cmd, ttl_seconds) so a future migration
// from velsigner's local socket to /v1/sign needs only a transport
// swap, not a payload rewrite.
type signRequestCmd struct {
	Server     string `json:"server"`
	Cmd        string `json:"cmd"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// signAcceptedResponse is the 202 Accepted body returned from POST
// /v1/sign. Clients then poll poll_url until a resolution arrives.
type signAcceptedResponse struct {
	RequestID string `json:"request_id"`
	PollURL   string `json:"poll_url"`
}

// pollResponse is the body of GET /v1/poll/{id}. status is one of
// "pending" | "approved" | "denied" | "timeout" | "error".
// signatures is populated only on approved; approved_by/at are
// populated on approved or denied.
type pollResponse struct {
	RequestID    string       `json:"request_id"`
	Status       string       `json:"status"`
	Signatures   []signedCmd  `json:"signatures,omitempty"`
	ApprovedBy   string       `json:"approved_by_user,omitempty"`
	ApprovedAt   *time.Time   `json:"approved_at,omitempty"`
	Error        string       `json:"error,omitempty"`
}

// signedCmd is a single signed command in the poll response. The
// shape matches v1's velsigner socket response so the velgate
// verification path needs no changes.
type signedCmd struct {
	Cmd string `json:"cmd"`
	Sig string `json:"sig"`
}

// auditResponse is the body of GET /v1/audit. v2.0 returns an empty
// list; v2.1 wires it to the SQLite store's RecentAudit query.
type auditResponse struct {
	Entries []auditEntry `json:"entries"`
}

// auditEntry mirrors the v1 audit-log row shape: one decision per
// row, with the original commands and the approving user (if any).
type auditEntry struct {
	RequestID  string    `json:"request_id"`
	Status     string    `json:"status"`
	ClientID   string    `json:"client_id"`
	Commands   []string  `json:"commands"`
	ApprovedBy string    `json:"approved_by_user,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// handleHealthz returns 200 with a one-line "ok" body. Liveness only;
// readiness (DB-up, key-loaded) is a v2.1 concern.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// handleSign accepts a /v1/sign request. v2.0 SCAFFOLD: parse the body,
// generate a request_id, return 202 with the poll URL. The actual
// store insert + approval workflow lands in scaffold commit 2.
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return
	}
	if req.ClientID == "" {
		writeJSONError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if len(req.Commands) == 0 {
		writeJSONError(w, http.StatusBadRequest, "commands must be non-empty")
		return
	}
	for i, c := range req.Commands {
		if c.Cmd == "" {
			writeJSONError(w, http.StatusBadRequest, "commands["+itoa(i)+"].cmd is empty")
			return
		}
		if c.TTLSeconds <= 0 {
			writeJSONError(w, http.StatusBadRequest, "commands["+itoa(i)+"].ttl_seconds must be > 0")
			return
		}
	}

	// Placeholder: emit a stable-looking request_id so test clients
	// can assert the shape. Scaffold commit 2 replaces this with a
	// store-inserted row.
	rid := generateRequestID()
	writeJSON(w, http.StatusAccepted, signAcceptedResponse{
		RequestID: rid,
		PollURL:   "/v1/poll/" + rid,
	})
}

// handlePoll long-polls for a resolution. v2.0 SCAFFOLD: returns 200
// with {status: "timeout"} after a short delay. Scaffold commit 2
// wires this to Store.WaitForResolution against the SQLite store.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("request_id")
	if rid == "" {
		writeJSONError(w, http.StatusBadRequest, "missing request_id in path")
		return
	}
	// v2.0 scaffold: no real backing store yet. We honour ctx.Done()
	// so a client disconnect doesn't pin a goroutine; otherwise we
	// return "timeout" after a brief synthetic wait. The 100ms wait
	// makes long-poll behaviour visible in tests without slowing the
	// suite.
	select {
	case <-time.After(100 * time.Millisecond):
	case <-r.Context().Done():
		// Client gave up; nothing to write — context is cancelled.
		return
	}
	writeJSON(w, http.StatusOK, pollResponse{
		RequestID: rid,
		Status:    "timeout",
	})
}

// handleAudit returns the recent audit list. v2.0 SCAFFOLD: returns
// an empty list. Scaffold commit 2 wires Store.RecentAudit.
func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, auditResponse{Entries: []auditEntry{}})
}

// writeJSON marshals v and writes it with Content-Type set. Errors
// from the underlying Write are intentionally swallowed: by the time
// we're encoding, the response status has been committed and there
// is no useful recovery.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError is the common error-response renderer. We use a
// stable {error: "..."} shape so clients can pattern-match without
// regex'ing free-form bodies.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// itoa is a tiny strconv.Itoa alias kept inline so handlers.go has
// one std-lib import set. (encoding/json + net/http + time only.)
func itoa(i int) string {
	// Minimal positive-int formatter; the only callers pass small
	// indexes (commands[i]).
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
