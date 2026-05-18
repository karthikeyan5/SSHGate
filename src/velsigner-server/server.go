package velsignerserver

import (
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
)

// Server is the hosted velsigner-server HTTP handler. It owns the route
// table, the bearer-token auth check, and the shared dependencies
// (logger, API key, store handle). A single Server instance serves an
// arbitrary number of concurrent requests; all fields are read-only
// after construction.
//
// Server itself implements http.Handler so callers can drop it into
// http.Server or httptest. cmd/velsigner-server wires the production
// server; handlers_test.go wires an httptest.Server in-process.
type Server struct {
	// APIKey is the single bearer token that gates /v1/* routes. v2.0
	// uses one shared key file (managed by ops); v2.1 introduces
	// per-client keys + WebAuthn/TOTP for the human approval surface.
	APIKey string

	// Store is the persistence layer. v2.0 ships a SQLite-backed
	// implementation (commit 2 of the scaffold series); v2.0 commit 1
	// runs against a nil Store and returns canned placeholders.
	Store Store

	// Logger receives one line per request (method, path, status,
	// duration). Defaults to log.Default() if nil.
	Logger *log.Logger

	mux *http.ServeMux
}

// Store is the persistence interface used by handlers. Defined here
// (rather than imported from the store package) so server.go has no
// dependency on a concrete backend. The store/ package's exported
// Store type embeds this minimal contract.
//
// Commit 2 of the scaffold series fills this in and wires it into
// handlers; in commit 1 the field is unused.
type Store interface{}

// NewServer builds a Server with routes registered. The Server's
// ServeHTTP method is safe for concurrent use.
//
// auth is the bearer token; passing the empty string is a programming
// error (the server would let every request through) and panics so the
// mistake surfaces during test setup, not in production traffic.
func NewServer(auth string, store Store, logger *log.Logger) *Server {
	if auth == "" {
		panic("velsignerserver: NewServer: APIKey is required")
	}
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{
		APIKey: auth,
		Store:  store,
		Logger: logger,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

// routes registers the v2.0 route table. Go 1.22+ ServeMux pattern
// syntax is used for the {request_id} wildcard on /v1/poll/.
func (s *Server) routes() {
	// Public route: liveness check. No auth — load balancers and
	// monitoring need to hit this without a token.
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// Bearer-token-gated routes. We wrap each handler in withAuth so
	// the auth check sits next to the route registration and cannot
	// drift across handler files.
	s.mux.Handle("POST /v1/sign", s.withAuth(http.HandlerFunc(s.handleSign)))
	s.mux.Handle("GET /v1/poll/{request_id}", s.withAuth(http.HandlerFunc(s.handlePoll)))
	s.mux.Handle("GET /v1/audit", s.withAuth(http.HandlerFunc(s.handleAudit)))
}

// ServeHTTP makes Server an http.Handler. The wrapping logRequest
// produces one line per request — minimal observability for v2.0 (full
// metrics + tracing land in v2.1).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logRequest(w, r, s.mux.ServeHTTP)
}

// withAuth wraps next with a bearer-token check. On a missing or
// mismatching token it writes 401 with a JSON {"error":"unauthorized"}
// body. The token comparison uses crypto/subtle to defeat timing
// attacks; the difference is negligible at v2.0's QPS but it's the
// right reflex.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(hdr, prefix) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		got := hdr[len(prefix):]
		// Equal-length compare via subtle: if lengths differ, fail
		// without touching the token bytes.
		if len(got) != len(s.APIKey) || subtle.ConstantTimeCompare([]byte(got), []byte(s.APIKey)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
