package backend_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

// fakeServer implements the v2 wire protocol just enough to test the
// HostedServerBackend client. Tests control its state via the
// approveAfter and denyAfter fields; the handler returns canned
// JSON bodies matching the server-side handlers' shapes.
type fakeServer struct {
	mu sync.Mutex
	// reqID is the ID returned by /v1/sign. Reset per test.
	reqID string
	// pollAction governs how /v1/poll responds. One of:
	//   "pending"   → loops forever returning "timeout" (server's
	//                 poll window elapsed; client should retry)
	//   "approved"  → next poll returns approved + signatures
	//   "denied"    → next poll returns denied
	//   "error"     → next poll returns error
	pollAction string
	// pollDelay is applied before each /v1/poll response so tests
	// can exercise the long-poll path without flakes.
	pollDelay time.Duration
	// signatureCmd populates the "cmd" field of the approved
	// signature so tests can assert end-to-end payload flow.
	signatureCmd string
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/sign" && r.Method == http.MethodPost:
		f.mu.Lock()
		rid := f.reqID
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"request_id": rid,
			"poll_url":   "/v1/poll/" + rid,
		})
	case strings.HasPrefix(r.URL.Path, "/v1/poll/") && r.Method == http.MethodGet:
		f.mu.Lock()
		action := f.pollAction
		delay := f.pollDelay
		sigCmd := f.signatureCmd
		f.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		switch action {
		case "approved":
			now := time.Now().UTC()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id":       strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":           "approved",
				"signatures":       []map[string]string{{"cmd": sigCmd, "sig": "VELGATE_SIG:fake"}},
				"approved_by_user": "karthi",
				"approved_at":      now,
			})
		case "denied":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id":       strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":           "denied",
				"approved_by_user": "karthi",
			})
		case "error":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":     "error",
				"error":      "boom",
			})
		default: // "pending" or unset
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id": strings.TrimPrefix(r.URL.Path, "/v1/poll/"),
				"status":     "timeout",
			})
		}
	default:
		http.NotFound(w, r)
	}
}

// fakeWithAuth wraps fakeServer.handle with a bearer-token check so
// tests can assert that the client always sends Authorization.
func (f *fakeServer) handleWithAuth(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.handle(w, r)
	})
}

func newFakeServerBackend(t *testing.T, fs *fakeServer) (*backend.HostedServerBackend, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(fs.handleWithAuth("test-key"))
	t.Cleanup(ts.Close)
	return &backend.HostedServerBackend{
		BaseURL:    ts.URL,
		APIKey:     "test-key",
		ClientID:   "test-laptop",
		HTTPClient: ts.Client(),
		PollWait:   100 * time.Millisecond,
		Timeout:    3 * time.Second,
	}, ts
}

func TestHostedServerBackend_Approved(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_abc", pollAction: "approved", signatureCmd: "echo hi"}
	hb, _ := newFakeServerBackend(t, fs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := hb.Request(ctx, backend.ApprovalRequest{
		RequestID: "ignored-by-server-but-required-by-daemon",
		Commands:  []backend.CommandReq{{Server: "prod", Cmd: "echo hi", TTLSec: 60}},
		Submitted: time.Now(),
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res, ok := <-ch:
		if !ok {
			t.Fatal("channel closed without a result")
		}
		if res.Status != backend.StatusApproved {
			t.Errorf("status = %v; want StatusApproved", res.Status)
		}
		if res.ApprovedBy != "karthi" {
			t.Errorf("ApprovedBy = %q; want karthi", res.ApprovedBy)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Request did not resolve within 3s")
	}
}

func TestHostedServerBackend_Denied(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_deny", pollAction: "denied"}
	hb, _ := newFakeServerBackend(t, fs)

	ctx := context.Background()
	ch, err := hb.Request(ctx, backend.ApprovalRequest{
		RequestID: "r1",
		Commands:  []backend.CommandReq{{Server: "p", Cmd: "rm -rf /", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res := <-ch:
		if res.Status != backend.StatusDenied {
			t.Errorf("status = %v; want StatusDenied", res.Status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Request did not resolve within 3s")
	}
}

func TestHostedServerBackend_TimeoutBudget(t *testing.T) {
	t.Parallel()
	// pollAction "" → server always returns "timeout"; client
	// should keep re-polling until its Timeout fires.
	fs := &fakeServer{reqID: "r_to"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.PollWait = 50 * time.Millisecond
	hb.Timeout = 250 * time.Millisecond

	start := time.Now()
	ch, err := hb.Request(context.Background(), backend.ApprovalRequest{
		RequestID: "r1",
		Commands:  []backend.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case res := <-ch:
		if res.Status != backend.StatusTimeout {
			t.Errorf("status = %v; want StatusTimeout", res.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Request did not time out")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Errorf("elapsed = %v; want >= ~250ms (Timeout budget)", elapsed)
	}
}

func TestHostedServerBackend_CtxCancel(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_cancel"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.PollWait = 100 * time.Millisecond
	hb.Timeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := hb.Request(ctx, backend.ApprovalRequest{
		RequestID: "r1",
		Commands:  []backend.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	// Cancel after a brief moment; the long-poll should yield
	// StatusTimeout quickly.
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	select {
	case res := <-ch:
		if res.Status != backend.StatusTimeout {
			t.Errorf("status = %v; want StatusTimeout on ctx cancel", res.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx cancel did not propagate")
	}
}

func TestHostedServerBackend_RejectsBadAuth(t *testing.T) {
	t.Parallel()
	fs := &fakeServer{reqID: "r_unauth"}
	hb, _ := newFakeServerBackend(t, fs)
	hb.APIKey = "wrong-token"

	_, err := hb.Request(context.Background(), backend.ApprovalRequest{
		RequestID: "r1",
		Commands:  []backend.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
	})
	if err == nil {
		t.Fatal("Request should fail with 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v; want a 401 mention", err)
	}
}

func TestHostedServerBackend_ValidatesConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hb   backend.HostedServerBackend
	}{
		{"no BaseURL", backend.HostedServerBackend{APIKey: "k", ClientID: "c"}},
		{"no APIKey", backend.HostedServerBackend{BaseURL: "http://x", ClientID: "c"}},
		{"no ClientID", backend.HostedServerBackend{BaseURL: "http://x", APIKey: "k"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.hb.Request(context.Background(), backend.ApprovalRequest{
				RequestID: "r",
				Commands:  []backend.CommandReq{{Server: "p", Cmd: "x", TTLSec: 60}},
			})
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestHostedServerBackend_SendsExpectedBody(t *testing.T) {
	t.Parallel()
	var captured []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sign" {
			captured, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"request_id":"r_x","poll_url":"/v1/poll/r_x"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"request_id":"r_x","status":"approved","signatures":[]}`))
	}))
	defer ts.Close()

	hb := &backend.HostedServerBackend{
		BaseURL:    ts.URL,
		APIKey:     "k",
		ClientID:   "karthi-laptop",
		HTTPClient: ts.Client(),
		PollWait:   50 * time.Millisecond,
		Timeout:    2 * time.Second,
	}
	ch, err := hb.Request(context.Background(), backend.ApprovalRequest{
		RequestID: "ignored",
		Commands: []backend.CommandReq{
			{Server: "prod", Cmd: "echo hi", TTLSec: 60},
			{Server: "stage", Cmd: "uptime", TTLSec: 30},
		},
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	<-ch

	var body struct {
		ClientID string `json:"client_id"`
		Commands []struct {
			Server     string `json:"server"`
			Cmd        string `json:"cmd"`
			TTLSeconds int64  `json:"ttl_seconds"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("decode captured body: %v (raw=%q)", err, string(captured))
	}
	if body.ClientID != "karthi-laptop" {
		t.Errorf("client_id = %q; want karthi-laptop", body.ClientID)
	}
	if len(body.Commands) != 2 {
		t.Fatalf("commands len = %d; want 2", len(body.Commands))
	}
	if body.Commands[0].Cmd != "echo hi" || body.Commands[0].Server != "prod" || body.Commands[0].TTLSeconds != 60 {
		t.Errorf("commands[0] = %+v; want {prod, echo hi, 60}", body.Commands[0])
	}
}
