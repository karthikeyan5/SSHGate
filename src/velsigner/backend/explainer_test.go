package backend_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/velsigner/backend"
)

// fakeChatCompletions is a minimal stand-in for an OpenAI-compatible
// /v1/chat/completions endpoint. The fields `respond` / `status` /
// `delay` let each test tailor behaviour without re-writing the
// httptest plumbing every time.
type fakeChatCompletions struct {
	server *httptest.Server

	// respond returns the JSON body the server will write. If respond
	// returns "", the server writes an empty body (useful for the
	// malformed-JSON case).
	respond func(reqBody []byte) string
	// status is the HTTP status code to return (default 200).
	status int
	// delay is artificial latency injected before responding.
	delay time.Duration

	// lastAuth captures the Authorization header from the most recent
	// request — tests assert the bearer prefix.
	lastAuth string
	// lastBody captures the raw request body (JSON) so the test can
	// assert on the model / prompt content.
	lastBody []byte
	// hits counts the number of requests served.
	hits int
}

func newFakeChat(t *testing.T) *fakeChatCompletions {
	t.Helper()
	f := &fakeChatCompletions{status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		f.lastAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		f.lastBody = body

		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				// Client cancelled (e.g. context timeout). Drop the
				// connection silently — the client surfaces
				// ctx.DeadlineExceeded on its side.
				return
			}
		}

		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream broke"}}`))
			return
		}

		respBody := ""
		if f.respond != nil {
			respBody = f.respond(body)
		}
		_, _ = w.Write([]byte(respBody))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// chatCompletionsResponse encodes a minimal happy-path chat completions
// body. content is the message.content text the assistant returned.
func chatCompletionsResponse(content string) string {
	resp := map[string]any{
		"id":      "cmpl-test",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "gpt-4o-mini",
		"choices": []any{
			map[string]any{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": content,
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func newExplainerFor(fake *fakeChatCompletions, timeout time.Duration) *backend.OpenAICompatibleExplainer {
	return &backend.OpenAICompatibleExplainer{
		Endpoint:   fake.server.URL + "/v1/chat/completions",
		Model:      "gpt-4o-mini",
		APIKey:     "test-key-12345",
		HTTPClient: fake.server.Client(),
		Timeout:    timeout,
	}
}

func TestOpenAICompatibleExplainer_HappyPath(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("restart the nginx web server\ninstall the certbot package via apt\nrequest a Let's Encrypt cert for example.com")
	}
	ex := newExplainerFor(fake, 2*time.Second)

	cmds := []string{
		"systemctl restart nginx",
		"apt install -y certbot",
		"certbot --nginx -d example.com",
	}
	got, err := ex.Explain(context.Background(), cmds)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := []string{
		"restart the nginx web server",
		"install the certbot package via apt",
		"request a Let's Encrypt cert for example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q; want %q", i, got[i], want[i])
		}
	}

	// Authorization header was set.
	if !strings.HasPrefix(fake.lastAuth, "Bearer ") {
		t.Errorf("Authorization header = %q; want Bearer prefix", fake.lastAuth)
	}
	// Body contained the model name + commands.
	if !strings.Contains(string(fake.lastBody), `"gpt-4o-mini"`) {
		t.Errorf("request body missing model: %s", fake.lastBody)
	}
	for _, c := range cmds {
		if !strings.Contains(string(fake.lastBody), c) {
			t.Errorf("request body missing command %q: %s", c, fake.lastBody)
		}
	}
}

func TestOpenAICompatibleExplainer_EmptyLinePreserved(t *testing.T) {
	t.Parallel()
	// Per-command empty line → empty string in result (not an error).
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("explanation A\n\nexplanation C")
	}
	ex := newExplainerFor(fake, 2*time.Second)

	got, err := ex.Explain(context.Background(), []string{"cmdA", "cmdB", "cmdC"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := []string{"explanation A", "", "explanation C"}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestOpenAICompatibleExplainer_TimeoutFromCtx(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.delay = 5 * time.Second
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("never returned\nnever returned")
	}
	// Generous instance Timeout; rely on ctx for the cancel.
	ex := newExplainerFor(fake, 30*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := ex.Explain(ctx, []string{"a", "b"})
	if err == nil {
		t.Fatal("Explain returned nil err; want ctx timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v; want context.DeadlineExceeded", err)
	}
}

func TestOpenAICompatibleExplainer_TimeoutFromInstance(t *testing.T) {
	t.Parallel()
	// Even with a no-deadline ctx, the instance Timeout must bound the
	// call. Use a server that delays beyond the instance Timeout.
	fake := newFakeChat(t)
	fake.delay = 500 * time.Millisecond
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("late\nlate")
	}
	ex := newExplainerFor(fake, 50*time.Millisecond)

	_, err := ex.Explain(context.Background(), []string{"a", "b"})
	if err == nil {
		t.Fatal("Explain returned nil err; want timeout error")
	}
	// http.Client.Timeout surfaces as a url.Error wrapping a deadline-ish
	// error; we don't care about the exact identity, just that the wall
	// time was bounded.
}

func TestOpenAICompatibleExplainer_HTTPError(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.status = http.StatusInternalServerError
	ex := newExplainerFor(fake, 2*time.Second)

	_, err := ex.Explain(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("Explain returned nil err; want 500 error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v; want mention of 500", err)
	}
}

func TestOpenAICompatibleExplainer_Unauthorized(t *testing.T) {
	t.Parallel()
	// 401 must surface as an error and MUST NOT trigger retries
	// (daemon.md §11.5).
	fake := newFakeChat(t)
	fake.status = http.StatusUnauthorized
	ex := newExplainerFor(fake, 2*time.Second)

	_, err := ex.Explain(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("Explain returned nil err; want 401 error")
	}
	if fake.hits != 1 {
		t.Errorf("hits = %d; want 1 (no retry on 401)", fake.hits)
	}
}

func TestOpenAICompatibleExplainer_MalformedJSON(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string { return "{not-json" }
	ex := newExplainerFor(fake, 2*time.Second)

	_, err := ex.Explain(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("Explain returned nil err; want JSON parse error")
	}
}

func TestOpenAICompatibleExplainer_EmptyChoices(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return `{"id":"x","object":"chat.completion","choices":[]}`
	}
	ex := newExplainerFor(fake, 2*time.Second)

	_, err := ex.Explain(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("Explain returned nil err; want empty-choices error")
	}
}

func TestOpenAICompatibleExplainer_NilCommands(t *testing.T) {
	t.Parallel()
	// Zero commands → fast return with empty slice, no upstream call.
	fake := newFakeChat(t)
	ex := newExplainerFor(fake, 2*time.Second)

	got, err := ex.Explain(context.Background(), nil)
	if err != nil {
		t.Fatalf("Explain(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len(got) = %d; want 0", len(got))
	}
	if fake.hits != 0 {
		t.Errorf("hits = %d; want 0 (no upstream call on empty input)", fake.hits)
	}
}

func TestOpenAICompatibleExplainer_PadsShortResponse(t *testing.T) {
	t.Parallel()
	// If the model returns fewer lines than commands, the extra
	// positions become empty strings (caller renders "(no explanation)").
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("one explanation")
	}
	ex := newExplainerFor(fake, 2*time.Second)

	got, err := ex.Explain(context.Background(), []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := []string{"one explanation", "", ""}
	if len(got) != len(want) {
		t.Fatalf("len = %d; want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestOpenAICompatibleExplainer_TruncatesLongResponse(t *testing.T) {
	t.Parallel()
	// If the model returns MORE lines than commands, we keep only the
	// first len(cmds) — defensive: avoids leaking extra model chatter
	// into the Telegram message.
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("one\ntwo\nthree\nfour\nfive")
	}
	ex := newExplainerFor(fake, 2*time.Second)

	got, err := ex.Explain(context.Background(), []string{"a", "b"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d; want 2 (got=%v)", len(got), got)
	}
	if got[0] != "one" || got[1] != "two" {
		t.Errorf("got=%v; want [one two]", got)
	}
}

// Sanity-check the prompt rendering: numbered list, one per command.
func TestOpenAICompatibleExplainer_PromptShape(t *testing.T) {
	t.Parallel()
	fake := newFakeChat(t)
	fake.respond = func(_ []byte) string {
		return chatCompletionsResponse("a\nb")
	}
	ex := newExplainerFor(fake, 2*time.Second)

	_, err := ex.Explain(context.Background(), []string{"cmdA", "cmdB"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	body := string(fake.lastBody)
	for _, want := range []string{"1. cmdA", "2. cmdB"} {
		if !strings.Contains(body, want) {
			t.Errorf("request body missing %q\nbody=%s", want, body)
		}
	}
}

