package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Explainer generates short plain-English explanations of shell commands.
//
// Approval flow must never block on Explainer availability: the
// TelegramBackend treats any non-nil error from Explain as
// "render commands without explanations + footer note." Implementations
// MUST honour ctx for cancellation/timeout.
type Explainer interface {
	// Explain returns one-line explanations for each command, in the same
	// order. The returned slice has the same length as cmds. On per-command
	// failure (e.g. the model returns fewer lines than commands), the
	// corresponding entry MAY be an empty string; the backend renders
	// "(no explanation)" for empty entries. Total wall-time is bounded by
	// the smaller of ctx and the implementation's own timeout.
	Explain(ctx context.Context, cmds []string) ([]string, error)
}

// OpenAICompatibleExplainer is the default Explainer. It POSTs a single
// Chat Completions request to an OpenAI-compatible endpoint (OpenAI,
// OpenRouter, LM Studio, llama.cpp's server, etc.) and parses the
// assistant's reply as one-explanation-per-line.
//
// The instance is safe for concurrent use as long as HTTPClient is.
type OpenAICompatibleExplainer struct {
	// Endpoint is the full URL of the chat completions API, e.g.
	// https://api.openai.com/v1/chat/completions or
	// https://openrouter.ai/api/v1/chat/completions.
	Endpoint string
	// Model is the model identifier the endpoint expects, e.g.
	// "gpt-4o-mini" or "anthropic/claude-haiku-4.5".
	Model string
	// APIKey is sent as the Bearer token in the Authorization header.
	APIKey string
	// HTTPClient is injected so tests can point at httptest. If nil,
	// a default client with Timeout = Timeout is constructed per call.
	HTTPClient *http.Client
	// Timeout bounds the per-call wall time. Defaults to 5s if zero.
	// Also applied to HTTPClient if HTTPClient is nil.
	Timeout time.Duration
}

// chatRequest is the minimal subset of the OpenAI Chat Completions
// request shape we need: model + messages.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the minimal subset we read back. We tolerate extra
// upstream fields silently.
type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

// explainerPrompt is the system + user prompt template. Kept package-
// private so it's easy to evolve without breaking callers. The
// numbered-list shape matches what we parse on the response side.
const explainerPromptHeader = `You are a security reviewer's assistant. For each shell command below, write a SINGLE SHORT SENTENCE (at most 25 words) explaining what it does in plain English. Reply with ONE LINE PER COMMAND, in the same order. No numbering, no formatting, no commentary, just the sentences. If a command is ambiguous or you don't know, write: unknown command.

Commands:
`

// Explain implements Explainer.
func (e *OpenAICompatibleExplainer) Explain(ctx context.Context, cmds []string) ([]string, error) {
	if len(cmds) == 0 {
		return nil, nil
	}

	timeout := e.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Apply the instance timeout on top of ctx — caller's ctx wins if
	// tighter (daemon.md §11.3). We attach the deadline regardless of
	// HTTPClient.Timeout so cancellation propagates uniformly.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := buildExplainerRequest(e.Model, cmds)
	if err != nil {
		return nil, fmt.Errorf("explainer: build request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("explainer: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if e.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.APIKey)
	}

	client := e.HTTPClient
	if client == nil {
		// Construct a one-off client with the same timeout. Production
		// callers SHOULD inject HTTPClient explicitly (daemon.md §11.1).
		client = &http.Client{Timeout: timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("explainer: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a small chunk for the log line; don't leak credentials
		// upward. daemon.md §11.4 — distinguish 4xx (our bug / stale
		// key) from 5xx (upstream).
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		class := "5xx"
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			class = "4xx"
		}
		return nil, fmt.Errorf("explainer: upstream %s status %d", class, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("explainer: read body: %w", err)
	}

	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("explainer: decode response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, errors.New("explainer: response has no choices")
	}
	content := parsed.Choices[0].Message.Content
	return parseExplainerContent(content, len(cmds)), nil
}

// buildExplainerRequest assembles the JSON body for a single chat
// completion. Separated so tests (or future callers) can stub.
func buildExplainerRequest(model string, cmds []string) ([]byte, error) {
	var user strings.Builder
	user.WriteString(explainerPromptHeader)
	for i, c := range cmds {
		fmt.Fprintf(&user, "%d. %s\n", i+1, c)
	}
	cr := chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "user", Content: user.String()},
		},
	}
	return json.Marshal(cr)
}

// parseExplainerContent splits the model reply on newlines and returns
// exactly n entries (padding with "" or truncating extras). Lines are
// stripped of leading/trailing whitespace. Empty lines become "".
func parseExplainerContent(content string, n int) []string {
	// Normalise CRLF and any leading/trailing whitespace.
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(content), "\n")

	out := make([]string, n)
	for i := 0; i < n; i++ {
		if i >= len(lines) {
			out[i] = ""
			continue
		}
		out[i] = strings.TrimSpace(lines[i])
	}
	return out
}
