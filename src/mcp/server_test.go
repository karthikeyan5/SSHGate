package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/goleak"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestMain runs goleak for the mcp package tests. The Server spawns
// goroutines via the SDK; each subtest closes its session so the
// counts settle before goleak's snapshot.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeSign returns canned signatures.
type fakeSign struct {
	signed []signpkg.Signed
	err    error
}

func (f *fakeSign) Sign(_ context.Context, _ string, _ []signpkg.CmdReq) ([]signpkg.Signed, error) {
	return f.signed, f.err
}

// fakeSSH returns canned output.
type fakeSSH struct {
	stdout []byte
	stderr []byte
	exit   int
	err    error
}

func (f *fakeSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	return f.stdout, f.stderr, f.exit, f.err
}

func buildServer(t *testing.T, runner *tools.Runner) *mcp.Server {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	return &mcp.Server{Runner: runner, Logger: logger}
}

func connectInProcess(t *testing.T, server *mcp.Server) (*mcpsdk.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcpsdk.NewInMemoryTransports()

	sdkServer := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    mcp.ServerName,
		Version: mcp.Version,
	}, nil)
	// Mirror the run-tool registration that Serve does, but use the
	// in-memory transport so we don't fight with stdin EOF.
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolName,
		Description: "Run a shell command on a registered server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunInput) (*mcpsdk.CallToolResult, tools.RunOutput, error) {
		out, err := server.Runner.Run(ctx, in)
		if err != nil {
			return nil, tools.RunOutput{}, err
		}
		return nil, out, nil
	})
	if _, err := sdkServer.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return cs, func() {
		_ = cs.Close()
	}
}

func newRegistryWith(t *testing.T, alias string, e registry.Entry) *registry.Servers {
	t.Helper()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(alias, e); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServer_InitializeReportsName(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)

	cs, stop := connectInProcess(t, srv)
	defer stop()

	info := cs.InitializeResult()
	if info == nil {
		t.Fatal("InitializeResult is nil")
	}
	if info.ServerInfo == nil {
		t.Fatal("ServerInfo is nil")
	}
	if info.ServerInfo.Name != mcp.ServerName {
		t.Errorf("ServerInfo.Name = %q; want %q", info.ServerInfo.Name, mcp.ServerName)
	}
}

func TestServer_ListToolsReturnsRunTool(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 1 {
		t.Fatalf("got %d tools; want 1", len(res.Tools))
	}
	tool := res.Tools[0]
	if tool.Name != mcp.ToolName {
		t.Errorf("Name = %q; want %q", tool.Name, mcp.ToolName)
	}
	if tool.Description == "" {
		t.Error("Description is empty")
	}
	if tool.InputSchema == nil {
		t.Error("InputSchema is nil")
	}
}

func TestServer_CallToolReadPath(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte("hello\n")}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolName,
		Arguments: map[string]any{"alias": "h1", "command": "df -h"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Errorf("IsError = true; expected success. Content: %+v", res.Content)
	}
	// StructuredContent is `any` over the wire — the SDK delivers it
	// as a json.RawMessage on the client side.
	raw, ok := res.StructuredContent.(json.RawMessage)
	if !ok {
		// Fallback: marshal whatever was delivered and re-parse.
		b, mErr := json.Marshal(res.StructuredContent)
		if mErr != nil {
			t.Fatalf("structured content: %T (%v)", res.StructuredContent, res.StructuredContent)
		}
		raw = b
	}
	var out tools.RunOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured content: %v (raw=%s)", err, string(raw))
	}
	if out.Stdout != "hello\n" {
		t.Errorf("Stdout = %q", out.Stdout)
	}
	if out.Kind != "read" {
		t.Errorf("Kind = %q; want read", out.Kind)
	}
}

func TestServer_CallToolUnknownAliasReturnsToolError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolName,
		Arguments: map[string]any{"alias": "nope", "command": "df -h"},
	})
	if err != nil {
		t.Fatalf("CallTool returned protocol err: %v", err)
	}
	if !res.IsError {
		t.Error("IsError = false; want true for unknown alias")
	}
}

func TestServe_StdioEOFShutsDown(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := &mcp.Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	// Empty reader → immediate EOF. Serve should return promptly.
	in := bytesReader(nil)
	var out devNull
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, in, &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve on EOF: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Serve did not return within 2s on EOF")
	}
}

func TestServe_RejectsNilRunner(t *testing.T) {
	t.Parallel()
	srv := &mcp.Server{Logger: log.New(io.Discard, "", 0)}
	err := srv.Serve(context.Background(), bytesReader(nil), &devNull{})
	if err == nil {
		t.Error("Serve with nil Runner returned nil; want error")
	}
}

func TestServe_RejectsNilLogger(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := &mcp.Server{Runner: runner}
	err := srv.Serve(context.Background(), bytesReader(nil), &devNull{})
	if err == nil {
		t.Error("Serve with nil Logger returned nil; want error")
	}
}

// bytesReader returns an io.Reader over a static byte slice that
// reports io.EOF after the slice is exhausted (which io.Reader of
// nil/empty does by default — bytes.Reader is fine here, but we
// want a tiny dependency-free helper to keep the file portable
// across the goleak-protected test run).
type byteReader struct {
	buf []byte
	off int
}

func bytesReader(b []byte) *byteReader { return &byteReader{buf: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

type devNull struct{}

func (*devNull) Write(p []byte) (int, error) { return len(p), nil }

// Ensure imports stay referenced even when adjusting tests.
var _ = os.Stdin
