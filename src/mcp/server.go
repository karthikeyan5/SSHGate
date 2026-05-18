package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// isCleanShutdown reports whether err is one of the expected
// transport-closing signals: stdin EOF, ctx cancellation, or the
// SDK's ErrConnectionClosed sentinel. Any of these is a clean
// shutdown of the MCP session, not a runtime failure.
func isCleanShutdown(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, mcpsdk.ErrConnectionClosed) {
		return true
	}
	// The SDK wraps EOF into "server is closing: EOF" via the
	// jsonrpc2 error chain — we accept the textual form as a
	// last-resort match because the wrapper does not always
	// preserve io.EOF.
	if msg := err.Error(); strings.Contains(msg, "server is closing") || strings.Contains(msg, "EOF") {
		return true
	}
	return false
}

// Version is the SSHGate MCP server's reported version string. It
// flows into the JSON-RPC initialize response and from there into
// Claude Code's session log.
const Version = "0.1.5"

// ServerName MUST equal the .mcp.json key. Claude Code routes tool
// names by "mcp__<ServerName>__<tool>" — a mismatch causes silent
// drops (plugin.md §3.1).
const ServerName = "sshgate"

// ToolName is the un-namespaced tool name registered with the SDK.
// Claude Code's surface name is "mcp__sshgate__run".
const ToolName = "run"

// Server is the MCP front-end. It owns a single tool implementation
// (the Runner) and is configured by main. Logger is the operator-side
// log target; it MUST write to stderr (stdout is the JSON-RPC
// channel).
type Server struct {
	Runner *tools.Runner
	Logger *log.Logger
}

// Serve runs the MCP server over the provided stdio pipes. It
// returns nil on clean shutdown (ctx cancelled or stdin EOF) and a
// non-nil error otherwise.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Runner == nil {
		return errors.New("mcp: Runner is nil")
	}
	if s.Logger == nil {
		return errors.New("mcp: Logger is nil")
	}

	server := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    ServerName,
		Version: Version,
	}, nil)

	// Register the run tool using the generic AddTool helper so the
	// SDK derives the input schema from RunInput automatically.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolName,
		Description: "Run a shell command on a registered server. Read commands run directly; write commands request human approval (a Telegram tap) before running.",
	}, s.runHandler)

	t := &mcpsdk.IOTransport{
		Reader: readerCloser{in},
		Writer: writerCloser{out},
	}
	if err := server.Run(ctx, t); err != nil {
		if isCleanShutdown(err) {
			return nil
		}
		return err
	}
	return nil
}

// runHandler is the typed tool handler bound to ToolName. It
// delegates to the Runner and surfaces any error as an MCP tool
// error (which the SDK packs into IsError=true on the result).
func (s *Server) runHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunInput) (*mcpsdk.CallToolResult, tools.RunOutput, error) {
	out, err := s.Runner.Run(ctx, in)
	if err != nil {
		// Log to stderr so an operator running the binary by hand sees
		// the failure; the model gets the structured tool error from
		// the SDK.
		s.Logger.Printf("run alias=%s err=%v", in.Alias, err)
		return nil, tools.RunOutput{}, err
	}
	s.Logger.Printf("run alias=%s kind=%s approved=%v exit=%d", in.Alias, out.Kind, out.Approved, out.ExitCode)
	// Also pack a TextContent block so older MCP clients (without
	// structured content support) see a human-readable result.
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRunSummary(out)}},
	}, out, nil
}

// formatRunSummary returns a short human-readable summary of out for
// fallback TextContent. Stdout/stderr are truncated to keep the
// chat-side log compact; structured content carries the full output.
func formatRunSummary(out tools.RunOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s exit=%d", out.Kind, out.ExitCode)
	if out.Kind == "write" {
		fmt.Fprintf(&b, " approved=%v", out.Approved)
	}
	if out.Stdout != "" {
		fmt.Fprintf(&b, "\n--- stdout ---\n%s", truncate(out.Stdout, 2000))
	}
	if out.Stderr != "" {
		fmt.Fprintf(&b, "\n--- stderr ---\n%s", truncate(out.Stderr, 2000))
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[...truncated]"
}

// readerCloser / writerCloser adapt plain io.Reader / io.Writer to
// the io.ReadCloser / io.WriteCloser expected by mcpsdk.IOTransport.
// Close is a no-op — the caller (typically main) owns the stdio
// pipes and is responsible for closing them on shutdown.
type readerCloser struct{ io.Reader }

func (readerCloser) Close() error { return nil }

type writerCloser struct{ io.Writer }

func (writerCloser) Close() error { return nil }
