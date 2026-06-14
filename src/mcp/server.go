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
const Version = "0.2.0"

// ServerName MUST equal the .mcp.json key. Claude Code routes tool
// names by "mcp__<ServerName>__<tool>" — a mismatch causes silent
// drops (plugin.md §3.1).
const ServerName = "sshgate"

// ToolName is the un-namespaced tool name registered with the SDK.
// Claude Code's surface name is "mcp__sshgate__run".
const ToolName = "run"

// ToolNameRunBatch is the un-namespaced batch tool name. Claude Code's
// surface name is "mcp__sshgate__run_batch".
const ToolNameRunBatch = "run_batch"

// ToolNameAddServer registers a new server alias with auto-setup
// (uploads gate, rewrites authorized_keys, verifies). Claude Code's
// surface name is "mcp__sshgate__add_server".
const ToolNameAddServer = "add_server"

// ToolNameListServers lists registered server aliases with their
// connection details. Claude Code's surface name is
// "mcp__sshgate__list_servers".
const ToolNameListServers = "list_servers"

// ToolNameStatus reports signer-socket and per-server reachability.
// Claude Code's surface name is "mcp__sshgate__status".
const ToolNameStatus = "status"

// ToolNameRevokeServer tears down a registered server: signs and ships
// SSHGATE_REVOKE, lets gate strip itself from authorized_keys and
// remove ~/.sshgate-gate/, then removes the alias from the registry. Claude
// Code's surface name is "mcp__sshgate__revoke_server".
const ToolNameRevokeServer = "revoke_server"

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

	// run_batch — same approval engine, but one Telegram tap covers
	// the whole batch of writes (reads stay direct).
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameRunBatch,
		Description: "Run a sequence of shell commands on a registered server. Reads run directly; all writes are bundled into a single approval (one Telegram tap). stop_on_error defaults to true.",
	}, s.runBatchHandler)

	// add_server — auto-setup. Bootstraps via the operator's existing
	// SSH access (key file path or ssh-agent), uploads gate, rewrites
	// authorized_keys with command="..." forcing for the SSHGate
	// dedicated key, verifies via the SSHGATE_OK probe, and registers
	// the alias. Idempotent — re-add on a server with the canonical
	// restricted entry already in place skips the rewrite.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameAddServer,
		Description: "Register a new server alias and install gate on it. Bootstrap leg uses your existing SSH access (bootstrap_key_path or bootstrap_agent=true). Auto-setup uploads gate + signing key, rewrites authorized_keys, verifies via the SSHGATE_OK probe, then atomically registers the alias.",
	}, s.addServerHandler)

	// list_servers — returns every registered alias with its host/port/user.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameListServers,
		Description: "List every registered SSHGate server (alias, host, port, user, added_at). Output is sorted alphabetically by alias.",
	}, s.listServersHandler)

	// status — health probe of signer and every registered server.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameStatus,
		Description: "Report signer-socket reachability and per-server SSH reachability (via the SSHGATE_OK probe). Server probes run in parallel with a short timeout.",
	}, s.statusHandler)

	// revoke_server — signs SSHGATE_REVOKE, ships it, removes the alias
	// from the registry once gate confirms the on-host teardown.
	mcpsdk.AddTool(server, &mcpsdk.Tool{
		Name:        ToolNameRevokeServer,
		Description: "Revoke a registered server. Signs SSHGATE_REVOKE (one approval), gate strips its authorized_keys line and removes ~/.sshgate-gate/, MCP removes the alias. Backup kept at ~/.ssh/authorized_keys.sshgate-revoke-backup.",
	}, s.revokeServerHandler)

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

// runBatchHandler is the typed tool handler for run_batch. The Runner
// returns a structured RunBatchOutput either way (approved, denied,
// timed-out, or unreachable) — only a true infrastructure error (nil
// runner, unknown alias, etc.) is surfaced as a Go error.
func (s *Server) runBatchHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunBatchInput) (*mcpsdk.CallToolResult, tools.RunBatchOutput, error) {
	out, err := s.Runner.RunBatch(ctx, in)
	if err != nil {
		s.Logger.Printf("run_batch alias=%s err=%v", in.Alias, err)
		return nil, tools.RunBatchOutput{}, err
	}
	s.Logger.Printf("run_batch alias=%s n=%d approved=%v denied=%v reason=%s", in.Alias, len(out.Results), out.Approved, out.Denied, out.Reason)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRunBatchSummary(out)}},
	}, out, nil
}

// addServerHandler is the typed tool handler for add_server. Errors
// surface as MCP tool errors (IsError=true) so Claude can see exactly
// why setup failed; on success the structured AddServerOutput carries
// the captured host fingerprint and the remote binary path.
func (s *Server) addServerHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.AddServerInput) (*mcpsdk.CallToolResult, tools.AddServerOutput, error) {
	out, err := s.Runner.AddServer(ctx, in)
	if err != nil {
		s.Logger.Printf("add_server alias=%s err=%v", in.Alias, err)
		return nil, tools.AddServerOutput{}, err
	}
	s.Logger.Printf("add_server alias=%s host=%s port=%d user=%s fp=%s idempotent=%v",
		out.Alias, out.Host, out.Port, out.User, out.Fingerprint, out.Idempotent)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatAddServerSummary(out)}},
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

// formatRunBatchSummary renders a short human summary of a batch
// outcome for the fallback TextContent block. Structured content
// carries the full per-command stdout/stderr/exit.
func formatRunBatchSummary(out tools.RunBatchOutput) string {
	var b strings.Builder
	if out.Denied {
		fmt.Fprintf(&b, "batch denied (%s) on %s", out.Reason, out.Server)
		return b.String()
	}
	fmt.Fprintf(&b, "batch on %s: %d command(s), approved=%v", out.Server, len(out.Results), out.Approved)
	for i, r := range out.Results {
		fmt.Fprintf(&b, "\n[%d] %s exit=%d", i, r.Kind, r.ExitCode)
		if r.Skipped {
			fmt.Fprintf(&b, " (skipped)")
		}
		// A gate deny (exit 77/65) on a write annotates the result's
		// Stderr with remediation; echo it into the fallback summary so
		// the model sees it even without structured-content support.
		if note := gateDenyNoteFor(r); note != "" {
			fmt.Fprintf(&b, "\n     %s", note)
		}
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[...truncated]"
}

// gateDenyNoteFor returns a short remediation line for a write command
// result whose exit code is a well-known gate deny (77 = missing sig /
// read-only, 65 = bad/expired sig), or "" otherwise. Reads never carry
// these codes, so the annotation is write-only. The run_batch layer
// already folds the full note into the result's Stderr; this keeps the
// fallback TextContent summary actionable too.
func gateDenyNoteFor(r tools.CommandResult) string {
	if r.Kind != "write" {
		return ""
	}
	switch r.ExitCode {
	case 77:
		return "gate denied (exit 77): no signer pubkey (read-only / Tier-1) or missing signature — run /sshgate:setup then /sshgate:add to upgrade."
	case 65:
		return "gate rejected the signature (exit 65): expired or invalid — usually clock skew or a stale approval; retry."
	default:
		return ""
	}
}

// revokeServerHandler is the typed handler for sshgate.revoke_server.
// Sign denials/timeouts and SSH/registry errors surface as MCP tool
// errors (IsError=true) so Claude can see exactly why the revoke
// failed; on success the structured RevokeServerOutput carries the
// confirmation message printed by gate.
func (s *Server) revokeServerHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RevokeServerInput) (*mcpsdk.CallToolResult, tools.RevokeServerOutput, error) {
	out, err := s.Runner.RevokeServer(ctx, in)
	if err != nil {
		s.Logger.Printf("revoke_server alias=%s err=%v", in.Alias, err)
		return nil, out, err
	}
	s.Logger.Printf("revoke_server alias=%s remote_cleaned=%v registry_removed=%v",
		out.Alias, out.RemoteCleaned, out.RegistryRemoved)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatRevokeServerSummary(out)}},
	}, out, nil
}

// formatRevokeServerSummary renders a short human summary for the
// fallback TextContent block. Structured output carries the full
// RevokeServerOutput.
func formatRevokeServerSummary(out tools.RevokeServerOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "revoked %s: remote_cleaned=%v registry_removed=%v",
		out.Alias, out.RemoteCleaned, out.RegistryRemoved)
	if out.Message != "" {
		fmt.Fprintf(&b, "\ngate: %s", out.Message)
	}
	return b.String()
}

// listServersHandler is the typed handler for sshgate.list_servers.
// The structured ListServersOutput carries the alphabetically-sorted
// registry contents; the TextContent fallback is a one-line summary.
func (s *Server) listServersHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.ListServersInput) (*mcpsdk.CallToolResult, tools.ListServersOutput, error) {
	out, err := s.Runner.ListServers(ctx, in)
	if err != nil {
		s.Logger.Printf("list_servers err=%v", err)
		return nil, tools.ListServersOutput{}, err
	}
	s.Logger.Printf("list_servers total=%d", out.Total)
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatListServersSummary(out)}},
	}, out, nil
}

// statusHandler is the typed handler for sshgate.status. Per-target
// failures are returned as part of the structured output; only a true
// configuration error (nil dependency) surfaces as an MCP tool error.
func (s *Server) statusHandler(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.StatusInput) (*mcpsdk.CallToolResult, tools.StatusOutput, error) {
	out, err := s.Runner.Status(ctx, in)
	if err != nil {
		s.Logger.Printf("status err=%v", err)
		return nil, tools.StatusOutput{}, err
	}
	s.Logger.Printf("status signer_reachable=%v servers=%d", out.SignerSocket.Reachable, len(out.Servers))
	return &mcpsdk.CallToolResult{
		Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: formatStatusSummary(out)}},
	}, out, nil
}

// formatListServersSummary returns a compact human listing for the
// fallback TextContent block. Structured content carries the full
// ListServersOutput.
func formatListServersSummary(out tools.ListServersOutput) string {
	if out.Total == 0 {
		return "no registered servers"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d server(s):", out.Total)
	for _, s := range out.Servers {
		fmt.Fprintf(&b, "\n  %s  %s@%s:%d", s.Alias, s.User, s.Host, s.Port)
	}
	return b.String()
}

// formatStatusSummary renders a short health summary for the fallback
// TextContent block. Structured content carries the full StatusOutput.
func formatStatusSummary(out tools.StatusOutput) string {
	var b strings.Builder
	switch {
	case out.SignerSocket.Reachable:
		fmt.Fprintf(&b, "signer: reachable (%s)", out.SignerSocket.Path)
	case !out.SignerSocket.Configured:
		// Tier 1: no signer daemon installed. This is the expected
		// read-only state, not a failure to debug (audit M4).
		fmt.Fprintf(&b, "signer: not configured (%s) — read-only / Tier 1; writes are denied at the gate. Run /sshgate:setup to add a Telegram signer.", out.SignerSocket.Path)
	case out.SignerSocket.Permission:
		// Socket present but the dial was permission-denied: the MCP
		// process is not in the sshgatesigner group. NOT a dead daemon —
		// the fix is a fresh login + Claude Code relaunch, not systemctl.
		fmt.Fprintf(&b, "signer: socket present but NOT ACCESSIBLE (%s) — permission denied; your shell/session is not in the sshgatesigner group. Log out and back in, relaunch Claude Code (a side-terminal newgrp is not enough), then run /mcp to confirm. This is NOT a dead daemon.", out.SignerSocket.Path)
	default:
		// Configured (socket file present) but the dial failed — a real
		// Tier-2 daemon problem worth surfacing.
		fmt.Fprintf(&b, "signer: UNREACHABLE (%s): %s", out.SignerSocket.Path, out.SignerSocket.Error)
	}
	for _, sv := range out.Servers {
		if sv.Reachable {
			fmt.Fprintf(&b, "\n  %s: ok %dms", sv.Alias, sv.PingMS)
		} else {
			fmt.Fprintf(&b, "\n  %s: DOWN %s", sv.Alias, sv.Error)
		}
	}
	return b.String()
}

// formatAddServerSummary renders a short human summary for the
// fallback TextContent block. Structured output carries the full
// AddServerOutput.
func formatAddServerSummary(out tools.AddServerOutput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "added %s (%s@%s:%d)", out.Alias, out.User, out.Host, out.Port)
	if out.Idempotent {
		b.WriteString(" [idempotent: existing restricted entry detected]")
	}
	if out.Fingerprint != "" {
		fmt.Fprintf(&b, "\nhost fingerprint: %s", out.Fingerprint)
	}
	if out.BinaryPath != "" {
		fmt.Fprintf(&b, "\ngate: %s", out.BinaryPath)
	}
	fmt.Fprintf(&b, "\nverified_ok=%v", out.VerifiedOK)
	return b.String()
}

// readerCloser / writerCloser adapt plain io.Reader / io.Writer to
// the io.ReadCloser / io.WriteCloser expected by mcpsdk.IOTransport.
// Close is a no-op — the caller (typically main) owns the stdio
// pipes and is responsible for closing them on shutdown.
type readerCloser struct{ io.Reader }

func (readerCloser) Close() error { return nil }

type writerCloser struct{ io.Writer }

func (writerCloser) Close() error { return nil }
