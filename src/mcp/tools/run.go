package tools

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RunInput is the JSON input to the sshgate.run tool. Schema:
//
//	{
//	  "type":"object",
//	  "required":["alias","command"],
//	  "properties":{
//	    "alias":{"type":"string"},
//	    "command":{"type":"string"}
//	  }
//	}
type RunInput struct {
	Alias   string `json:"alias" jsonschema:"registered server alias (run sshgate.list_servers to see options)"`
	Command string `json:"command" jsonschema:"shell command to run on the remote host"`
}

// RunOutput is the structured result. The MCP server layer also
// surfaces it as a TextContent block so older clients can see it.
type RunOutput struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	// Kind is "read" or "write" — Claude can see whether the command
	// was routed through the approval flow.
	Kind string `json:"kind"`
	// Approved is true when a sign request was made and approved (i.e.
	// for writes). Reads are always direct, never solicited approval.
	Approved bool `json:"approved"`
}

// SignClient is the subset of sign.Client that Runner needs. It
// exists so tests can inject a fake without standing up the
// velsigner socket.
type SignClient interface {
	Sign(ctx context.Context, requestID string, cmds []signpkg.CmdReq) ([]signpkg.Signed, error)
}

// SSHRunner is the subset of ssh.Client that Runner needs. It
// exists so tests can inject a fake without standing up an SSH
// server.
type SSHRunner interface {
	Run(ctx context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error)
}

// Runner is the sshgate.run tool implementation. All fields must be
// non-nil before calling Run; the MCP entry point sets them at
// startup.
type Runner struct {
	Servers *registry.Servers
	Sign    SignClient
	SSH     SSHRunner

	// WriteTTLSec is the signature validity window for writes,
	// passed to the daemon as ttl_seconds. Zero means
	// DefaultWriteTTLSec.
	WriteTTLSec int64

	// AddServerCfg overrides the defaults used by AddServer (paths to
	// the velgate binary, signing pubkey, and SSHGate dedicated
	// pubkey). Tests inject this; production leaves it zero and the
	// resolver populates each field from $XDG_CONFIG_HOME / env.
	AddServerCfg AddServerConfig

	// VelsignerSockPath is the absolute path to the velsigner Unix
	// socket. Status() dials this path to report velsigner reachability;
	// other tools route through Sign (which carries its own SocketPath).
	// Production wires the same path into both.
	VelsignerSockPath string
}

// DefaultWriteTTLSec is the default sig-validity window for writes —
// long enough to cover dial+exec, well under sigwire.MaxSigValidity.
const DefaultWriteTTLSec = 120

// Run resolves the alias from the registry, classifies the command,
// and dispatches:
//   - read  → SSH directly with the literal command;
//   - write → Sign (one-cmd request), then SSH with the signed
//     wire prefix.
//
// Errors from Sign and SSH are wrapped (errors.Is preserves the
// sentinel). Unknown aliases produce a friendly error mentioning the
// alias by name.
func (r *Runner) Run(ctx context.Context, in RunInput) (RunOutput, error) {
	if r.Servers == nil {
		return RunOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RunOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RunOutput{}, errors.New("tools: SSH is nil")
	}
	if strings.TrimSpace(in.Command) == "" {
		return RunOutput{}, errors.New("tools: command is empty")
	}
	if in.Alias == "" {
		return RunOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RunOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	kind := classify.Classify(in.Command)
	switch kind {
	case classify.KindUnknown:
		// The classifier reports KindUnknown only for empty/whitespace
		// input — already handled above.
		return RunOutput{}, fmt.Errorf("tools: could not classify command %q", in.Command)
	case classify.KindRead:
		return r.runRead(ctx, entry, in.Command)
	case classify.KindWrite:
		return r.runWrite(ctx, in.Alias, entry, in.Command)
	default:
		return RunOutput{}, fmt.Errorf("tools: unexpected classification %v", kind)
	}
}

func (r *Runner) runRead(ctx context.Context, e registry.Entry, cmd string) (RunOutput, error) {
	stdout, stderr, exit, err := r.SSH.Run(ctx, e.Host, e.User, e.Port, cmd)
	if err != nil {
		return RunOutput{Stdout: string(stdout), Stderr: string(stderr), ExitCode: exit, Kind: "read"},
			fmt.Errorf("ssh exec: %w", err)
	}
	return RunOutput{
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		ExitCode: exit,
		Kind:     "read",
		Approved: false,
	}, nil
}

func (r *Runner) runWrite(ctx context.Context, alias string, e registry.Entry, cmd string) (RunOutput, error) {
	ttl := r.WriteTTLSec
	if ttl <= 0 {
		ttl = DefaultWriteTTLSec
	}
	reqID, err := newRequestID()
	if err != nil {
		return RunOutput{Kind: "write"}, fmt.Errorf("tools: request id: %w", err)
	}
	// Spec defines CmdReq.Server as the registered alias (recorded in
	// the velsigner audit log), not the underlying hostname. Passing
	// the alias keeps audit-log archaeology stable across hostname
	// changes and matches the format the audit-log examples use.
	signed, err := r.Sign.Sign(ctx, reqID, []signpkg.CmdReq{{Server: alias, Cmd: cmd, TTLSec: ttl}})
	if err != nil {
		// Preserve the sentinel for the MCP layer.
		return RunOutput{Kind: "write"}, fmt.Errorf("tools: sign: %w", err)
	}
	if len(signed) != 1 {
		return RunOutput{Kind: "write"}, fmt.Errorf("tools: expected 1 signature; got %d", len(signed))
	}
	wireCmd := signed[0].Sig + " " + cmd

	stdout, stderr, exit, err := r.SSH.Run(ctx, e.Host, e.User, e.Port, wireCmd)
	if err != nil {
		return RunOutput{Stdout: string(stdout), Stderr: string(stderr), ExitCode: exit, Kind: "write", Approved: true},
			fmt.Errorf("ssh exec: %w", err)
	}
	return RunOutput{
		Stdout:   string(stdout),
		Stderr:   string(stderr),
		ExitCode: exit,
		Kind:     "write",
		Approved: true,
	}, nil
}

// newRequestID returns a short random identifier prefixed with "r_"
// (matching the audit-log naming convention in the spec). 12 bytes
// of entropy is ~96 bits — plenty for correlating a sign request
// over the socket within a session.
func newRequestID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "r_" + base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
