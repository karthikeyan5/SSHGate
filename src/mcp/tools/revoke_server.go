package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RevokeServerInput is the JSON input to sshgate.revoke_server. The
// tool tears down the remote velgate install behind alias and removes
// the alias from the local registry. Spec §"Revocation → From our end
// (remote)".
type RevokeServerInput struct {
	Alias string `json:"alias" jsonschema:"alias of the server to revoke (must already be registered)"`
}

// RevokeServerOutput is the structured result. RemoteCleaned and
// RegistryRemoved are reported independently so partial-failure cases
// (e.g. SSH succeeded but registry write failed) are visible to the
// caller; a fully-successful revoke has both true.
type RevokeServerOutput struct {
	Alias           string `json:"alias"`
	RemoteCleaned   bool   `json:"remote_cleaned"`
	RegistryRemoved bool   `json:"registry_removed"`
	Message         string `json:"message"`
}

// RevokeTTLSec is the validity window we request when signing the
// VELGATE_REVOKE command. Spec calls for 60s — long enough to cover
// dial+exec, well under sigwire.MaxSigValidity.
const RevokeTTLSec = 60

// revokeStdoutMarker is the prefix velgate prints on successful revoke
// (see velgate.FormatRevokeStdout). The MCP side requires the marker
// before removing the alias from the registry.
const revokeStdoutMarker = "VELGATE_REVOKED"

// RevokeServer signs VELGATE_REVOKE, runs it on the remote, and on
// confirmation removes the alias from the registry.
//
// Flow:
//
//  1. Look up alias → unknown → return error.
//  2. Sign VELGATE_REVOKE through the velsigner backend (one-cmd
//     sign request, TTL = RevokeTTLSec).
//  3. SSH the signed line. velgate's main.go routes it to doRevoke,
//     which strips the SSHGate-restricted authorized_keys line and
//     removes ~/.velgate/.
//  4. Verify stdout contains VELGATE_REVOKED; remove alias from the
//     registry. Registry write failures keep RemoteCleaned=true so the
//     operator can re-run revoke or hand-clean the registry.
//
// Sign-side errors (ErrDenied, ErrTimeout, ErrUnreachable) are wrapped
// so callers can match with errors.Is.
func (r *Runner) RevokeServer(ctx context.Context, in RevokeServerInput) (RevokeServerOutput, error) {
	if r.Servers == nil {
		return RevokeServerOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RevokeServerOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RevokeServerOutput{}, errors.New("tools: SSH is nil")
	}
	if in.Alias == "" {
		return RevokeServerOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RevokeServerOutput{}, fmt.Errorf("tools: unknown server alias %q", in.Alias)
	}

	reqID, err := newRequestID()
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: request id: %w", err)
	}
	// Spec defines CmdReq.Server as the registered alias (recorded
	// in the velsigner audit log), not the underlying hostname.
	signed, err := r.Sign.Sign(ctx, reqID, []signpkg.CmdReq{{
		Server: in.Alias,
		Cmd:    "VELGATE_REVOKE",
		TTLSec: RevokeTTLSec,
	}})
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: sign revoke: %w", err)
	}
	if len(signed) != 1 {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: expected 1 signature; got %d", len(signed))
	}
	wireCmd := signed[0].Sig + " VELGATE_REVOKE"

	stdout, stderr, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, wireCmd)
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: ssh revoke: %w (stderr=%q exit=%d)",
			err, strings.TrimSpace(string(stderr)), exit)
	}
	if !strings.Contains(string(stdout), revokeStdoutMarker) {
		return RevokeServerOutput{Alias: in.Alias},
			fmt.Errorf("tools: velgate did not confirm revoke (stdout=%q stderr=%q exit=%d)",
				strings.TrimSpace(string(stdout)), strings.TrimSpace(string(stderr)), exit)
	}

	out := RevokeServerOutput{
		Alias:         in.Alias,
		RemoteCleaned: true,
		Message:       strings.TrimSpace(string(stdout)),
	}

	if err := r.Servers.Remove(in.Alias); err != nil {
		// Remote is already clean. Surface the registry error but keep
		// RemoteCleaned=true so the operator can recover by hand-editing
		// servers.json.
		return out, fmt.Errorf("tools: remote cleaned but registry remove failed: %w", err)
	}
	out.RegistryRemoved = true
	return out, nil
}
