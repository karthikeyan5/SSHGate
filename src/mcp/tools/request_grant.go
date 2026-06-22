package tools

import (
	"context"
	"errors"
	"fmt"
)

// RequestGrantInput is the JSON input to sshgate.request_grant. It asks
// the signer to mint a STANDING GRANT on alias: ONE human Telegram
// approval of a distinct "STANDING GRANT" message lets the signer
// auto-sign matching writes for the window WITHOUT further taps. The
// agent can only REQUEST — it can never create a grant itself; only the
// human approving the scary message does.
type RequestGrantInput struct {
	Alias string `json:"alias" jsonschema:"registered server alias the grant applies to (run sshgate.list_servers)"`
	// Scope is "all" or "commands". "all" auto-signs ANY write on the alias
	// for the window — use it ONLY for a throwaway / dedicated target, never
	// a server that also holds anything you care about. "commands"
	// auto-signs ONLY the exact command strings in Commands (no patterns,
	// no argument tolerance) — prefer this for any server that matters.
	Scope string `json:"scope" jsonschema:"grant scope: \"all\" (auto-sign EVERY write on the alias — throwaway/dedicated targets only) or \"commands\" (auto-sign ONLY the exact strings in commands)"`
	// Commands is the exact command set for scope="commands"; required and
	// non-empty for that scope, and must be empty for scope="all".
	Commands []string `json:"commands,omitempty" jsonschema:"for scope=commands: the EXACT command strings that may auto-sign (exact-string match, no patterns). Required for scope=commands; omit for scope=all."`
	// DurationHours is the grant window in hours, 1..24 (24h hard ceiling).
	DurationHours int `json:"duration_hours" jsonschema:"grant lifetime in hours, 1 to 24 (24h hard ceiling). The grant dies on signer restart regardless."`
	// Reason is the human-readable justification shown in the approval.
	Reason string `json:"reason,omitempty" jsonschema:"why this standing grant is needed (shown to the human approver)"`
}

// RequestGrantOutput is the structured result. On approval GrantID +
// ExpiryUnix are set. A denial/timeout surfaces as an MCP tool error
// (this output is only returned on success).
type RequestGrantOutput struct {
	Alias      string   `json:"alias"`
	Scope      string   `json:"scope"`
	Commands   []string `json:"commands,omitempty"`
	GrantID    string   `json:"grant_id"`
	ExpiryUnix int64    `json:"expiry_unix"`
}

// RequestGrant validates the request locally, then asks the signer to
// mint a standing grant — which requires a human Telegram approval of a
// distinct "STANDING GRANT" message. The agent cannot self-grant: this
// path only carries a REQUEST; the grant exists only after the human
// approves, and lives solely in the signer's memory (never on the MCP
// side). Validation (scope, command set, 1..24h duration) runs BEFORE any
// tap so a malformed request never wastes an approval.
func (r *Runner) RequestGrant(ctx context.Context, in RequestGrantInput) (RequestGrantOutput, error) {
	if r.Servers == nil {
		return RequestGrantOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RequestGrantOutput{}, errors.New("tools: Sign is nil")
	}
	if in.Alias == "" {
		return RequestGrantOutput{}, errors.New("tools: alias is empty")
	}
	if _, ok := r.Servers.Get(in.Alias); !ok {
		return RequestGrantOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	switch in.Scope {
	case "all":
		if len(in.Commands) != 0 {
			return RequestGrantOutput{}, errors.New("tools: scope \"all\" must not carry a commands list (it auto-signs every write); use scope \"commands\" to restrict")
		}
	case "commands":
		if len(in.Commands) == 0 {
			return RequestGrantOutput{}, errors.New("tools: scope \"commands\" requires a non-empty commands list (the exact strings allowed to auto-sign)")
		}
		for i, c := range in.Commands {
			if c == "" {
				return RequestGrantOutput{}, fmt.Errorf("tools: commands[%d] is empty", i)
			}
		}
	default:
		return RequestGrantOutput{}, fmt.Errorf("tools: invalid scope %q (must be \"all\" or \"commands\")", in.Scope)
	}

	if in.DurationHours < 1 || in.DurationHours > 24 {
		return RequestGrantOutput{}, fmt.Errorf("tools: duration_hours %d out of range (must be 1..24; the signer caps grants at 24h)", in.DurationHours)
	}

	reqID, err := newRequestID()
	if err != nil {
		return RequestGrantOutput{}, fmt.Errorf("tools: request id: %w", err)
	}

	gid, expiry, err := r.Sign.RequestGrant(ctx, reqID, in.Alias, in.Scope, in.Commands, int64(in.DurationHours)*3600)
	if err != nil {
		// Preserve the sentinel (ErrDenied/ErrTimeout/...) for the MCP
		// layer while making the message actionable. The agent must NOT
		// re-submit a denied grant — that is the human's call.
		return RequestGrantOutput{}, fmt.Errorf("tools: request_grant: %w", err)
	}

	return RequestGrantOutput{
		Alias:      in.Alias,
		Scope:      in.Scope,
		Commands:   in.Commands,
		GrantID:    gid,
		ExpiryUnix: expiry,
	}, nil
}
