package tools

import (
	"context"
	"errors"
	"fmt"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// ListGrantsInput is the JSON input to sshgate.list_grants. It reports the
// signer's in-memory LIVE standing grants. It is READ-ONLY: no human
// approval, no capability granted — it only reports state. Alias is an
// OPTIONAL filter; empty lists every live grant. Its primary use is to
// reconcile true grant state after a request_grant whose approval verdict
// did not arrive (the phantom-live grant), so the agent can re-learn a
// grant's id / scope / expiry instead of guessing.
type ListGrantsInput struct {
	Alias string `json:"alias,omitempty" jsonschema:"optional: restrict to one registered alias's grant. Omit to list every live standing grant the signer currently holds."`
}

// ListGrantsOutput is the structured result: the live (unexpired) grants the
// signer reported. Expired grants are never returned. Grants is empty when
// the signer holds none (a fresh / restarted signer, or after revoke).
type ListGrantsOutput struct {
	Grants []signpkg.GrantInfo `json:"grants"`
}

// ListGrants queries the signer for its in-memory live standing grants
// (optionally filtered to Alias). It is read-only — no approval, no backend
// — so it returns promptly and is always safe to call. The alias is
// optional (empty lists all); it is NOT required to be registered, because a
// stale grant for a since-removed alias must still be observable. A nil Sign
// client is guarded like the other tools.
func (r *Runner) ListGrants(ctx context.Context, in ListGrantsInput) (ListGrantsOutput, error) {
	if r.Sign == nil {
		return ListGrantsOutput{}, errors.New("tools: Sign is nil")
	}

	reqID, err := newRequestID()
	if err != nil {
		return ListGrantsOutput{}, fmt.Errorf("tools: request id: %w", err)
	}

	grants, err := r.Sign.ListGrants(ctx, reqID, in.Alias)
	if err != nil {
		// Preserve the sentinel (ErrUnreachable/...) for the MCP layer while
		// keeping the message actionable.
		return ListGrantsOutput{}, fmt.Errorf("tools: list_grants: %w", err)
	}

	return ListGrantsOutput{Grants: grants}, nil
}
