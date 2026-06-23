package tools

import (
	"context"
	"errors"
	"fmt"
)

// RevokeGrantInput is the JSON input to sshgate.revoke_grant. It drops
// the standing grant for alias on the signer. Revoke is de-escalation —
// it only ever SHRINKS capability — so it needs no human approval and is
// always safe to call.
type RevokeGrantInput struct {
	Alias string `json:"alias" jsonschema:"alias whose standing grant to revoke (subsequent writes will prompt again). Safe to call even if no grant exists."`
}

// RevokeGrantOutput is the structured result. Revoked is true once the
// signer has dropped the grant (revoking a non-existent grant is a
// successful no-op, so Revoked is still true).
type RevokeGrantOutput struct {
	Alias   string `json:"alias"`
	Revoked bool   `json:"revoked"`
}

// RevokeGrant drops the standing grant for alias on the signer. It does
// NOT require the alias to be registered (a stale grant for a
// since-removed alias must still be revocable), only non-empty. No human
// approval is involved — de-escalation is always permitted.
func (r *Runner) RevokeGrant(ctx context.Context, in RevokeGrantInput) (RevokeGrantOutput, error) {
	if r.Sign == nil {
		return RevokeGrantOutput{}, errors.New("tools: Sign is nil")
	}
	if in.Alias == "" {
		return RevokeGrantOutput{}, errors.New("tools: alias is empty")
	}

	reqID, err := newRequestID()
	if err != nil {
		return RevokeGrantOutput{Alias: in.Alias}, fmt.Errorf("tools: request id: %w", err)
	}

	if err := r.Sign.RevokeGrant(ctx, reqID, in.Alias); err != nil {
		return RevokeGrantOutput{Alias: in.Alias}, fmt.Errorf("tools: revoke_grant: %w", err)
	}

	return RevokeGrantOutput{Alias: in.Alias, Revoked: true}, nil
}
