package main

import (
	"testing"

	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// TestApprovalTimeoutOrdering guards the "approved-undelivered" bug at its
// root. The approval path crosses three processes — the MCP client, the
// signer daemon's connection handler, and the approval backend — and they
// MUST satisfy
//
//	ClientSignTimeout > SignerHandlerTimeout > ApprovalWindow
//
// or a human approval that lands late is signed-but-undelivered: the master
// key signs, but a deadline-expired connection (or an already-abandoned
// client) means the signature never returns to the MCP.
//
// The consts in sigwire/timeouts.go define each outer bound as the next inner
// bound plus slack, so the ordering holds by construction — this test fails
// loudly if a future edit breaks it. The production daemon pins
// signer.Server.HandlerTimeout to sigwire.SignerHandlerTimeout (see the
// wire-up in run(), main.go) and the MCP client defaults to
// sigwire.ClientSignTimeout (src/mcp/sign/client.go), so the literals can no
// longer drift below the window the way the original 30s default did.
func TestApprovalTimeoutOrdering(t *testing.T) {
	t.Parallel()

	if !(sigwire.SignerHandlerTimeout > sigwire.ApprovalWindow) {
		t.Errorf("SignerHandlerTimeout (%s) must be strictly greater than ApprovalWindow (%s): "+
			"a late approval would be cut short and the signed response stranded",
			sigwire.SignerHandlerTimeout, sigwire.ApprovalWindow)
	}
	if !(sigwire.ClientSignTimeout > sigwire.SignerHandlerTimeout) {
		t.Errorf("ClientSignTimeout (%s) must be strictly greater than SignerHandlerTimeout (%s): "+
			"the MCP client must wait for the daemon's verdict, not abandon early",
			sigwire.ClientSignTimeout, sigwire.SignerHandlerTimeout)
	}
}
