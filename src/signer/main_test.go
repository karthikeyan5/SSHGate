package signer_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak.VerifyTestMain across the whole signer test
// suite (socket, daemon, audit, keystore). Per go.md §4.11.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
