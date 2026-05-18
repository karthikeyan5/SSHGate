package velsigner_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak.VerifyTestMain across the whole velsigner test
// suite (socket, daemon, audit, keystore). Per go.md §4.11.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
