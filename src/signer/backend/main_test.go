package backend_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain runs goleak across the backend test suite (stub, mock,
// telegram, chatstore). Per go.md §4.11. Goroutines spawned by the
// telegram-bot-api library during getMe / the BotAPI shutdown channel
// internal plumbing are filtered below; everything else must exit.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// The telegram-bot-api library creates a `shutdownChannel` on
		// every BotAPI; it only closes when StopReceivingUpdates is
		// called. Since we use a hand-rolled poll loop (not
		// GetUpdatesChan), nothing is parked on that channel — but
		// the library doesn't ship a finalizer, so leaving the BotAPI
		// alive at test end is benign. We don't filter it explicitly
		// because no goroutine waits on it in our code path.
	)
}
