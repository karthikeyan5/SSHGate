package sigwire

import "testing"

// TestProtoVersionIsOne pins the current socket-RPC protocol version. A
// change here is a deliberate breaking-shape bump and must be accompanied
// by matching daemon/client struct changes — the test forces that to be a
// conscious edit, not an accident.
func TestProtoVersionIsOne(t *testing.T) {
	if ProtoVersion != 1 {
		t.Errorf("ProtoVersion = %d; want 1", ProtoVersion)
	}
}

// TestProtoVersionPositive guards the daemon's accept-as-legacy rule: 0 is
// reserved to mean "absent / legacy client", so a real ProtoVersion must
// be strictly greater than 0 or the mismatch check can never fire.
func TestProtoVersionPositive(t *testing.T) {
	if ProtoVersion <= 0 {
		t.Errorf("ProtoVersion = %d; must be > 0 (0 is reserved for legacy/absent)", ProtoVersion)
	}
}
