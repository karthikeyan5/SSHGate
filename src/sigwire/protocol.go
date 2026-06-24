package sigwire

// ProtoVersion is the version of the MCP↔signer Unix-socket RPC shape.
//
// It is EXACT-MATCH, not a negotiated range: the daemon accepts a request
// only when its proto_version is absent (legacy / 0) or equals this value,
// otherwise it returns a clear "different builds, rebuild both" error. The
// field rides the gate-invisible socket RPC only — it never touches the
// signed payload (sigwire.SigPayload) — so no deployed gate is affected.
//
// Bump this on ANY breaking change to the socket-RPC request/response shape
// (a renamed/removed field, a changed meaning, a new required field). It is
// DECOUPLED from the human-facing product semver: a release can ship
// without bumping it, and bumping it does not imply a semver change.
//
// Because the per-kind decoders use DisallowUnknownFields, the version is
// checked in the LENIENT kindPeek pre-pass BEFORE any strict decode — a
// naive strict-decoded version field would have an old daemon reject the
// field itself and re-create the very build-skew outage this guards against.
const ProtoVersion = 1
