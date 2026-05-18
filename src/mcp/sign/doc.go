// Package sign is the MCP-side client of the velsigner Unix-socket
// protocol. It packs a list of pending write commands into one sign
// request, dials the velsigner socket, and waits for the daemon's
// verdict.
//
// The protocol is one JSON line per direction (the same shape served
// by velsigner.Daemon.HandleSignRequest):
//
//	→ {"kind":"sign","request_id":"r_xxx","commands":[{server,cmd,ttl_seconds},...]}
//	← {"request_id":"...","status":"approved|denied|timeout|error",
//	   "signatures":[{cmd,sig}],"error":"..."}
//
// The Sign method maps the four protocol-level outcomes to four
// sentinel error values (ErrDenied, ErrTimeout, ErrUnreachable, plus
// a wrapped error for "protocol error / malformed response"). The
// MCP server layer turns these into structured tool errors.
//
// All Sign calls are bounded by Client.Timeout — the velsigner
// backend has its own approval window (60s for Telegram in v2), so
// callers SHOULD set Timeout to that window plus a few seconds of
// connection slack.
package sign
