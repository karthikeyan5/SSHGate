// Package velsignerserver is the hosted velsigner-server: the v2 evolution
// of the local velsigner daemon. It serves an HTTPS API over which
// SSHGate plugins on any number of machines request command signatures,
// blocks each request on a human approval (via WebAuthn/TOTP in v2.1+),
// and returns signed payloads compatible with the existing velgate
// verification path.
//
// v2.0 is the SCAFFOLD. It establishes the package layout, the wire
// protocol surface (POST /v1/sign, GET /v1/poll/{id}, GET /v1/audit,
// GET /healthz), a single bearer-token auth, and a SQLite state store.
// It explicitly does NOT yet implement: WebAuthn + TOTP login, the web
// UI, multi-operator approval rules, server-side LLM explainer, or
// monitoring/metrics — those are v2.1 work items.
//
// The package is laid out as:
//
//	server.go      — Server struct, http.Handler registration
//	handlers.go    — per-route HTTP handlers
//	doc.go         — this file
//	cmd/velsigner-server/main.go — entry point
//	store/         — Store interface + SQLite implementation
//	install/       — VPS deploy script + systemd unit template
//
// The reference for the wire protocol is the design spec at
// docs/specs/2026-05-19-sshgate-design.md §"v2 vision → Wire protocol";
// the swap-point on the velsigner side is
// src/velsigner/backend/hosted.go (commit 3 of the v2 scaffold series).
package velsignerserver
